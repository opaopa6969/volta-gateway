//! PostgreSQL-backed store implementing all domain store traits.
//! Requires the `postgres` feature.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc;

use crate::error::AuthError;
use crate::record::*;
use crate::store::{UserStore, TenantStore, MembershipStore, InvitationStore, FlowPersistence, SessionStore, MfaStore, RecoveryCodeStore, MagicLinkStore, SigningKeyStore, IdpConfigStore, M2mClientStore, PasskeyStore, OidcFlowStore, WebhookStore, OutboxStore, WebhookDeliveryStore, AuditStore, DeviceTrustStore, BillingStore, PolicyStore};

/// PostgreSQL-backed store — single struct implementing all DAO traits.
#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// ─── SessionStore (PG-backed) ──────────────────────────────

/// Row type for session query — roles stored as comma-separated TEXT.
#[derive(sqlx::FromRow)]
struct SessionRow {
    id: String,
    user_id: String,
    tenant_id: String,
    return_to: Option<String>,
    created_at: i64,
    last_active_at: i64,
    expires_at: i64,
    invalidated_at: Option<i64>,
    mfa_verified_at: Option<i64>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    csrf_token: Option<String>,
    email: Option<String>,
    tenant_slug: Option<String>,
    roles: Option<String>,
    display_name: Option<String>,
}

impl From<SessionRow> for SessionRecord {
    fn from(r: SessionRow) -> Self {
        SessionRecord {
            session_id: r.id,
            user_id: r.user_id,
            tenant_id: r.tenant_id,
            return_to: r.return_to,
            created_at: r.created_at as u64,
            last_active_at: r.last_active_at as u64,
            expires_at: r.expires_at as u64,
            invalidated_at: r.invalidated_at.map(|v| v as u64),
            mfa_verified_at: r.mfa_verified_at.map(|v| v as u64),
            ip_address: r.ip_address,
            user_agent: r.user_agent,
            csrf_token: r.csrf_token,
            email: r.email,
            tenant_slug: r.tenant_slug,
            roles: r.roles.map(|s| s.split(',').filter(|s| !s.is_empty()).map(String::from).collect()).unwrap_or_default(),
            display_name: r.display_name,
        }
    }
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[async_trait]
impl SessionStore for PgStore {
    async fn create(&self, record: SessionRecord) -> Result<(), AuthError> {
        let roles_csv = record.roles.join(",");
        sqlx::query(
            "INSERT INTO sessions (id, user_id, tenant_id, return_to, created_at, last_active_at, \
                                   expires_at, invalidated_at, mfa_verified_at, ip_address, user_agent, \
                                   csrf_token, email, tenant_slug, roles, display_name) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)"
        )
        .bind(&record.session_id)
        .bind(&record.user_id)
        .bind(&record.tenant_id)
        .bind(&record.return_to)
        .bind(record.created_at as i64)
        .bind(record.last_active_at as i64)
        .bind(record.expires_at as i64)
        .bind(record.invalidated_at.map(|v| v as i64))
        .bind(record.mfa_verified_at.map(|v| v as i64))
        .bind(&record.ip_address)
        .bind(&record.user_agent)
        .bind(&record.csrf_token)
        .bind(&record.email)
        .bind(&record.tenant_slug)
        .bind(&roles_csv)
        .bind(&record.display_name)
        .execute(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(())
    }

    async fn find(&self, session_id: &str) -> Result<Option<SessionRecord>, AuthError> {
        let now = now_epoch();
        let row = sqlx::query_as::<_, SessionRow>(
            "SELECT id, user_id, tenant_id, return_to, created_at, last_active_at, \
                    expires_at, invalidated_at, mfa_verified_at, ip_address, user_agent, \
                    csrf_token, email, tenant_slug, roles, display_name \
             FROM sessions WHERE id = $1 AND invalidated_at IS NULL AND expires_at > $2"
        )
        .bind(session_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(row.map(SessionRecord::from))
    }

    async fn touch(&self, session_id: &str, new_expires_at: u64) -> Result<(), AuthError> {
        let now = now_epoch();
        sqlx::query("UPDATE sessions SET last_active_at = $1, expires_at = $2 WHERE id = $3")
            .bind(now)
            .bind(new_expires_at as i64)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(AuthError::from)?;
        Ok(())
    }

    async fn mark_mfa_verified(&self, session_id: &str) -> Result<(), AuthError> {
        let now = now_epoch();
        sqlx::query("UPDATE sessions SET mfa_verified_at = $1 WHERE id = $2")
            .bind(now)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(AuthError::from)?;
        Ok(())
    }

    async fn revoke(&self, session_id: &str) -> Result<(), AuthError> {
        let now = now_epoch();
        sqlx::query("UPDATE sessions SET invalidated_at = $1 WHERE id = $2")
            .bind(now)
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(AuthError::from)?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: &str) -> Result<usize, AuthError> {
        let now = now_epoch();
        let result = sqlx::query(
            "UPDATE sessions SET invalidated_at = $1 WHERE user_id = $2 AND invalidated_at IS NULL"
        )
        .bind(now)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(result.rows_affected() as usize)
    }

    async fn list_by_user(&self, user_id: &str) -> Result<Vec<SessionRecord>, AuthError> {
        let rows = sqlx::query_as::<_, SessionRow>(
            "SELECT id, user_id, tenant_id, return_to, created_at, last_active_at, \
                    expires_at, invalidated_at, mfa_verified_at, ip_address, user_agent, \
                    csrf_token, email, tenant_slug, roles, display_name \
             FROM sessions WHERE user_id = $1 ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(rows.into_iter().map(SessionRecord::from).collect())
    }

    async fn count_active(&self, user_id: &str) -> Result<usize, AuthError> {
        let now = now_epoch();
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sessions WHERE user_id = $1 AND invalidated_at IS NULL AND expires_at > $2"
        )
        .bind(user_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(row.0 as usize)
    }

    async fn cleanup_expired(&self) -> Result<usize, AuthError> {
        let now = now_epoch();
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(AuthError::from)?;
        Ok(result.rows_affected() as usize)
    }
}

// ─── UserStore ─────────────────────────────────────────────

#[async_trait]
impl UserStore for PgStore {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<UserRecord>, AuthError> {
        sqlx::query_as::<_, UserRecord>(
            "SELECT id, email, display_name, google_sub, created_at, is_active, locale, deleted_at \
             FROM users WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>, AuthError> {
        sqlx::query_as::<_, UserRecord>(
            "SELECT id, email, display_name, google_sub, created_at, is_active, locale, deleted_at \
             FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn find_by_google_sub(&self, google_sub: &str) -> Result<Option<UserRecord>, AuthError> {
        sqlx::query_as::<_, UserRecord>(
            "SELECT id, email, display_name, google_sub, created_at, is_active, locale, deleted_at \
             FROM users WHERE google_sub = $1"
        )
        .bind(google_sub)
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn upsert(&self, record: UserRecord) -> Result<UserRecord, AuthError> {
        sqlx::query_as::<_, UserRecord>(
            "INSERT INTO users (id, email, display_name, google_sub, created_at, is_active, locale) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (email) DO UPDATE SET \
               display_name = EXCLUDED.display_name, \
               google_sub = EXCLUDED.google_sub, \
               is_active = EXCLUDED.is_active, \
               locale = EXCLUDED.locale \
             RETURNING id, email, display_name, google_sub, created_at, is_active, locale, deleted_at"
        )
        .bind(record.id)
        .bind(&record.email)
        .bind(&record.display_name)
        .bind(&record.google_sub)
        .bind(record.created_at)
        .bind(record.is_active)
        .bind(&record.locale)
        .fetch_one(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn update_display_name(&self, id: Uuid, display_name: &str) -> Result<(), AuthError> {
        sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
            .bind(display_name)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(AuthError::from)?;
        Ok(())
    }

    async fn soft_delete(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE users SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(AuthError::from)?;
        Ok(())
    }
}

// ─── TenantStore ───────────────────────────────────────────

#[async_trait]
impl TenantStore for PgStore {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<TenantRecord>, AuthError> {
        sqlx::query_as::<_, TenantRecord>(
            "SELECT id, name, slug, email_domain, auto_join, created_by, created_at, \
                    plan, max_members, is_active, mfa_required, mfa_grace_until \
             FROM tenants WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<TenantRecord>, AuthError> {
        sqlx::query_as::<_, TenantRecord>(
            "SELECT id, name, slug, email_domain, auto_join, created_by, created_at, \
                    plan, max_members, is_active, mfa_required, mfa_grace_until \
             FROM tenants WHERE slug = $1"
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<TenantRecord>, AuthError> {
        sqlx::query_as::<_, TenantRecord>(
            "SELECT t.id, t.name, t.slug, t.email_domain, t.auto_join, t.created_by, t.created_at, \
                    t.plan, t.max_members, t.is_active, t.mfa_required, t.mfa_grace_until \
             FROM memberships m JOIN tenants t ON t.id = m.tenant_id \
             WHERE m.user_id = $1 AND m.is_active = true AND t.is_active = true"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn create(&self, record: TenantRecord) -> Result<TenantRecord, AuthError> {
        sqlx::query_as::<_, TenantRecord>(
            "INSERT INTO tenants (id, name, slug, email_domain, auto_join, created_by, created_at, \
                                  plan, max_members, is_active, mfa_required, mfa_grace_until) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             RETURNING id, name, slug, email_domain, auto_join, created_by, created_at, \
                       plan, max_members, is_active, mfa_required, mfa_grace_until"
        )
        .bind(record.id)
        .bind(&record.name)
        .bind(&record.slug)
        .bind(&record.email_domain)
        .bind(record.auto_join)
        .bind(record.created_by)
        .bind(record.created_at)
        .bind(&record.plan)
        .bind(record.max_members)
        .bind(record.is_active)
        .bind(record.mfa_required)
        .bind(record.mfa_grace_until)
        .fetch_one(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn create_personal(&self, user_id: Uuid, name: &str, slug: &str) -> Result<TenantRecord, AuthError> {
        let mut tx = self.pool.begin().await.map_err(AuthError::from)?;

        let tenant = sqlx::query_as::<_, TenantRecord>(
            "INSERT INTO tenants (name, slug, created_by, plan, max_members) \
             VALUES ($1, $2, $3, 'FREE', 1) \
             RETURNING id, name, slug, email_domain, auto_join, created_by, created_at, \
                       plan, max_members, is_active, mfa_required, mfa_grace_until"
        )
        .bind(name)
        .bind(slug)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AuthError::from)?;

        sqlx::query(
            "INSERT INTO memberships (user_id, tenant_id, role) VALUES ($1, $2, 'OWNER')"
        )
        .bind(user_id)
        .bind(tenant.id)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::from)?;

        tx.commit().await.map_err(AuthError::from)?;
        Ok(tenant)
    }
}

// ─── MembershipStore ───────────────────────────────────────

#[async_trait]
impl MembershipStore for PgStore {
    async fn find(&self, user_id: Uuid, tenant_id: Uuid) -> Result<Option<MembershipRecord>, AuthError> {
        sqlx::query_as::<_, MembershipRecord>(
            "SELECT id, user_id, tenant_id, role, joined_at, invited_by, is_active \
             FROM memberships WHERE user_id = $1 AND tenant_id = $2"
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<MembershipRecord>, AuthError> {
        sqlx::query_as::<_, MembershipRecord>(
            "SELECT id, user_id, tenant_id, role, joined_at, invited_by, is_active \
             FROM memberships WHERE tenant_id = $1 AND is_active = true \
             ORDER BY joined_at"
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn create(&self, record: MembershipRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO memberships (id, user_id, tenant_id, role, joined_at, invited_by, is_active) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(record.id)
        .bind(record.user_id)
        .bind(record.tenant_id)
        .bind(&record.role)
        .bind(record.joined_at)
        .bind(record.invited_by)
        .bind(record.is_active)
        .execute(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(())
    }

    async fn update_role(&self, id: Uuid, role: &str) -> Result<(), AuthError> {
        sqlx::query("UPDATE memberships SET role = $1 WHERE id = $2")
            .bind(role)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(AuthError::from)?;
        Ok(())
    }

    async fn deactivate(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE memberships SET is_active = false WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(AuthError::from)?;
        Ok(())
    }

    async fn count_active_owners(&self, tenant_id: Uuid) -> Result<usize, AuthError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM memberships \
             WHERE tenant_id = $1 AND role = 'OWNER' AND is_active = true"
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(row.0 as usize)
    }
}

// ─── InvitationStore ───────────────────────────────────────

#[async_trait]
impl InvitationStore for PgStore {
    async fn create(&self, record: InvitationRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO invitations (id, tenant_id, code, email, role, max_uses, used_count, \
                                      created_by, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
        )
        .bind(record.id)
        .bind(record.tenant_id)
        .bind(&record.code)
        .bind(&record.email)
        .bind(&record.role)
        .bind(record.max_uses)
        .bind(record.used_count)
        .bind(record.created_by)
        .bind(record.created_at)
        .bind(record.expires_at)
        .execute(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(())
    }

    async fn find_by_code(&self, code: &str) -> Result<Option<InvitationRecord>, AuthError> {
        sqlx::query_as::<_, InvitationRecord>(
            "SELECT id, tenant_id, code, email, role, max_uses, used_count, \
                    created_by, created_at, expires_at \
             FROM invitations WHERE code = $1"
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn accept(&self, code: &str, user_id: Uuid) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await.map_err(AuthError::from)?;

        // Fetch and lock the invitation
        let inv = sqlx::query_as::<_, InvitationRecord>(
            "SELECT id, tenant_id, code, email, role, max_uses, used_count, \
                    created_by, created_at, expires_at \
             FROM invitations WHERE code = $1 FOR UPDATE"
        )
        .bind(code)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AuthError::from)?
        .ok_or_else(|| AuthError::NotFound(format!("invitation code={}", code)))?;

        if !inv.is_usable_at(Utc::now()) {
            return Err(AuthError::Conflict("invitation expired or fully used".into()));
        }

        // Increment used_count
        sqlx::query("UPDATE invitations SET used_count = used_count + 1 WHERE id = $1")
            .bind(inv.id)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::from)?;

        // Record usage
        sqlx::query(
            "INSERT INTO invitation_usages (invitation_id, used_by) VALUES ($1, $2)"
        )
        .bind(inv.id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::from)?;

        // Create membership (upsert: if already member, update role)
        sqlx::query(
            "INSERT INTO memberships (user_id, tenant_id, role, invited_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (user_id, tenant_id) DO UPDATE SET \
               role = EXCLUDED.role, is_active = true"
        )
        .bind(user_id)
        .bind(inv.tenant_id)
        .bind(&inv.role)
        .bind(inv.created_by)
        .execute(&mut *tx)
        .await
        .map_err(AuthError::from)?;

        tx.commit().await.map_err(AuthError::from)?;
        Ok(())
    }

    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<InvitationRecord>, AuthError> {
        sqlx::query_as::<_, InvitationRecord>(
            "SELECT id, tenant_id, code, email, role, max_uses, used_count, \
                    created_by, created_at, expires_at \
             FROM invitations WHERE tenant_id = $1 \
             ORDER BY created_at DESC"
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn cancel(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE invitations SET max_uses = 0 WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(AuthError::from)?;
        Ok(())
    }
}

// ─── FlowPersistence ──────────────────────────────────────

#[async_trait]
impl FlowPersistence for PgStore {
    async fn create(&self, record: FlowRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO auth_flows (id, session_id, flow_type, current_state, \
                                     guard_failure_count, version, created_at, updated_at, \
                                     expires_at, completed_at, exit_state, summary) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
        )
        .bind(record.id)
        .bind(&record.session_id)
        .bind(&record.flow_type)
        .bind(&record.current_state)
        .bind(record.guard_failure_count)
        .bind(record.version)
        .bind(record.created_at)
        .bind(record.updated_at)
        .bind(record.expires_at)
        .bind(record.completed_at)
        .bind(&record.exit_state)
        .bind(&record.summary)
        .execute(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(())
    }

    async fn find(&self, id: Uuid) -> Result<Option<FlowRecord>, AuthError> {
        sqlx::query_as::<_, FlowRecord>(
            "SELECT id, session_id, flow_type, current_state, guard_failure_count, \
                    version, created_at, updated_at, expires_at, completed_at, \
                    exit_state, summary \
             FROM auth_flows WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn update_state(&self, id: Uuid, state: &str, version: i32) -> Result<(), AuthError> {
        let result = sqlx::query(
            "UPDATE auth_flows SET current_state = $1, version = $2, updated_at = now() \
             WHERE id = $3 AND version = $2 - 1"
        )
        .bind(state)
        .bind(version)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(AuthError::from)?;

        if result.rows_affected() == 0 {
            return Err(AuthError::Conflict("flow version conflict (optimistic lock)".into()));
        }
        Ok(())
    }

    async fn complete(
        &self,
        id: Uuid,
        exit_state: &str,
        summary: Option<serde_json::Value>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE auth_flows SET exit_state = $1, completed_at = now(), \
                                   updated_at = now(), summary = $2 \
             WHERE id = $3"
        )
        .bind(exit_state)
        .bind(&summary)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(())
    }

    async fn record_transition(
        &self,
        flow_id: Uuid,
        from: Option<&str>,
        to: &str,
        trigger: &str,
        error: Option<&str>,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO auth_flow_transitions (flow_id, from_state, to_state, trigger, error_detail) \
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(flow_id)
        .bind(from)
        .bind(to)
        .bind(trigger)
        .bind(error)
        .execute(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(())
    }

    async fn find_active_by_session(&self, session_id: &str) -> Result<Vec<FlowRecord>, AuthError> {
        sqlx::query_as::<_, FlowRecord>(
            "SELECT id, session_id, flow_type, current_state, guard_failure_count, \
                    version, created_at, updated_at, expires_at, completed_at, \
                    exit_state, summary \
             FROM auth_flows \
             WHERE session_id = $1 AND completed_at IS NULL AND expires_at > now() \
             ORDER BY created_at DESC"
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await
        .map_err(AuthError::from)
    }

    async fn cleanup_expired(&self) -> Result<usize, AuthError> {
        let result = sqlx::query(
            "DELETE FROM auth_flows WHERE expires_at < now() AND completed_at IS NULL"
        )
        .execute(&self.pool)
        .await
        .map_err(AuthError::from)?;
        Ok(result.rows_affected() as usize)
    }
}

// ─── MfaStore ──────────────────────────────────────────────

#[async_trait]
impl MfaStore for PgStore {
    async fn upsert(&self, user_id: Uuid, mfa_type: &str, secret: &str) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO user_mfa (user_id, type, secret) VALUES ($1, $2, $3) \
             ON CONFLICT (user_id, (type)) DO UPDATE SET secret = EXCLUDED.secret, is_active = true"
        ).bind(user_id).bind(mfa_type).bind(secret)
        .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }

    async fn find(&self, user_id: Uuid, mfa_type: &str) -> Result<Option<MfaRecord>, AuthError> {
        sqlx::query_as::<_, MfaRecord>(
            "SELECT id, user_id, type AS mfa_type, secret, is_active, created_at \
             FROM user_mfa WHERE user_id = $1 AND type = $2 AND is_active = true"
        ).bind(user_id).bind(mfa_type)
        .fetch_optional(&self.pool).await.map_err(AuthError::from)
    }

    async fn has_active(&self, user_id: Uuid) -> Result<bool, AuthError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_mfa WHERE user_id = $1 AND is_active = true"
        ).bind(user_id).fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0 > 0)
    }

    async fn deactivate(&self, user_id: Uuid, mfa_type: &str) -> Result<(), AuthError> {
        sqlx::query("UPDATE user_mfa SET is_active = false WHERE user_id = $1 AND type = $2")
            .bind(user_id).bind(mfa_type)
            .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
}

// ─── RecoveryCodeStore ─────────────────────────────────────

#[async_trait]
impl RecoveryCodeStore for PgStore {
    async fn replace_all(&self, user_id: Uuid, code_hashes: &[String]) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await.map_err(AuthError::from)?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id).execute(&mut *tx).await.map_err(AuthError::from)?;
        for hash in code_hashes {
            sqlx::query("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)")
                .bind(user_id).bind(hash).execute(&mut *tx).await.map_err(AuthError::from)?;
        }
        tx.commit().await.map_err(AuthError::from)?;
        Ok(())
    }

    async fn consume(&self, user_id: Uuid, code_hash: &str) -> Result<bool, AuthError> {
        let result = sqlx::query(
            "UPDATE mfa_recovery_codes SET used_at = now() \
             WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL"
        ).bind(user_id).bind(code_hash).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(result.rows_affected() > 0)
    }

    async fn count_unused(&self, user_id: Uuid) -> Result<usize, AuthError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL"
        ).bind(user_id).fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0 as usize)
    }

    async fn delete_all(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
            .bind(user_id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
}

// ─── MagicLinkStore ────────────────────────────────────────

#[async_trait]
impl MagicLinkStore for PgStore {
    async fn create(&self, email: &str, token: &str, ttl_minutes: i64) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO magic_links (email, token, expires_at) \
             VALUES ($1, $2, now() + make_interval(mins => $3))"
        ).bind(email).bind(token).bind(ttl_minutes as f64)
        .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }

    async fn consume(&self, token: &str) -> Result<Option<MagicLinkRecord>, AuthError> {
        sqlx::query_as::<_, MagicLinkRecord>(
            "UPDATE magic_links SET used_at = now() \
             WHERE token = $1 AND used_at IS NULL AND expires_at > now() \
             RETURNING id, email, token, expires_at, used_at, created_at"
        ).bind(token).fetch_optional(&self.pool).await.map_err(AuthError::from)
    }
}

// ─── SigningKeyStore ───────────────────────────────────────

#[async_trait]
impl SigningKeyStore for PgStore {
    async fn save(&self, kid: &str, public_pem: &str, private_pem: &str) -> Result<(), AuthError> {
        sqlx::query("INSERT INTO signing_keys (kid, public_key, private_key) VALUES ($1, $2, $3)")
            .bind(kid).bind(public_pem).bind(private_pem)
            .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }

    async fn load_active(&self) -> Result<Option<SigningKeyRecord>, AuthError> {
        sqlx::query_as::<_, SigningKeyRecord>(
            "SELECT kid, public_key, private_key, status, created_at, rotated_at, expires_at \
             FROM signing_keys WHERE status = 'active' ORDER BY created_at DESC LIMIT 1"
        ).fetch_optional(&self.pool).await.map_err(AuthError::from)
    }

    async fn list(&self) -> Result<Vec<SigningKeyRecord>, AuthError> {
        sqlx::query_as::<_, SigningKeyRecord>(
            "SELECT kid, public_key, private_key, status, created_at, rotated_at, expires_at \
             FROM signing_keys ORDER BY created_at DESC"
        ).fetch_all(&self.pool).await.map_err(AuthError::from)
    }

    async fn rotate(&self, old_kid: &str, new_kid: &str, public_pem: &str, private_pem: &str) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await.map_err(AuthError::from)?;
        sqlx::query("UPDATE signing_keys SET status = 'retired', rotated_at = now() WHERE kid = $1")
            .bind(old_kid).execute(&mut *tx).await.map_err(AuthError::from)?;
        sqlx::query("INSERT INTO signing_keys (kid, public_key, private_key) VALUES ($1, $2, $3)")
            .bind(new_kid).bind(public_pem).bind(private_pem)
            .execute(&mut *tx).await.map_err(AuthError::from)?;
        tx.commit().await.map_err(AuthError::from)?;
        Ok(())
    }

    async fn revoke(&self, kid: &str) -> Result<(), AuthError> {
        sqlx::query("UPDATE signing_keys SET status = 'revoked', rotated_at = now() WHERE kid = $1")
            .bind(kid).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
}

// ─── IdpConfigStore ────────────────────────────────────────

#[async_trait]
impl IdpConfigStore for PgStore {
    async fn upsert(&self, config: IdpConfigRecord) -> Result<Uuid, AuthError> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO idp_configs (id, tenant_id, provider_type, metadata_url, issuer, client_id, client_secret, x509_cert) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO UPDATE SET \
               metadata_url = EXCLUDED.metadata_url, issuer = EXCLUDED.issuer, \
               client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret, \
               x509_cert = EXCLUDED.x509_cert, is_active = true \
             RETURNING id"
        )
        .bind(config.id).bind(config.tenant_id).bind(&config.provider_type)
        .bind(&config.metadata_url).bind(&config.issuer).bind(&config.client_id)
        .bind(&config.client_secret).bind(&config.x509_cert)
        .fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0)
    }

    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<IdpConfigRecord>, AuthError> {
        sqlx::query_as::<_, IdpConfigRecord>(
            "SELECT id, tenant_id, provider_type, metadata_url, issuer, client_id, client_secret, x509_cert, created_at, is_active \
             FROM idp_configs WHERE tenant_id = $1 AND is_active = true ORDER BY created_at"
        ).bind(tenant_id).fetch_all(&self.pool).await.map_err(AuthError::from)
    }

    async fn find(&self, tenant_id: Uuid, provider_type: &str) -> Result<Option<IdpConfigRecord>, AuthError> {
        sqlx::query_as::<_, IdpConfigRecord>(
            "SELECT id, tenant_id, provider_type, metadata_url, issuer, client_id, client_secret, x509_cert, created_at, is_active \
             FROM idp_configs WHERE tenant_id = $1 AND provider_type = $2 AND is_active = true"
        ).bind(tenant_id).bind(provider_type).fetch_optional(&self.pool).await.map_err(AuthError::from)
    }
}

// ─── M2mClientStore ────────────────────────────────────────

#[async_trait]
impl M2mClientStore for PgStore {
    async fn create(&self, record: M2mClientRecord) -> Result<Uuid, AuthError> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO m2m_clients (id, tenant_id, client_id, client_secret_hash, scopes) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id"
        )
        .bind(record.id).bind(record.tenant_id).bind(&record.client_id)
        .bind(&record.client_secret_hash).bind(&record.scopes)
        .fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0)
    }

    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<M2mClientRecord>, AuthError> {
        sqlx::query_as::<_, M2mClientRecord>(
            "SELECT id, tenant_id, client_id, client_secret_hash, scopes, is_active, created_at \
             FROM m2m_clients WHERE client_id = $1 AND is_active = true"
        ).bind(client_id).fetch_optional(&self.pool).await.map_err(AuthError::from)
    }

    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<M2mClientRecord>, AuthError> {
        sqlx::query_as::<_, M2mClientRecord>(
            "SELECT id, tenant_id, client_id, client_secret_hash, scopes, is_active, created_at \
             FROM m2m_clients WHERE tenant_id = $1 AND is_active = true ORDER BY created_at"
        ).bind(tenant_id).fetch_all(&self.pool).await.map_err(AuthError::from)
    }
}

// ─── PasskeyStore ──────────────────────────────────────────

#[async_trait]
impl PasskeyStore for PgStore {
    async fn create(&self, record: PasskeyRecord) -> Result<Uuid, AuthError> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO user_passkeys (id, user_id, credential_id, public_key, sign_count, \
                                        transports, name, aaguid, backup_eligible, backup_state) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id"
        )
        .bind(record.id).bind(record.user_id).bind(&record.credential_id)
        .bind(&record.public_key).bind(record.sign_count)
        .bind(&record.transports).bind(&record.name).bind(record.aaguid)
        .bind(record.backup_eligible).bind(record.backup_state)
        .fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0)
    }

    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<PasskeyRecord>, AuthError> {
        sqlx::query_as::<_, PasskeyRecord>(
            "SELECT id, user_id, credential_id, public_key, sign_count, transports, name, \
                    aaguid, backup_eligible, backup_state, created_at, last_used_at \
             FROM user_passkeys WHERE user_id = $1 ORDER BY created_at"
        ).bind(user_id).fetch_all(&self.pool).await.map_err(AuthError::from)
    }

    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<PasskeyRecord>, AuthError> {
        sqlx::query_as::<_, PasskeyRecord>(
            "SELECT id, user_id, credential_id, public_key, sign_count, transports, name, \
                    aaguid, backup_eligible, backup_state, created_at, last_used_at \
             FROM user_passkeys WHERE credential_id = $1"
        ).bind(credential_id).fetch_optional(&self.pool).await.map_err(AuthError::from)
    }

    async fn update_counter(&self, id: Uuid, new_sign_count: i64) -> Result<bool, AuthError> {
        // #17: only succeed when the new count is strictly greater than the stored
        // value. Rejects concurrent replays and cloned-authenticator attacks.
        let result = sqlx::query(
            "UPDATE user_passkeys SET sign_count = $1, last_used_at = now() \
             WHERE id = $2 AND sign_count < $1"
        ).bind(new_sign_count).bind(id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete(&self, user_id: Uuid, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM user_passkeys WHERE id = $1 AND user_id = $2")
            .bind(id).bind(user_id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }

    async fn count(&self, user_id: Uuid) -> Result<usize, AuthError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM user_passkeys WHERE user_id = $1"
        ).bind(user_id).fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0 as usize)
    }
}

// ─── WebhookStore ──────────────────────────────────────────

#[async_trait]
impl WebhookStore for PgStore {
    async fn create(&self, r: WebhookRecord) -> Result<Uuid, AuthError> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO webhook_subscriptions (id, tenant_id, endpoint_url, secret, events) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id"
        ).bind(r.id).bind(r.tenant_id).bind(&r.endpoint_url).bind(&r.secret).bind(&r.events)
        .fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0)
    }
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<WebhookRecord>, AuthError> {
        sqlx::query_as::<_, WebhookRecord>(
            "SELECT id, tenant_id, endpoint_url, secret, events, is_active, created_at, last_success_at, last_failure_at \
             FROM webhook_subscriptions WHERE tenant_id = $1 ORDER BY created_at"
        ).bind(tenant_id).fetch_all(&self.pool).await.map_err(AuthError::from)
    }
    async fn find(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<WebhookRecord>, AuthError> {
        sqlx::query_as::<_, WebhookRecord>(
            "SELECT id, tenant_id, endpoint_url, secret, events, is_active, created_at, last_success_at, last_failure_at \
             FROM webhook_subscriptions WHERE id = $1 AND tenant_id = $2"
        ).bind(id).bind(tenant_id).fetch_optional(&self.pool).await.map_err(AuthError::from)
    }
    async fn update(&self, id: Uuid, endpoint_url: &str, events: &str, is_active: bool) -> Result<(), AuthError> {
        sqlx::query("UPDATE webhook_subscriptions SET endpoint_url=$1, events=$2, is_active=$3 WHERE id=$4")
            .bind(endpoint_url).bind(events).bind(is_active).bind(id)
            .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
    async fn deactivate(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE webhook_subscriptions SET is_active=false WHERE id=$1")
            .bind(id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
}

// ─── OutboxStore ───────────────────────────────────────────

#[async_trait]
impl OutboxStore for PgStore {
    async fn enqueue(&self, tenant_id: Option<Uuid>, event_type: &str, payload: serde_json::Value) -> Result<Uuid, AuthError> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO outbox_events (tenant_id, event_type, payload) VALUES ($1, $2, $3) RETURNING id"
        ).bind(tenant_id).bind(event_type).bind(&payload)
        .fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0)
    }
    async fn claim_pending(&self, limit: i64) -> Result<Vec<OutboxRecord>, AuthError> {
        sqlx::query_as::<_, OutboxRecord>(
            "SELECT id, tenant_id, event_type, payload, created_at, published_at, attempt_count, next_attempt_at, last_error \
             FROM outbox_events WHERE published_at IS NULL AND next_attempt_at <= now() \
             ORDER BY created_at LIMIT $1"
        ).bind(limit).fetch_all(&self.pool).await.map_err(AuthError::from)
    }
    async fn mark_published(&self, id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE outbox_events SET published_at=now() WHERE id=$1")
            .bind(id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
    async fn mark_retry(&self, id: Uuid, attempt: i32, error: &str) -> Result<(), AuthError> {
        sqlx::query("UPDATE outbox_events SET attempt_count=$1, last_error=$2, next_attempt_at=now()+make_interval(secs=>$3) WHERE id=$4")
            .bind(attempt).bind(error).bind((attempt as f64) * 30.0).bind(id)
            .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
    async fn delete_by_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        // payload is JSONB; match any event that references this user_id anywhere
        // inside its payload (covers "actor_id", "user_id", "target_id" variants).
        sqlx::query(
            "DELETE FROM outbox_events \
             WHERE payload::text LIKE '%' || $1::text || '%'"
        ).bind(user_id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
}

// ─── WebhookDeliveryStore ──────────────────────────────────

#[async_trait]
impl WebhookDeliveryStore for PgStore {
    async fn insert(&self, r: WebhookDeliveryRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO webhook_deliveries (id, outbox_event_id, webhook_id, event_type, status, status_code, response_body) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        ).bind(r.id).bind(r.outbox_event_id).bind(r.webhook_id).bind(&r.event_type)
        .bind(&r.status).bind(r.status_code).bind(&r.response_body)
        .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
    async fn list_by_webhook(&self, webhook_id: Uuid, limit: i64) -> Result<Vec<WebhookDeliveryRecord>, AuthError> {
        sqlx::query_as::<_, WebhookDeliveryRecord>(
            "SELECT id, outbox_event_id, webhook_id, event_type, status, status_code, response_body, created_at \
             FROM webhook_deliveries WHERE webhook_id=$1 ORDER BY created_at DESC LIMIT $2"
        ).bind(webhook_id).bind(limit).fetch_all(&self.pool).await.map_err(AuthError::from)
    }
}

// ─── AuditStore ────────────────────────────────────────────

#[async_trait]
impl AuditStore for PgStore {
    async fn insert(&self, r: AuditLogRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO audit_logs (event_type, actor_id, actor_ip, tenant_id, target_type, target_id, detail, request_id) \
             VALUES ($1, $2, $3::varchar, $4, $5, $6, $7, $8)"
        ).bind(&r.event_type).bind(r.actor_id).bind(&r.actor_ip).bind(r.tenant_id)
        .bind(&r.target_type).bind(&r.target_id).bind(&r.detail).bind(r.request_id)
        .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
    async fn list(&self, tenant_id: Uuid, offset: i64, limit: i64) -> Result<Vec<AuditLogRecord>, AuthError> {
        sqlx::query_as::<_, AuditLogRecord>(
            "SELECT id, timestamp, event_type, actor_id, actor_ip::varchar, tenant_id, target_type, target_id, detail, request_id \
             FROM audit_logs WHERE tenant_id=$1 ORDER BY timestamp DESC OFFSET $2 LIMIT $3"
        ).bind(tenant_id).bind(offset).bind(limit)
        .fetch_all(&self.pool).await.map_err(AuthError::from)
    }
    async fn anonymize(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("UPDATE audit_logs SET actor_id=NULL, detail=NULL WHERE actor_id=$1")
            .bind(user_id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
    async fn delete_flow_transitions_by_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        // auth_flow_transitions.flow_id → auth_flows.id (session_id → sessions.user_id)
        sqlx::query(
            "DELETE FROM auth_flow_transitions WHERE flow_id IN (\
                 SELECT id FROM auth_flows WHERE session_id IN (\
                     SELECT session_id FROM sessions WHERE user_id = $1::text\
                 )\
             )"
        ).bind(user_id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
}

// ─── DeviceTrustStore ──────────────────────────────────────

#[async_trait]
impl DeviceTrustStore for PgStore {
    async fn list_trusted(&self, user_id: Uuid) -> Result<Vec<TrustedDeviceRecord>, AuthError> {
        sqlx::query_as::<_, TrustedDeviceRecord>(
            "SELECT id, user_id, device_id, device_name, user_agent, ip_address, created_at, last_seen_at \
             FROM trusted_devices WHERE user_id=$1 ORDER BY last_seen_at DESC"
        ).bind(user_id).fetch_all(&self.pool).await.map_err(AuthError::from)
    }
    async fn create_trusted(&self, r: TrustedDeviceRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO trusted_devices (id, user_id, device_id, device_name, user_agent, ip_address) \
             VALUES ($1, $2, $3, $4, $5, $6)"
        ).bind(r.id).bind(r.user_id).bind(r.device_id).bind(&r.device_name)
        .bind(&r.user_agent).bind(&r.ip_address)
        .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
    async fn delete_trusted(&self, user_id: Uuid, device_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM trusted_devices WHERE user_id=$1 AND device_id=$2")
            .bind(user_id).bind(device_id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
    async fn delete_all_trusted(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM trusted_devices WHERE user_id=$1")
            .bind(user_id).execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }
}

// ─── BillingStore ──────────────────────────────────────────

#[async_trait]
impl BillingStore for PgStore {
    async fn list_plans(&self) -> Result<Vec<PlanRecord>, AuthError> {
        sqlx::query_as::<_, PlanRecord>("SELECT id, name, max_members, max_apps, features FROM plans ORDER BY max_members")
            .fetch_all(&self.pool).await.map_err(AuthError::from)
    }
    async fn find_subscription(&self, tenant_id: Uuid) -> Result<Option<SubscriptionRecord>, AuthError> {
        sqlx::query_as::<_, SubscriptionRecord>(
            "SELECT id, tenant_id, plan_id, status, stripe_sub_id, started_at, expires_at \
             FROM subscriptions WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT 1"
        ).bind(tenant_id).fetch_optional(&self.pool).await.map_err(AuthError::from)
    }
    async fn upsert_subscription(&self, r: SubscriptionRecord) -> Result<Uuid, AuthError> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO subscriptions (id, tenant_id, plan_id, status, stripe_sub_id, started_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (id) DO UPDATE SET plan_id=EXCLUDED.plan_id, status=EXCLUDED.status, \
               stripe_sub_id=EXCLUDED.stripe_sub_id, expires_at=EXCLUDED.expires_at \
             RETURNING id"
        ).bind(r.id).bind(r.tenant_id).bind(&r.plan_id).bind(&r.status)
        .bind(&r.stripe_sub_id).bind(r.started_at).bind(r.expires_at)
        .fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0)
    }
}

// ─── PolicyStore ───────────────────────────────────────────

#[async_trait]
impl PolicyStore for PgStore {
    async fn create(&self, r: PolicyRecord) -> Result<Uuid, AuthError> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO policies (id, tenant_id, resource, action, condition, effect, priority) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
        ).bind(r.id).bind(r.tenant_id).bind(&r.resource).bind(&r.action)
        .bind(&r.condition).bind(&r.effect).bind(r.priority)
        .fetch_one(&self.pool).await.map_err(AuthError::from)?;
        Ok(row.0)
    }
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<PolicyRecord>, AuthError> {
        sqlx::query_as::<_, PolicyRecord>(
            "SELECT id, tenant_id, resource, action, condition, effect, priority, is_active, created_at \
             FROM policies WHERE tenant_id=$1 AND is_active=true ORDER BY priority DESC"
        ).bind(tenant_id).fetch_all(&self.pool).await.map_err(AuthError::from)
    }
    async fn find_matching(&self, tenant_id: Uuid, resource: &str, action: &str) -> Result<Option<PolicyRecord>, AuthError> {
        sqlx::query_as::<_, PolicyRecord>(
            "SELECT id, tenant_id, resource, action, condition, effect, priority, is_active, created_at \
             FROM policies WHERE tenant_id=$1 AND resource=$2 AND action=$3 AND is_active=true \
             ORDER BY priority DESC LIMIT 1"
        ).bind(tenant_id).bind(resource).bind(action)
        .fetch_optional(&self.pool).await.map_err(AuthError::from)
    }
}

// ─── OidcFlowStore (Backlog P0 #1) ─────────────────────────

#[async_trait]
impl OidcFlowStore for PgStore {
    async fn save(&self, r: OidcFlowRecord) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO oidc_flows \
               (id, state, nonce, code_verifier_encrypted, return_to, invite_code, tenant_id, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        )
        .bind(r.id)
        .bind(&r.state)
        .bind(&r.nonce)
        .bind(&r.code_verifier_encrypted)
        .bind(r.return_to.as_deref())
        .bind(r.invite_code.as_deref())
        .bind(r.tenant_id)
        .bind(r.expires_at)
        .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(())
    }

    async fn consume(&self, state: &str) -> Result<Option<OidcFlowRecord>, AuthError> {
        // Atomic single-use semantics: DELETE … RETURNING … ensures a
        // concurrent second consumption sees zero rows.
        let row: Option<OidcFlowRecord> = sqlx::query_as::<_, OidcFlowRecord>(
            "DELETE FROM oidc_flows \
             WHERE state = $1 AND expires_at > now() \
             RETURNING id, state, nonce, code_verifier_encrypted, return_to, invite_code, \
                       tenant_id, created_at, expires_at"
        )
        .bind(state)
        .fetch_optional(&self.pool).await.map_err(AuthError::from)?;
        Ok(row)
    }

    async fn delete_expired(&self) -> Result<u64, AuthError> {
        let res = sqlx::query("DELETE FROM oidc_flows WHERE expires_at <= now()")
            .execute(&self.pool).await.map_err(AuthError::from)?;
        Ok(res.rows_affected())
    }
}

// ─── Paginated admin queries (P2.1) ────────────────────────
//
// These are direct methods on PgStore (no trait) — the admin handlers pass the
// rows through as JSON, so we skip the overhead of reconstructing full record
// structs. `order` is a pre-sanitized SQL fragment produced by
// `auth-server::pagination::PageRequest::order_sql`.

impl PgStore {
    /// `(items, total)` — users list with optional `q` (email/display_name) filter.
    pub async fn list_users_paginated(
        &self,
        q: Option<&str>,
        order: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<serde_json::Value>, i64), AuthError> {
        let sql = format!(
            "SELECT id, email, display_name, is_active, created_at, locale, \
                    COUNT(*) OVER() AS total_count \
             FROM users \
             WHERE deleted_at IS NULL \
               AND ($1::text IS NULL OR email ILIKE '%' || $1 || '%' OR COALESCE(display_name,'') ILIKE '%' || $1 || '%') \
             ORDER BY {} LIMIT $2 OFFSET $3",
            order
        );
        let rows: Vec<(Uuid, String, Option<String>, bool, chrono::DateTime<chrono::Utc>, Option<String>, i64)> =
            sqlx::query_as(&sql).bind(q).bind(limit).bind(offset)
                .fetch_all(&self.pool).await.map_err(AuthError::from)?;
        let total = rows.first().map(|r| r.6).unwrap_or(0);
        let items = rows.into_iter().map(|(id, email, name, active, created, locale, _)| {
            serde_json::json!({
                "id": id,
                "email": email,
                "display_name": name,
                "is_active": active,
                "created_at": created.to_rfc3339(),
                "locale": locale,
            })
        }).collect();
        Ok((items, total))
    }

    /// `(items, total)` — sessions list, optionally filtered by user_id.
    pub async fn list_sessions_paginated(
        &self,
        user_id: Option<&str>,
        order: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<serde_json::Value>, i64), AuthError> {
        let sql = format!(
            "SELECT id, user_id, tenant_id, created_at, expires_at, invalidated_at, ip_address, user_agent, \
                    COUNT(*) OVER() AS total_count \
             FROM sessions \
             WHERE ($1::text IS NULL OR user_id = $1) \
             ORDER BY {} LIMIT $2 OFFSET $3",
            order
        );
        let rows: Vec<(String, String, String, i64, i64, Option<i64>, Option<String>, Option<String>, i64)> =
            sqlx::query_as(&sql).bind(user_id).bind(limit).bind(offset)
                .fetch_all(&self.pool).await.map_err(AuthError::from)?;
        let total = rows.first().map(|r| r.8).unwrap_or(0);
        let items = rows.into_iter().map(|(id, uid, tid, created, expires, invalidated, ip, ua, _)| {
            serde_json::json!({
                "session_id": id,
                "user_id": uid,
                "tenant_id": tid,
                "created_at": created,
                "expires_at": expires,
                "invalidated_at": invalidated,
                "ip_address": ip,
                "user_agent": ua,
                "active": invalidated.is_none(),
            })
        }).collect();
        Ok((items, total))
    }

    /// `(items, total)` — audit log with from/to/event filters.
    pub async fn list_audit_paginated(
        &self,
        tenant_id: Uuid,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
        event: Option<&str>,
        order: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<serde_json::Value>, i64), AuthError> {
        let sql = format!(
            "SELECT id, timestamp, event_type, actor_id, tenant_id, target_type, target_id, \
                    COUNT(*) OVER() AS total_count \
             FROM audit_logs \
             WHERE tenant_id = $1 \
               AND ($2::timestamptz IS NULL OR timestamp >= $2) \
               AND ($3::timestamptz IS NULL OR timestamp <= $3) \
               AND ($4::text IS NULL OR event_type = $4) \
             ORDER BY {} LIMIT $5 OFFSET $6",
            order
        );
        let rows: Vec<(i64, chrono::DateTime<chrono::Utc>, String, Option<Uuid>, Option<Uuid>, Option<String>, Option<String>, i64)> =
            sqlx::query_as(&sql).bind(tenant_id).bind(from).bind(to).bind(event).bind(limit).bind(offset)
                .fetch_all(&self.pool).await.map_err(AuthError::from)?;
        let total = rows.first().map(|r| r.7).unwrap_or(0);
        let items = rows.into_iter().map(|(id, ts, ev, actor, tid, ttype, tid_str, _)| {
            serde_json::json!({
                "id": id,
                "timestamp": ts.to_rfc3339(),
                "event_type": ev,
                "actor_id": actor,
                "tenant_id": tid,
                "target_type": ttype,
                "target_id": tid_str,
            })
        }).collect();
        Ok((items, total))
    }

    /// `(items, total)` — tenant members list.
    pub async fn list_members_paginated(
        &self,
        tenant_id: Uuid,
        order: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<serde_json::Value>, i64), AuthError> {
        let sql = format!(
            "SELECT m.id, m.user_id, u.email, u.display_name, m.role, m.is_active, m.joined_at, \
                    COUNT(*) OVER() AS total_count \
             FROM memberships m \
             LEFT JOIN users u ON u.id = m.user_id \
             WHERE m.tenant_id = $1 \
             ORDER BY {} LIMIT $2 OFFSET $3",
            order
        );
        let rows: Vec<(Uuid, Uuid, Option<String>, Option<String>, String, bool, chrono::DateTime<chrono::Utc>, i64)> =
            sqlx::query_as(&sql).bind(tenant_id).bind(limit).bind(offset)
                .fetch_all(&self.pool).await.map_err(AuthError::from)?;
        let total = rows.first().map(|r| r.7).unwrap_or(0);
        let items = rows.into_iter().map(|(id, uid, email, name, role, active, joined, _)| {
            serde_json::json!({
                "id": id,
                "user_id": uid,
                "email": email,
                "display_name": name,
                "role": role,
                "is_active": active,
                "joined_at": joined.to_rfc3339(),
            })
        }).collect();
        Ok((items, total))
    }

    /// `(items, total)` — invitations list, filtered by status (pending / used / expired).
    pub async fn list_invitations_paginated(
        &self,
        tenant_id: Uuid,
        status: Option<&str>,
        order: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<serde_json::Value>, i64), AuthError> {
        // Status filter is expressed as SQL fragment because the condition is
        // multi-predicate; we still keep the column-sort whitelist via `order`.
        let status_sql = match status.unwrap_or("").to_ascii_lowercase().as_str() {
            "pending" => "used_count < max_uses AND expires_at > now()",
            "used" => "used_count >= max_uses",
            "expired" => "expires_at <= now() AND used_count < max_uses",
            _ => "TRUE",
        };
        let sql = format!(
            "SELECT id, tenant_id, code, email, role, used_count, max_uses, created_at, expires_at, \
                    COUNT(*) OVER() AS total_count \
             FROM invitations \
             WHERE tenant_id = $1 AND {} \
             ORDER BY {} LIMIT $2 OFFSET $3",
            status_sql, order
        );
        let rows: Vec<(Uuid, Uuid, String, Option<String>, String, i32, i32, chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>, i64)> =
            sqlx::query_as(&sql).bind(tenant_id).bind(limit).bind(offset)
                .fetch_all(&self.pool).await.map_err(AuthError::from)?;
        let total = rows.first().map(|r| r.9).unwrap_or(0);
        let items = rows.into_iter().map(|(id, tid, code, email, role, used, max, created, expires, _)| {
            serde_json::json!({
                "id": id,
                "tenant_id": tid,
                "code": code,
                "email": email,
                "role": role,
                "used_count": used,
                "max_uses": max,
                "created_at": created.to_rfc3339(),
                "expires_at": expires.to_rfc3339(),
            })
        }).collect();
        Ok((items, total))
    }
}
