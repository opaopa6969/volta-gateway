//! テナント管理 API の認可をハンドラ単位で確かめる統合テスト。
//!
//! Docker の PostgreSQL（testcontainers、ホスト側ポートはランダム）を使うので
//! `#[ignore]` にしてある。実行:
//!
//! ```text
//! cargo test -p volta-auth-server tenant_authz -- --ignored --test-threads=1
//! ```
//!
//! テナント A（OWNER / ADMIN / MEMBER）とテナント B（OWNER）を用意し、
//! cookie セッションと Bearer トークンの両方で、自テナントの正当な操作は通り、
//! 他テナント・権限不足・ロール昇格は 403 になることを見る。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use axum_extra::extract::CookieJar;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiError;
use crate::handlers::{admin, extra, manage, mfa, signing_key, webhook};
use crate::pagination::PageRequest;
use crate::state::AppState;
use volta_auth_core::record::*;
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::*;

const JWT_SECRET: &[u8] = b"tenant-authz-test-secret-0123456789abcdef";
/// `SYSTEM_ADMIN_EMAILS` に載せるテスト用のシステム管理者。
const SYSTEM_ADMIN_EMAIL: &str = "root@example.com";

struct Fixture {
    _container: testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>,
    state: AppState,
    tenant_a: Uuid,
    tenant_b: Uuid,
    owner_a: Actor,
    admin_a: Actor,
    member_a: Actor,
    owner_b: Actor,
}

struct Actor {
    user_id: Uuid,
    session_id: String,
}

async fn setup_pool() -> (
    PgPool,
    testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>,
) {
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::postgres::Postgres;

    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port);
    let pool = PgPool::connect(&url).await.unwrap();

    // auth-core/migrations を番号順に全部流す（本番と同じスキーマ）。
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../auth-core/migrations");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    for f in files {
        let sql = std::fs::read_to_string(&f).unwrap();
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("migration {} failed: {e}", f.display()));
    }
    (pool, container)
}

fn test_state(pool: PgPool) -> AppState {
    use volta_auth_core::idp::{IdpClient, IdpConfig};
    use volta_auth_core::jwt::{JwtIssuer, JwtVerifier};
    use volta_auth_core::notification::{NotificationConfig, NotificationService};

    AppState {
        db: PgStore::new(pool),
        idp: Arc::new(IdpClient::new(IdpConfig {
            provider: "google".into(),
            client_id: String::new(),
            client_secret: String::new(),
            issuer_url: None,
            auth_url: None,
            token_url: None,
            userinfo_url: None,
            scopes: vec![],
            jwks_url: None,
            display_name: None,
        })),
        jwt_issuer: JwtIssuer::new_hs256(JWT_SECRET, 300),
        jwt_verifier: JwtVerifier::new_hs256(JWT_SECRET),
        op_issuer: None,
        cookie_domain: String::new(),
        session_ttl_secs: 300,
        force_secure_cookie: false,
        base_url: "http://localhost".into(),
        state_signing_key: vec![7; 32],
        local_bypass: Arc::new(crate::local_bypass::LocalNetworkBypass::new("")),
        auth_events: crate::auth_events::AuthEventBus::new(),
        key_cipher: Arc::new(volta_auth_core::crypto::KeyCipher::from_master(&[9; 32])),
        passkey: None,
        notifications: Arc::new(NotificationService::new(NotificationConfig::default())),
        notify_channel: "DUMMY".into(),
        email_verification_enabled: false,
        passkey_signup_enabled: false,
        return_to: Arc::new(crate::return_to::ReturnToPolicy::from_settings(
            None,
            "",
            "http://localhost",
        )),
        system_admins: Arc::new(crate::helpers::SystemAdmins::parse(SYSTEM_ADMIN_EMAIL)),
    }
}

async fn create_user(db: &PgStore, email: &str) -> Uuid {
    UserStore::upsert(
        db,
        UserRecord {
            id: Uuid::new_v4(),
            email: email.into(),
            display_name: Some(email.into()),
            google_sub: None,
            created_at: Utc::now(),
            is_active: true,
            locale: None,
            deleted_at: None,
        },
    )
    .await
    .unwrap()
    .id
}

async fn create_tenant(db: &PgStore, slug: &str, owner: Uuid) -> Uuid {
    TenantStore::create(
        db,
        TenantRecord {
            id: Uuid::new_v4(),
            name: slug.into(),
            slug: slug.into(),
            email_domain: None,
            auto_join: false,
            created_by: Some(owner),
            created_at: Utc::now(),
            plan: Some("FREE".into()),
            max_members: Some(50),
            is_active: true,
            mfa_required: false,
            mfa_grace_until: None,
        },
    )
    .await
    .unwrap()
    .id
}

async fn add_member(db: &PgStore, user: Uuid, tenant: Uuid, role: &str) {
    MembershipStore::create(
        db,
        MembershipRecord {
            id: Uuid::new_v4(),
            user_id: user,
            tenant_id: tenant,
            role: role.into(),
            joined_at: Utc::now(),
            invited_by: None,
            is_active: true,
        },
    )
    .await
    .unwrap();
}

async fn login(db: &PgStore, user: Uuid, tenant: Uuid, role: &str) -> String {
    let now = Utc::now().timestamp() as u64;
    let sid = Uuid::new_v4().to_string();
    SessionStore::create(
        db,
        SessionRecord {
            session_id: sid.clone(),
            user_id: user.to_string(),
            tenant_id: tenant.to_string(),
            return_to: None,
            created_at: now,
            last_active_at: now,
            expires_at: now + 3600,
            invalidated_at: None,
            mfa_verified_at: Some(now),
            ip_address: None,
            user_agent: None,
            csrf_token: None,
            email: None,
            tenant_slug: None,
            roles: vec![role.into()],
            display_name: None,
        },
    )
    .await
    .unwrap();
    sid
}

async fn actor(db: &PgStore, email: &str, tenant: Uuid, role: &str) -> Actor {
    let user_id = create_user(db, email).await;
    add_member(db, user_id, tenant, role).await;
    let session_id = login(db, user_id, tenant, role).await;
    Actor {
        user_id,
        session_id,
    }
}

async fn setup() -> Fixture {
    let (pool, container) = setup_pool().await;
    let state = test_state(pool);
    let db = &state.db;

    let founder_a = create_user(db, "founder-a@example.com").await;
    let founder_b = create_user(db, "founder-b@example.com").await;
    let tenant_a = create_tenant(db, "tenant-a", founder_a).await;
    let tenant_b = create_tenant(db, "tenant-b", founder_b).await;

    let owner_a = actor(db, "owner-a@example.com", tenant_a, "OWNER").await;
    let admin_a = actor(db, "admin-a@example.com", tenant_a, "ADMIN").await;
    let member_a = actor(db, "member-a@example.com", tenant_a, "MEMBER").await;
    let owner_b = actor(db, "owner-b@example.com", tenant_b, "OWNER").await;

    Fixture {
        _container: container,
        state,
        tenant_a,
        tenant_b,
        owner_a,
        admin_a,
        member_a,
        owner_b,
    }
}

impl Actor {
    fn jar(&self) -> CookieJar {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            format!("__volta_session={}", self.session_id)
                .parse()
                .unwrap(),
        );
        CookieJar::from_headers(&h)
    }
}

fn no_bearer() -> HeaderMap {
    HeaderMap::new()
}

fn bearer(state: &AppState, tenant: Uuid, roles: &str) -> HeaderMap {
    let token = state
        .jwt_issuer
        .issue(&volta_auth_core::jwt::VoltaClaims {
            sub: "m2m_test".into(),
            email: None,
            tenant_id: Some(tenant.to_string()),
            tenant_slug: None,
            roles: Some(roles.into()),
            name: None,
            app_id: None,
            iat: None,
            exp: None,
            jti: None,
            aud: None,
            scope: None,
        })
        .unwrap();
    let mut h = HeaderMap::new();
    h.insert("authorization", format!("Bearer {token}").parse().unwrap());
    h
}

fn empty_jar() -> CookieJar {
    CookieJar::from_headers(&HeaderMap::new())
}

fn status(r: Result<Response, ApiError>) -> StatusCode {
    match r {
        Ok(resp) => resp.status(),
        Err(e) => e.status,
    }
}

async fn body_json(r: Result<Response, ApiError>) -> serde_json::Value {
    let resp = r.unwrap_or_else(|e| panic!("expected success, got {:?}", e));
    assert!(resp.status().is_success(), "status {}", resp.status());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn invite(role: Option<&str>) -> Json<manage::CreateInviteReq> {
    Json(manage::CreateInviteReq {
        email: None,
        role: role.map(String::from),
    })
}

fn page() -> Query<PageRequest> {
    Query(PageRequest::default())
}

// ─── 招待 ──────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn invitation_create_is_tenant_and_role_bounded() {
    let f = setup().await;
    let s = &f.state;
    let inv = |a: &Actor, tid: Uuid, role: Option<&str>| {
        manage::create_invitation(
            State(s.clone()),
            a.jar(),
            no_bearer(),
            Path(tid),
            invite(role),
        )
    };

    // 他テナント → 403（OWNER でも）
    assert_eq!(
        status(inv(&f.admin_a, f.tenant_b, None).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(inv(&f.owner_a, f.tenant_b, Some("MEMBER")).await),
        StatusCode::FORBIDDEN
    );
    // 自テナントの MEMBER → 403
    assert_eq!(
        status(inv(&f.member_a, f.tenant_a, None).await),
        StatusCode::FORBIDDEN
    );
    // OWNER 招待は OWNER 自身でも拒否
    assert_eq!(
        status(inv(&f.owner_a, f.tenant_a, Some("OWNER")).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(inv(&f.admin_a, f.tenant_a, Some("owner")).await),
        StatusCode::FORBIDDEN
    );
    // 未知ロール → 400
    assert_eq!(
        status(inv(&f.admin_a, f.tenant_a, Some("SUPERUSER")).await),
        StatusCode::BAD_REQUEST
    );
    // 自テナントの ADMIN は MEMBER / ADMIN を招待できる
    assert!(inv(&f.admin_a, f.tenant_a, None).await.is_ok());
    assert!(inv(&f.admin_a, f.tenant_a, Some("admin")).await.is_ok());

    let stored = InvitationStore::list_by_tenant(&s.db, f.tenant_a)
        .await
        .unwrap();
    assert_eq!(stored.len(), 2);
    let mut roles: Vec<_> = stored.iter().map(|i| i.role.clone()).collect();
    roles.sort();
    assert_eq!(roles, vec!["ADMIN", "MEMBER"]);
    assert!(InvitationStore::list_by_tenant(&s.db, f.tenant_b)
        .await
        .unwrap()
        .is_empty());

    // Bearer: 他テナント向けトークン → 403、M2M（users 行なし）は招待を作れない → 403
    let r = manage::create_invitation(
        State(s.clone()),
        empty_jar(),
        bearer(s, f.tenant_b, "ADMIN"),
        Path(f.tenant_a),
        invite(None),
    )
    .await;
    assert_eq!(status(r), StatusCode::FORBIDDEN);
    let r = manage::create_invitation(
        State(s.clone()),
        empty_jar(),
        bearer(s, f.tenant_a, "ADMIN"),
        Path(f.tenant_a),
        invite(None),
    )
    .await;
    assert_eq!(status(r), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore]
async fn invitation_list_and_cancel_are_tenant_scoped() {
    let f = setup().await;
    let s = &f.state;

    let code = body_json(
        manage::create_invitation(
            State(s.clone()),
            f.admin_a.jar(),
            no_bearer(),
            Path(f.tenant_a),
            invite(None),
        )
        .await,
    )
    .await["code"]
        .as_str()
        .unwrap()
        .to_string();
    let inv = InvitationStore::find_by_code(&s.db, &code)
        .await
        .unwrap()
        .unwrap();

    // 一覧: 他テナント・MEMBER は 403、自テナント ADMIN は 200
    let list = |a: &Actor, tid: Uuid| {
        manage::list_invitations(State(s.clone()), a.jar(), no_bearer(), Path(tid), page())
    };
    assert_eq!(
        status(list(&f.owner_b, f.tenant_a).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(list(&f.member_a, f.tenant_a).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(status(list(&f.admin_a, f.tenant_a).await), StatusCode::OK);

    let cancel = |a: &Actor, tid: Uuid| {
        manage::cancel_invitation(State(s.clone()), a.jar(), no_bearer(), Path((tid, inv.id)))
    };
    // B の OWNER が A の招待を取り消そうとする: A のパスでは 403、
    // 自分の B のパスに A の招待 id を付けても効かない
    assert_eq!(
        status(cancel(&f.owner_b, f.tenant_a).await),
        StatusCode::FORBIDDEN
    );
    assert_ne!(status(cancel(&f.owner_b, f.tenant_b).await), StatusCode::OK);
    // MEMBER も取り消せない
    assert_eq!(
        status(cancel(&f.member_a, f.tenant_a).await),
        StatusCode::FORBIDDEN
    );
    let still = InvitationStore::find_by_code(&s.db, &code)
        .await
        .unwrap()
        .unwrap();
    assert!(
        still.is_usable_at(Utc::now()),
        "招待が他テナントから取り消された"
    );

    // 自テナントの ADMIN は取り消せる
    assert_eq!(status(cancel(&f.admin_a, f.tenant_a).await), StatusCode::OK);
    let after = InvitationStore::find_by_code(&s.db, &code)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.is_usable_at(Utc::now()));
}

// ─── M2M client ────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn m2m_client_creation_is_tenant_and_scope_bounded() {
    let f = setup().await;
    let s = &f.state;
    let create = |jar: CookieJar, headers: HeaderMap, tid: Uuid, scopes: &str| {
        manage::create_m2m_client(
            State(s.clone()),
            jar,
            headers,
            Path(tid),
            Json(manage::CreateM2mReq {
                scopes: Some(scopes.into()),
            }),
        )
    };

    // cookie: 他テナント → 403、MEMBER → 403、ADMIN が OWNER scope → 403、未知 scope → 400
    assert_eq!(
        status(create(f.admin_a.jar(), no_bearer(), f.tenant_b, "MEMBER").await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(create(f.member_a.jar(), no_bearer(), f.tenant_a, "MEMBER").await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(create(f.admin_a.jar(), no_bearer(), f.tenant_a, "OWNER").await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(create(f.admin_a.jar(), no_bearer(), f.tenant_a, "ADMIN,root").await),
        StatusCode::BAD_REQUEST
    );
    // 自テナント ADMIN → 成功、scopes は正規化される
    assert!(
        create(f.admin_a.jar(), no_bearer(), f.tenant_a, "admin member")
            .await
            .is_ok()
    );
    let clients = M2mClientStore::list_by_tenant(&s.db, f.tenant_a)
        .await
        .unwrap();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0].scopes, "ADMIN,MEMBER");
    assert!(M2mClientStore::list_by_tenant(&s.db, f.tenant_b)
        .await
        .unwrap()
        .is_empty());

    // Bearer: 他テナントのトークン → 403、MEMBER トークン → 403、
    // ADMIN トークンが OWNER scope → 403、自テナント ADMIN トークン → 成功
    assert_eq!(
        status(
            create(
                empty_jar(),
                bearer(s, f.tenant_a, "ADMIN"),
                f.tenant_b,
                "MEMBER"
            )
            .await
        ),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(
            create(
                empty_jar(),
                bearer(s, f.tenant_a, "MEMBER"),
                f.tenant_a,
                "MEMBER"
            )
            .await
        ),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(
            create(
                empty_jar(),
                bearer(s, f.tenant_a, "ADMIN"),
                f.tenant_a,
                "OWNER"
            )
            .await
        ),
        StatusCode::FORBIDDEN
    );
    assert!(create(
        empty_jar(),
        bearer(s, f.tenant_a, "ADMIN"),
        f.tenant_a,
        "VIEWER"
    )
    .await
    .is_ok());
    // Bearer があれば cookie には戻らない（他テナントのトークン + 自テナント ADMIN の cookie → 403）
    assert_eq!(
        status(
            create(
                f.admin_a.jar(),
                bearer(s, f.tenant_b, "ADMIN"),
                f.tenant_a,
                "MEMBER"
            )
            .await
        ),
        StatusCode::FORBIDDEN
    );

    // 一覧
    let list = |a: &Actor, tid: Uuid| {
        manage::list_m2m_clients(State(s.clone()), a.jar(), no_bearer(), Path(tid))
    };
    assert_eq!(
        status(list(&f.owner_b, f.tenant_a).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(list(&f.member_a, f.tenant_a).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(status(list(&f.admin_a, f.tenant_a).await), StatusCode::OK);
}

// ─── 管理画面からのユーザー作成 ──────────────────────────────────

#[tokio::test]
#[ignore]
async fn admin_create_user_is_bounded_to_callers_tenant() {
    let f = setup().await;
    let s = &f.state;
    let create = |jar: CookieJar, headers: HeaderMap, tid: Uuid, role: &str, email: &str| {
        admin::admin_create_user(
            State(s.clone()),
            jar,
            headers,
            Json(admin::AdminCreateUserReq {
                tenant_id: tid,
                email: email.into(),
                display_name: None,
                role: role.into(),
            }),
        )
    };

    // 自テナントの ADMIN が他テナントへ → 403
    assert_eq!(
        status(
            create(
                f.admin_a.jar(),
                no_bearer(),
                f.tenant_b,
                "ADMIN",
                "x@example.com"
            )
            .await
        ),
        StatusCode::FORBIDDEN
    );
    // Bearer の他テナント向け → 403
    assert_eq!(
        status(
            create(
                empty_jar(),
                bearer(s, f.tenant_a, "ADMIN"),
                f.tenant_b,
                "MEMBER",
                "y@example.com"
            )
            .await
        ),
        StatusCode::FORBIDDEN
    );
    // MEMBER → 403
    assert_eq!(
        status(
            create(
                f.member_a.jar(),
                no_bearer(),
                f.tenant_a,
                "MEMBER",
                "z@example.com"
            )
            .await
        ),
        StatusCode::FORBIDDEN
    );
    // OWNER 指定 → 400（この入口では扱わない、既存の挙動）
    assert_eq!(
        status(
            create(
                f.owner_a.jar(),
                no_bearer(),
                f.tenant_a,
                "OWNER",
                "w@example.com"
            )
            .await
        ),
        StatusCode::BAD_REQUEST
    );
    // 他テナントにはメンバーが増えていない
    assert_eq!(
        MembershipStore::list_by_tenant(&s.db, f.tenant_b)
            .await
            .unwrap()
            .len(),
        1
    );

    // 自テナントの ADMIN は ADMIN 以下を作れる（cookie / Bearer どちらも）
    assert_eq!(
        status(
            create(
                f.admin_a.jar(),
                no_bearer(),
                f.tenant_a,
                "ADMIN",
                "new-admin@example.com"
            )
            .await
        ),
        StatusCode::CREATED
    );
    assert_eq!(
        status(
            create(
                empty_jar(),
                bearer(s, f.tenant_a, "ADMIN"),
                f.tenant_a,
                "MEMBER",
                "new-m@example.com"
            )
            .await
        ),
        StatusCode::CREATED
    );
}

// ─── 組織の作成と名称変更 ────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn company_creation_and_management_are_scoped_and_atomic() {
    let f = setup().await;
    let state = &f.state;
    let slug = "new-company";
    let create = |name: &str| {
        manage::create_tenant(
            State(state.clone()),
            f.owner_a.jar(),
            Json(manage::CreateTenantReq {
                name: name.into(),
                slug: slug.into(),
            }),
        )
    };
    assert_eq!(status(create("   ").await), StatusCode::BAD_REQUEST);
    sqlx::query("ALTER TABLE memberships ADD CONSTRAINT test_owner_creation_guard CHECK (role <> 'OWNER') NOT VALID")
        .execute(state.db.pool())
        .await
        .unwrap();
    assert!(create("新しい会社").await.is_err());
    assert!(TenantStore::find_by_slug(&state.db, slug)
        .await
        .unwrap()
        .is_none());
    sqlx::query("ALTER TABLE memberships DROP CONSTRAINT test_owner_creation_guard")
        .execute(state.db.pool())
        .await
        .unwrap();

    let response = body_json(create("  新しい会社  ").await).await;
    let id = response["id"].as_str().unwrap().parse::<Uuid>().unwrap();
    let owner = MembershipStore::find(&state.db, f.owner_a.user_id, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.role, "OWNER");
    assert_eq!(
        TenantStore::find_by_id(&state.db, id)
            .await
            .unwrap()
            .unwrap()
            .name,
        "新しい会社"
    );

    let rename = |actor: &Actor| {
        manage::patch_tenant(
            State(state.clone()),
            actor.jar(),
            no_bearer(),
            Path(id),
            Json(manage::PatchTenantReq {
                name: Some("変更後の名称".into()),
            }),
        )
    };
    assert_eq!(status(rename(&f.owner_b).await), StatusCode::FORBIDDEN);
    assert_eq!(status(rename(&f.owner_a).await), StatusCode::OK);
    assert_eq!(
        TenantStore::find_by_id(&state.db, id)
            .await
            .unwrap()
            .unwrap()
            .name,
        "変更後の名称"
    );
}

// ─── その他のテナント管理 API ──────────────────────────────────

#[tokio::test]
#[ignore]
async fn other_tenant_admin_endpoints_require_membership_and_role() {
    let f = setup().await;
    let s = &f.state;
    let (a, b) = (f.tenant_a, f.tenant_b);

    // テナント参照: 所属者なら MEMBER でも可、他テナントは 403
    let get =
        |x: &Actor, tid| manage::get_tenant(State(s.clone()), x.jar(), no_bearer(), Path(tid));
    assert_eq!(status(get(&f.member_a, a).await), StatusCode::OK);
    assert_eq!(status(get(&f.owner_b, a).await), StatusCode::FORBIDDEN);

    // メンバー一覧: MEMBER 以上
    let members = |x: &Actor, tid| {
        manage::list_members(State(s.clone()), x.jar(), no_bearer(), Path(tid), page())
    };
    assert_eq!(status(members(&f.member_a, a).await), StatusCode::OK);
    assert_eq!(status(members(&f.member_a, b).await), StatusCode::FORBIDDEN);

    // メンバー変更: 他テナントの OWNER → 403、MEMBER → 403
    let target = MembershipStore::find(&s.db, f.member_a.user_id, a)
        .await
        .unwrap()
        .unwrap();
    let patch = |x: &Actor, tid, role: &str| {
        manage::patch_member(
            State(s.clone()),
            x.jar(),
            no_bearer(),
            Path((tid, target.id)),
            Json(manage::PatchMemberReq { role: role.into() }),
        )
    };
    assert_eq!(
        status(patch(&f.owner_b, a, "ADMIN").await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(patch(&f.owner_b, b, "ADMIN").await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(patch(&f.member_a, a, "ADMIN").await),
        StatusCode::FORBIDDEN
    );
    // ADMIN が OWNER を付与 → 403、ADMIN 以下は可
    assert_eq!(
        status(patch(&f.admin_a, a, "OWNER").await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(status(patch(&f.admin_a, a, "VIEWER").await), StatusCode::OK);

    // IdP 設定: ADMIN 以上
    let idp_list = |x: &Actor, tid| {
        manage::list_idp_configs(State(s.clone()), x.jar(), no_bearer(), Path(tid))
    };
    assert_eq!(status(idp_list(&f.admin_a, a).await), StatusCode::OK);
    assert_eq!(
        status(idp_list(&f.member_a, a).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(status(idp_list(&f.owner_b, a).await), StatusCode::FORBIDDEN);
    let upsert = manage::upsert_idp_config(
        State(s.clone()),
        f.owner_b.jar(),
        no_bearer(),
        Path(a),
        Json(manage::UpsertIdpReq {
            provider_type: "OIDC".into(),
            client_id: Some("c".into()),
            client_secret: None,
            issuer: Some("https://issuer.example.com".into()),
            metadata_url: None,
        }),
    )
    .await;
    assert_eq!(status(upsert), StatusCode::FORBIDDEN);
    assert!(IdpConfigStore::list_by_tenant(&s.db, a)
        .await
        .unwrap()
        .is_empty());

    // Webhook: 他テナント・MEMBER は 403、自テナント ADMIN は可
    let wh_list =
        |x: &Actor, tid| webhook::list_webhooks(State(s.clone()), x.jar(), no_bearer(), Path(tid));
    assert_eq!(status(wh_list(&f.admin_a, a).await), StatusCode::OK);
    assert_eq!(status(wh_list(&f.member_a, a).await), StatusCode::FORBIDDEN);
    assert_eq!(status(wh_list(&f.owner_b, a).await), StatusCode::FORBIDDEN);

    // Billing / Policy: 他テナントは 403
    assert_eq!(
        status(admin::get_billing(State(s.clone()), f.owner_b.jar(), no_bearer(), Path(a)).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(admin::list_policies(State(s.clone()), f.owner_b.jar(), no_bearer(), Path(a)).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(admin::list_policies(State(s.clone()), f.admin_a.jar(), no_bearer(), Path(a)).await),
        StatusCode::OK
    );

    // ユーザー単位の API は本人だけ
    assert_eq!(
        status(
            manage::list_passkeys(State(s.clone()), f.admin_a.jar(), Path(f.member_a.user_id))
                .await
        ),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(
            manage::list_passkeys(State(s.clone()), f.member_a.jar(), Path(f.member_a.user_id))
                .await
        ),
        StatusCode::OK
    );
    assert_eq!(
        status(
            manage::patch_user(
                State(s.clone()),
                f.owner_a.jar(),
                Path(f.member_a.user_id),
                Json(manage::PatchUserReq {
                    display_name: Some("x".into()),
                    locale: None,
                }),
            )
            .await
        ),
        StatusCode::FORBIDDEN
    );
}

// ─── オーナー移譲 ──────────────────────────────────────────────

async fn role_of(db: &PgStore, user: Uuid, tenant: Uuid) -> Option<String> {
    MembershipStore::find(db, user, tenant)
        .await
        .unwrap()
        .map(|m| m.role)
}

#[tokio::test]
#[ignore]
async fn transfer_ownership_is_owner_only_and_within_tenant() {
    let f = setup().await;
    let s = &f.state;
    let a = f.tenant_a;
    let transfer = |jar: CookieJar, headers: HeaderMap, tid: Uuid, to: Uuid| {
        extra::transfer_ownership(
            State(s.clone()),
            jar,
            headers,
            Path(tid),
            Json(extra::TransferReq { to_user_id: to }),
        )
    };

    // OWNER 以外（ADMIN / MEMBER）は移譲できない。ロールも変わらない。
    assert_eq!(
        status(transfer(f.admin_a.jar(), no_bearer(), a, f.admin_a.user_id).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(transfer(f.member_a.jar(), no_bearer(), a, f.member_a.user_id).await),
        StatusCode::FORBIDDEN
    );
    // 他テナントの OWNER も不可
    assert_eq!(
        status(transfer(f.owner_b.jar(), no_bearer(), a, f.owner_b.user_id).await),
        StatusCode::FORBIDDEN
    );
    // Bearer（M2M）は OWNER scope でも不可
    assert_eq!(
        status(transfer(empty_jar(), bearer(s, a, "OWNER"), a, f.admin_a.user_id).await),
        StatusCode::FORBIDDEN
    );
    // 移譲先がテナント外・自分自身・無効なメンバー → 400、実行者は OWNER のまま
    assert_eq!(
        status(transfer(f.owner_a.jar(), no_bearer(), a, f.owner_b.user_id).await),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        status(transfer(f.owner_a.jar(), no_bearer(), a, f.owner_a.user_id).await),
        StatusCode::BAD_REQUEST
    );
    let inactive = actor(&s.db, "inactive-a@example.com", a, "MEMBER").await;
    sqlx::query("UPDATE memberships SET is_active = false WHERE user_id = $1")
        .bind(inactive.user_id)
        .execute(s.db.pool())
        .await
        .unwrap();
    assert_eq!(
        status(transfer(f.owner_a.jar(), no_bearer(), a, inactive.user_id).await),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        role_of(&s.db, f.owner_a.user_id, a).await.as_deref(),
        Some("OWNER")
    );
    assert_eq!(
        role_of(&s.db, f.admin_a.user_id, a).await.as_deref(),
        Some("ADMIN")
    );
    assert_eq!(
        role_of(&s.db, f.member_a.user_id, a).await.as_deref(),
        Some("MEMBER")
    );

    // OWNER → 同テナントの有効なメンバーへは移譲でき、実行者は ADMIN になる
    assert_eq!(
        status(transfer(f.owner_a.jar(), no_bearer(), a, f.member_a.user_id).await),
        StatusCode::OK
    );
    assert_eq!(
        role_of(&s.db, f.member_a.user_id, a).await.as_deref(),
        Some("OWNER")
    );
    assert_eq!(
        role_of(&s.db, f.owner_a.user_id, a).await.as_deref(),
        Some("ADMIN")
    );
    // 降格後はもう移譲できない
    assert_eq!(
        status(transfer(f.owner_a.jar(), no_bearer(), a, f.admin_a.user_id).await),
        StatusCode::FORBIDDEN
    );
    // 他テナントには影響しない
    assert_eq!(
        role_of(&s.db, f.owner_b.user_id, f.tenant_b)
            .await
            .as_deref(),
        Some("OWNER")
    );
}

// ─── MFA（本人のみ） ────────────────────────────────────────────

async fn mfa_rows(db: &PgStore, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM user_mfa WHERE user_id = $1")
        .bind(user)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
#[ignore]
async fn mfa_user_endpoints_are_self_only() {
    let f = setup().await;
    let s = &f.state;
    let victim = f.member_a.user_id;

    // 他人（同じテナントの OWNER でも）は userId を指定して操作できない
    for jar in [f.owner_a.jar(), f.admin_a.jar(), f.owner_b.jar()] {
        assert_eq!(
            status(mfa::totp_setup(State(s.clone()), jar.clone(), Path(victim)).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(
                mfa::totp_verify_setup(
                    State(s.clone()),
                    jar.clone(),
                    Path(victim),
                    Json(mfa::VerifyCode {
                        code: "000000".into()
                    }),
                )
                .await
            ),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(mfa::totp_disable(State(s.clone()), jar.clone(), Path(victim)).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(mfa::regenerate_recovery_codes(State(s.clone()), jar, Path(victim)).await),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(mfa_rows(&s.db, victim).await, 0);
    assert_eq!(
        RecoveryCodeStore::count_unused(&s.db, victim)
            .await
            .unwrap(),
        0
    );

    // 本人は設定を始められる
    let body =
        body_json(mfa::totp_setup(State(s.clone()), f.member_a.jar(), Path(victim)).await).await;
    assert!(body["secret"].as_str().is_some_and(|x| !x.is_empty()));
    assert_eq!(mfa_rows(&s.db, victim).await, 1);
    // 未ログインは 401
    assert_eq!(
        status(mfa::totp_setup(State(s.clone()), empty_jar(), Path(victim)).await),
        StatusCode::UNAUTHORIZED
    );
}

// ─── テナント横断の管理 API（システム管理者のみ） ─────────────────

#[tokio::test]
#[ignore]
async fn cross_tenant_admin_apis_require_system_admin() {
    let f = setup().await;
    let s = &f.state;
    // システム管理者はテナントのロールに依らない（ここでは tenant_a の MEMBER）
    let root = actor(&s.db, SYSTEM_ADMIN_EMAIL, f.tenant_a, "MEMBER").await;

    let tenants = |jar: CookieJar, headers: HeaderMap| {
        admin::admin_list_tenants(State(s.clone()), jar, headers, page())
    };
    let users = |jar: CookieJar, headers: HeaderMap| {
        admin::admin_list_users(State(s.clone()), jar, headers, page())
    };

    // テナントの OWNER / ADMIN では横断 API を使えない
    for x in [&f.owner_a, &f.admin_a, &f.owner_b, &f.member_a] {
        assert_eq!(
            status(tenants(x.jar(), no_bearer()).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(users(x.jar(), no_bearer()).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(extra::admin_list_sessions(State(s.clone()), x.jar(), page()).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(
                extra::admin_export_user(State(s.clone()), x.jar(), Path(f.owner_b.user_id)).await
            ),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(admin::outbox_flush(State(s.clone()), x.jar(), no_bearer()).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(signing_key::list_keys(State(s.clone()), x.jar()).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(
                admin::hard_delete_user(
                    State(s.clone()),
                    x.jar(),
                    no_bearer(),
                    Path(f.owner_b.user_id)
                )
                .await
            ),
            StatusCode::FORBIDDEN
        );
    }
    let owner_b = UserStore::find_by_id(&s.db, f.owner_b.user_id)
        .await
        .unwrap()
        .unwrap();
    assert!(owner_b.deleted_at.is_none());

    // Bearer は ADMIN / OWNER でも不可。システム管理者の cookie に Bearer を足しても不可。
    assert_eq!(
        status(tenants(empty_jar(), bearer(s, f.tenant_a, "OWNER")).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(tenants(root.jar(), bearer(s, f.tenant_a, "ADMIN")).await),
        StatusCode::FORBIDDEN
    );

    // システム管理者は全テナント・全ユーザーを見られる
    let body = body_json(tenants(root.jar(), no_bearer()).await).await;
    assert_eq!(body["total"], 2, "{body}");
    assert_eq!(status(users(root.jar(), no_bearer()).await), StatusCode::OK);
    assert_eq!(
        status(extra::admin_list_sessions(State(s.clone()), root.jar(), page()).await),
        StatusCode::OK
    );
    assert_eq!(
        status(signing_key::list_keys(State(s.clone()), root.jar()).await),
        StatusCode::OK
    );

    // SYSTEM_ADMIN_EMAILS 未設定なら誰も使えない（安全側）
    let mut unset = s.clone();
    unset.system_admins = Arc::new(crate::helpers::SystemAdmins::default());
    assert_eq!(
        status(admin::admin_list_tenants(State(unset), root.jar(), no_bearer(), page()).await),
        StatusCode::FORBIDDEN
    );

    // 無効化されたシステム管理者は使えない
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(root.user_id)
        .execute(s.db.pool())
        .await
        .unwrap();
    assert_eq!(
        status(tenants(root.jar(), no_bearer()).await),
        StatusCode::FORBIDDEN
    );
}

// ─── セッション失効（本人のみ） ─────────────────────────────────

#[tokio::test]
#[ignore]
async fn revoking_a_session_by_id_is_limited_to_own_sessions() {
    let f = setup().await;
    let s = &f.state;
    // 他人のセッションは見つからない扱い（400）で、失効もしない
    assert_eq!(
        status(
            extra::revoke_session_by_id(
                State(s.clone()),
                f.owner_a.jar(),
                Path(f.member_a.session_id.clone())
            )
            .await
        ),
        StatusCode::BAD_REQUEST
    );
    assert!(SessionStore::find(&s.db, &f.member_a.session_id)
        .await
        .unwrap()
        .is_some());
    // 自分のセッションは失効できる
    assert_eq!(
        status(
            extra::revoke_session_by_id(
                State(s.clone()),
                f.member_a.jar(),
                Path(f.member_a.session_id.clone())
            )
            .await
        ),
        StatusCode::OK
    );
    assert!(SessionStore::find(&s.db, &f.member_a.session_id)
        .await
        .unwrap()
        .is_none());
}

// ─── 一時アクセス（テナント単位） ───────────────────────────────

fn temporary_access(tenant: Uuid, role: &str) -> Json<extra::CreateTemporaryAccessReq> {
    Json(extra::CreateTemporaryAccessReq {
        tenant_id: tenant,
        subject: "guest@example.com".into(),
        role: role.into(),
        domains: vec!["app.example.com".into()],
        blocked_domains: vec![],
        starts_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
    })
}

#[tokio::test]
#[ignore]
async fn temporary_access_is_tenant_scoped() {
    let f = setup().await;
    let s = &f.state;
    let create = |x: &Actor, tid: Uuid, role: &str| {
        extra::create_temporary_access(
            State(s.clone()),
            x.jar(),
            no_bearer(),
            temporary_access(tid, role),
        )
    };

    // 他テナント向け・MEMBER による発行は 403
    assert_eq!(
        status(create(&f.admin_a, f.tenant_b, "MEMBER").await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(create(&f.member_a, f.tenant_a, "MEMBER").await),
        StatusCode::FORBIDDEN
    );
    // 自テナントの ADMIN は発行できる
    let body = body_json(create(&f.admin_a, f.tenant_a, "MEMBER").await).await;
    let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    // 一覧・失効も対象テナントの ADMIN 以上だけ
    let list = |x: &Actor, tid: Uuid| {
        extra::list_temporary_access(
            State(s.clone()),
            x.jar(),
            no_bearer(),
            Query(extra::TemporaryAccessListQuery { tenant_id: tid }),
        )
    };
    assert_eq!(
        status(list(&f.owner_b, f.tenant_a).await),
        StatusCode::FORBIDDEN
    );
    assert_eq!(status(list(&f.admin_a, f.tenant_a).await), StatusCode::OK);
    let revoke = |x: &Actor, id: Uuid| {
        extra::revoke_temporary_access(State(s.clone()), x.jar(), no_bearer(), Path(id))
    };
    assert_eq!(status(revoke(&f.owner_b, id).await), StatusCode::FORBIDDEN);
    assert_eq!(
        status(revoke(&f.admin_a, Uuid::new_v4()).await),
        StatusCode::FORBIDDEN
    );
    let grants = s.db.list_temporary_access_grants(f.tenant_a).await.unwrap();
    assert!(grants[0].revoked_at.is_none());
    assert_eq!(status(revoke(&f.admin_a, id).await), StatusCode::OK);
    let grants = s.db.list_temporary_access_grants(f.tenant_a).await.unwrap();
    assert!(grants[0].revoked_at.is_some());
}

// ─── M2M トークンの roles ────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn m2m_token_roles_drop_unknown_scopes() {
    let f = setup().await;
    let s = &f.state;
    // scopes の検証が入る前に保存された client を再現する
    let secret = "legacy-secret";
    M2mClientStore::create(
        &s.db,
        M2mClientRecord {
            id: Uuid::new_v4(),
            tenant_id: f.tenant_a,
            client_id: "m2m_legacy".into(),
            client_secret_hash: crate::handlers::mfa::sha256_hex_pub(secret),
            scopes: "admin,SUPERUSER, member".into(),
            is_active: true,
            created_at: Utc::now(),
        },
    )
    .await
    .unwrap();

    let body = body_json(
        manage::oauth_token(
            State(s.clone()),
            HeaderMap::new(),
            axum::extract::Form(manage::TokenReq {
                grant_type: "client_credentials".into(),
                client_id: "m2m_legacy".into(),
                client_secret: Some(secret.into()),
                device_code: None,
                code: None,
                redirect_uri: None,
                code_verifier: None,
                refresh_token: None,
                subject_token: None,
                subject_token_type: None,
                scope: None,
                audience: None,
            }),
        )
        .await,
    )
    .await;
    let claims = s
        .jwt_verifier
        .verify(body["access_token"].as_str().unwrap())
        .unwrap();
    assert_eq!(claims.roles.as_deref(), Some("ADMIN,MEMBER"));
    assert_eq!(
        claims.tenant_id.as_deref(),
        Some(f.tenant_a.to_string().as_str())
    );
}
