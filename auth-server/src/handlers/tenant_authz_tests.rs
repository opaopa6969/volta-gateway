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
use crate::handlers::{admin, manage, webhook};
use crate::pagination::PageRequest;
use crate::state::AppState;
use volta_auth_core::record::*;
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::*;

const JWT_SECRET: &[u8] = b"tenant-authz-test-secret-0123456789abcdef";

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
