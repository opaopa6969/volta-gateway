//! Multi-account session + account chooser (Phase 2, docs/auth-methods-landscape.md §5).
//!
//! Google-style "signed in on this browser" experience. The active identity is
//! still `__volta_session`; `__volta_accounts` remembers every session id signed
//! in here. Accounts accumulate without touching the 8 login-completion sites:
//!   - `GET /login?add=1` stashes the current active session before the new login
//!     overwrites `__volta_session` (see oidc::login).
//!   - `GET /accounts` reconciles the *current* active session into the list and
//!     prunes any revoked/expired entries.
//!
//! Endpoints:
//!   GET  /accounts          → chooser page
//!   POST /accounts/use       → switch active account
//!   POST /accounts/signout   → sign out one account
//!   POST /accounts/signout-all → sign out every account on this browser

use axum::extract::{Form, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{
    clear_session_cookie, extract_session_id, read_accounts, set_accounts_cookie,
    set_session_cookie,
};
use crate::state::AppState;
use volta_auth_core::record::SessionRecord;
use volta_auth_core::store::SessionStore;

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Resolve every remembered account to a valid session record, in cookie order
/// with the active session ensured present. Invalid/expired ids are dropped.
async fn resolve_accounts(
    s: &AppState,
    jar: &axum_extra::extract::CookieJar,
) -> (Vec<SessionRecord>, Option<String>) {
    let active = extract_session_id(jar);
    let mut ids = read_accounts(jar);
    if let Some(a) = &active {
        if !ids.contains(a) {
            ids.insert(0, a.clone());
        }
    }
    let now = now_epoch();
    let mut valid = Vec::new();
    for id in ids {
        if let Ok(Some(rec)) = SessionStore::find(&s.db, &id).await {
            if rec.is_valid_at(now) {
                valid.push(rec);
            }
        }
    }
    (valid, active)
}

// ─── GET /accounts ─────────────────────────────────────────

pub async fn accounts_page(
    State(s): State<AppState>,
    jar: axum_extra::extract::CookieJar,
) -> Response {
    let (valid, active) = resolve_accounts(&s, &jar).await;
    if valid.is_empty() {
        let mut resp = Redirect::to(&format!("{}/login", s.base_url)).into_response();
        no_cache_headers(&mut resp);
        return resp;
    }

    let cards: String = valid.iter().map(|r| {
        let is_active = Some(&r.session_id) == active.as_ref();
        let name = r.display_name.clone().or_else(|| r.email.clone()).unwrap_or_else(|| "(no name)".into());
        let email = r.email.clone().unwrap_or_default();
        let tenant = r.tenant_slug.clone().unwrap_or_else(|| r.tenant_id.clone());
        let initial = name.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default();
        let badge = if is_active { "<span class=\"active\">使用中</span>" } else { "" };
        let use_btn = if is_active {
            String::new()
        } else {
            format!("<form method=\"post\" action=\"/accounts/use\"><input type=\"hidden\" name=\"session_id\" value=\"{}\"><button class=\"use\">このアカウントを使う</button></form>", html_escape(&r.session_id))
        };
        format!(
            "<div class=\"acct{}\">\
               <div class=\"avatar\">{}</div>\
               <div class=\"info\"><div class=\"name\">{} {}</div><div class=\"sub\">{}</div><div class=\"sub tenant\">{}</div></div>\
               <div class=\"actions\">{}\
                 <form method=\"post\" action=\"/accounts/signout\"><input type=\"hidden\" name=\"session_id\" value=\"{}\"><button class=\"signout\">サインアウト</button></form>\
               </div>\
             </div>",
            if is_active { " current" } else { "" },
            html_escape(&initial), html_escape(&name), badge,
            html_escape(&email), html_escape(&tenant),
            use_btn, html_escape(&r.session_id),
        )
    }).collect();

    let html = ACCOUNTS_PAGE_HTML.replace("__CARDS__", &cards);
    let ids: Vec<String> = valid.iter().map(|r| r.session_id.clone()).collect();
    let mut resp = Html(html).into_response();
    set_accounts_cookie(&mut resp, &ids, &s); // prune to the valid set
    no_cache_headers(&mut resp);
    resp
}

// ─── POST /accounts/use ────────────────────────────────────

#[derive(Deserialize)]
pub struct AccountRef {
    pub session_id: String,
}

pub async fn use_account(
    State(s): State<AppState>,
    jar: axum_extra::extract::CookieJar,
    Form(b): Form<AccountRef>,
) -> Result<Response, ApiError> {
    // The requested account must be one this browser remembers, and still valid.
    let mut ids = read_accounts(&jar);
    if let Some(a) = extract_session_id(&jar) {
        if !ids.contains(&a) {
            ids.push(a);
        }
    }
    if !ids.contains(&b.session_id) {
        return Err(ApiError::forbidden(
            "UNKNOWN_ACCOUNT",
            "このアカウントはこのブラウザに登録されていません",
        ));
    }
    let valid = SessionStore::find(&s.db, &b.session_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .filter(|r| r.is_valid_at(now_epoch()));
    if valid.is_none() {
        return Err(ApiError::bad_request(
            "SESSION_INVALID",
            "このアカウントのセッションは無効です。再ログインしてください。",
        ));
    }
    let mut resp = Redirect::to(&format!("{}/", s.base_url)).into_response();
    set_session_cookie(&mut resp, &b.session_id, &s);
    no_cache_headers(&mut resp);
    Ok(resp)
}

// ─── POST /accounts/signout ────────────────────────────────

pub async fn signout_account(
    State(s): State<AppState>,
    jar: axum_extra::extract::CookieJar,
    Form(b): Form<AccountRef>,
) -> Result<Response, ApiError> {
    let active = extract_session_id(&jar);
    // Revoke the chosen session server-side (idempotent if already gone).
    let _ = SessionStore::revoke(&s.db, &b.session_id).await;

    // Remaining remembered ids, minus the one we signed out, keeping only valid.
    let now = now_epoch();
    let mut remaining = Vec::new();
    for id in read_accounts(&jar) {
        if id == b.session_id {
            continue;
        }
        if let Ok(Some(r)) = SessionStore::find(&s.db, &id).await {
            if r.is_valid_at(now) {
                remaining.push(id);
            }
        }
    }

    let signed_out_active = active.as_deref() == Some(b.session_id.as_str());
    let mut resp = if remaining.is_empty() {
        Redirect::to(&format!("{}/login", s.base_url)).into_response()
    } else {
        Redirect::to(&format!("{}/accounts", s.base_url)).into_response()
    };
    set_accounts_cookie(&mut resp, &remaining, &s);
    if signed_out_active {
        // Promote another remembered account to active, or clear if none.
        match remaining.first() {
            Some(next) => set_session_cookie(&mut resp, next, &s),
            None => clear_session_cookie(&mut resp, &s),
        }
    }
    no_cache_headers(&mut resp);
    Ok(resp)
}

// ─── POST /accounts/signout-all ────────────────────────────

pub async fn signout_all(
    State(s): State<AppState>,
    jar: axum_extra::extract::CookieJar,
) -> Response {
    let mut ids = read_accounts(&jar);
    if let Some(a) = extract_session_id(&jar) {
        if !ids.contains(&a) {
            ids.push(a);
        }
    }
    for id in &ids {
        let _ = SessionStore::revoke(&s.db, id).await;
    }
    let mut resp = Redirect::to(&format!("{}/login", s.base_url)).into_response();
    clear_session_cookie(&mut resp, &s);
    set_accounts_cookie(&mut resp, &[], &s);
    no_cache_headers(&mut resp);
    resp
}

const ACCOUNTS_PAGE_HTML: &str = r##"<!DOCTYPE html><html lang="ja"><head>
<meta charset="utf-8"><title>アカウントの選択 — volta</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f5;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);max-width:440px;width:100%;overflow:hidden}
h1{font-size:18px;margin:0;padding:24px 24px 8px}
.hint{color:#666;font-size:13px;padding:0 24px 16px;margin:0}
.acct{display:flex;align-items:center;gap:12px;padding:14px 24px;border-top:1px solid #eee}
.acct.current{background:#f0f4ff}
.avatar{width:40px;height:40px;border-radius:50%;background:#0f3460;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:600;flex:0 0 auto}
.info{flex:1;min-width:0}
.name{font-size:15px;font-weight:600}
.sub{font-size:12px;color:#666;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tenant{color:#0f3460}
.active{font-size:11px;background:#2e7d32;color:#fff;border-radius:10px;padding:1px 8px;margin-left:6px;vertical-align:middle}
.actions{display:flex;flex-direction:column;gap:6px;align-items:flex-end}
button{border:0;border-radius:6px;padding:7px 12px;font-size:13px;cursor:pointer;white-space:nowrap}
.use{background:#0f3460;color:#fff}.use:hover{background:#16213e}
.signout{background:#eee;color:#555}.signout:hover{background:#e0e0e0}
.foot{padding:16px 24px;border-top:1px solid #eee;display:flex;justify-content:space-between;align-items:center}
.add{color:#0f3460;text-decoration:none;font-size:14px;font-weight:600}
.allout{background:none;color:#c62828;padding:7px 0}
</style></head><body>
<div class="card">
  <h1>アカウントの選択</h1>
  <p class="hint">このブラウザにサインイン中のアカウントです。</p>
  __CARDS__
  <div class="foot">
    <a class="add" href="/login?add=1">＋ 別のアカウントを追加</a>
    <form method="post" action="/accounts/signout-all"><button class="signout allout">すべてサインアウト</button></form>
  </div>
</div>
</body></html>"##;
