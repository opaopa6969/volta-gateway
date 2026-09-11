//! Rust auth-server に同梱する管理コンソール。
//!
//! 別プロセス・別リポジトリの静的配信を復活させず、HTML/CSS/JS をバイナリへ
//! 埋め込む。画面のデータ操作は既存の `/api/v1/*` を利用する。

use axum::extract::{OriginalUri, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;

use crate::error::no_cache_headers;
use crate::helpers::require_admin;
use crate::state::AppState;

const ADMIN_HTML: &str = include_str!("../admin_ui.html");
const PAGES: &[&str] = &[
    "users",
    "tenants",
    "members",
    "invitations",
    "sessions",
    "webhooks",
    "idp",
    "audit",
    "keys",
    "temporary-access",
];

pub async fn root() -> Redirect {
    Redirect::permanent("/admin/")
}

pub async fn page(
    State(state): State<AppState>,
    jar: CookieJar,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let path = uri.path();
    if path != "/admin/" && !known_page(path) {
        return StatusCode::NOT_FOUND.into_response();
    }

    match require_admin(&state, &jar).await {
        Ok(_) => {
            let mut response = Html(ADMIN_HTML).into_response();
            no_cache_headers(&mut response);
            response.headers_mut().insert(
                "content-security-policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'; form-action 'self'"
                    .parse()
                    .expect("static CSP is valid"),
            );
            response.headers_mut().insert(
                "x-content-type-options",
                "nosniff".parse().expect("static header is valid"),
            );
            response
        }
        Err(error) if error.status == StatusCode::UNAUTHORIZED => {
            let return_to = urlencoding::encode(path);
            Redirect::temporary(&format!("/login?return_to={return_to}")).into_response()
        }
        Err(error) => error.into_response(),
    }
}

fn known_page(path: &str) -> bool {
    path.strip_prefix("/admin/")
        .is_some_and(|page| PAGES.contains(&page))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_single_segment_pages_are_accepted() {
        assert!(known_page("/admin/users"));
        assert!(known_page("/admin/temporary-access"));
        assert!(!known_page("/admin/unknown"));
        assert!(!known_page("/admin/users/delete"));
    }

    #[test]
    fn embedded_console_has_user_creation_and_safe_dom_rendering() {
        assert!(ADMIN_HTML.contains("ユーザーを追加"));
        assert!(ADMIN_HTML.contains("/api/v1/admin/users"));
        for page in PAGES {
            assert!(ADMIN_HTML.contains(&format!("href=\"/admin/{page}\"")));
        }
        assert!(ADMIN_HTML.contains("textContent"));
        assert!(!ADMIN_HTML.contains("document.write"));
        assert!(ADMIN_HTML.contains("skipRender:true"));
    }
}
