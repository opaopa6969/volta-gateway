//! Pagination helpers for admin list endpoints (P2.1, Java `f31a2f2`).
//!
//! Mirrors the Java `Pagination` pair: `PageRequest` / `PageResponse`. Every
//! paginated admin endpoint returns `{items, total, page, size, pages}`.

use serde::{Deserialize, Serialize};

const DEFAULT_SIZE: u32 = 50;
const MAX_SIZE: u32 = 500;

/// Query-string parameters for admin list endpoints.
///
/// All fields are optional; defaults match the Java implementation
/// (`page=1`, `size=50`).
#[derive(Debug, Deserialize)]
pub struct PageRequest {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_size")]
    pub size: u32,
    pub sort: Option<String>,
    pub q: Option<String>,
    pub user_id: Option<String>,
    pub status: Option<String>,
    pub event: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            page: 1,
            size: DEFAULT_SIZE,
            sort: None,
            q: None,
            user_id: None,
            status: None,
            event: None,
            from: None,
            to: None,
        }
    }
}

fn default_page() -> u32 { 1 }
fn default_size() -> u32 { DEFAULT_SIZE }

impl PageRequest {
    /// Clamp page/size to sane bounds. Always returns a struct that's safe to
    /// pass into SQL.
    pub fn normalized(self) -> Self {
        let page = self.page.max(1);
        let size = self.size.clamp(1, MAX_SIZE);
        Self { page, size, ..self }
    }

    pub fn offset(&self) -> i64 {
        ((self.page.saturating_sub(1)) as i64) * (self.size as i64)
    }

    pub fn limit(&self) -> i64 { self.size as i64 }

    /// Sanitize the `sort` parameter against a whitelist of column names.
    /// Returns a raw SQL fragment (`"col ASC"` / `"col DESC"`) or the provided
    /// fallback when the input is missing or not whitelisted.
    ///
    /// `raw` format: `"col"` → ASC, `"-col"` → DESC, case-insensitive.
    pub fn order_sql(raw: Option<&str>, allowed: &[&str], fallback: &str) -> String {
        let (col_raw, dir) = match raw {
            Some(s) if !s.is_empty() => {
                if let Some(rest) = s.strip_prefix('-') {
                    (rest, "DESC")
                } else {
                    (s, "ASC")
                }
            }
            _ => return fallback.to_string(),
        };
        let col = col_raw.trim().to_ascii_lowercase();
        if allowed.iter().any(|a| a.eq_ignore_ascii_case(&col)) {
            format!("{} {}", col, dir)
        } else {
            fallback.to_string()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PageResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub size: u32,
    pub pages: u32,
}

impl<T: Serialize> PageResponse<T> {
    pub fn new(items: Vec<T>, total: i64, req: &PageRequest) -> Self {
        let pages = if req.size == 0 {
            0
        } else {
            let t = total.max(0) as u64;
            (t.div_ceil(req.size as u64)) as u32
        };
        Self { items, total, page: req.page, size: req.size, pages }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_for_first_page_is_zero() {
        let r = PageRequest { page: 1, size: 50, ..Default::default() }.normalized();
        assert_eq!(r.offset(), 0);
    }

    #[test]
    fn offset_for_later_pages() {
        let r = PageRequest { page: 3, size: 20, ..Default::default() }.normalized();
        assert_eq!(r.offset(), 40);
    }

    #[test]
    fn size_is_clamped() {
        let r = PageRequest { page: 1, size: 99999, ..Default::default() }.normalized();
        assert_eq!(r.size, MAX_SIZE);
    }

    #[test]
    fn pages_rounds_up() {
        let r = PageRequest { page: 1, size: 10, ..Default::default() }.normalized();
        let resp = PageResponse::new(Vec::<u32>::new(), 25, &r);
        assert_eq!(resp.pages, 3);
    }

    #[test]
    fn pages_zero_when_no_results() {
        let r = PageRequest { page: 1, size: 10, ..Default::default() }.normalized();
        let resp = PageResponse::new(Vec::<u32>::new(), 0, &r);
        assert_eq!(resp.pages, 0);
    }

    #[test]
    fn order_sql_whitelists_column() {
        let sql = PageRequest::order_sql(Some("created_at"), &["created_at", "email"], "created_at DESC");
        assert_eq!(sql, "created_at ASC");
    }

    #[test]
    fn order_sql_accepts_desc_prefix() {
        let sql = PageRequest::order_sql(Some("-email"), &["email"], "fallback");
        assert_eq!(sql, "email DESC");
    }

    #[test]
    fn order_sql_rejects_non_whitelisted() {
        let sql = PageRequest::order_sql(Some("password"), &["email"], "email ASC");
        assert_eq!(sql, "email ASC");
    }

    #[test]
    fn order_sql_falls_back_when_missing() {
        let sql = PageRequest::order_sql(None, &["email"], "email DESC");
        assert_eq!(sql, "email DESC");
    }
}
