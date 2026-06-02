//! API-driven config persistence via a JSON merge-patch overlay.
//!
//! The hand-written YAML stays the authoritative *base*; changes made through
//! the admin API (`PATCH /admin/config`) are accumulated in a separate overlay
//! file as an RFC 7386 JSON Merge Patch and re-applied on top of the base at
//! load time, so they survive restarts. The base YAML is never rewritten.
//!
//! Effective config = `deep_merge(base, overlay)` → [`GatewayConfig`].
//!
//! Hot-applicable fields (`routing`, `error_pages_dir`, `server.trusted_proxies`)
//! take effect immediately by rebuilding [`HotState`] and swapping it into the
//! shared `ArcSwap`. All other fields are persisted but need a restart to take
//! effect; [`apply_patch`](ConfigStore::apply_patch) reports which is which.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use serde_json::Value;

use crate::config::GatewayConfig;
use crate::proxy::HotState;

/// Outcome of applying a patch: which changed keys took effect live vs.
/// which were saved but need a restart.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ApplyResult {
    pub hot_applied: Vec<String>,
    pub requires_restart: Vec<String>,
}

/// Base config + overlay, guarded together by a single lock so all operations
/// observe a consistent (base, overlay) pair.
struct Inner {
    /// Base config parsed from the hand-written YAML, as a JSON value.
    base: Value,
    /// Accumulated API-driven patch (RFC 7386 merge patch).
    overlay: Value,
}

/// Owns the base config (from YAML) plus the mutable overlay (from the admin
/// API), and persists the overlay to disk on every change.
pub struct ConfigStore {
    inner: Mutex<Inner>,
    /// The hand-written YAML, re-read on [`reload`](Self::reload).
    base_path: PathBuf,
    /// Where the overlay is persisted.
    overlay_path: PathBuf,
}

impl ConfigStore {
    /// Load base YAML + overlay file and return the store plus the effective
    /// (merged) config. A missing/empty overlay file is treated as `{}`.
    pub fn load(base_yaml_path: &Path, overlay_path: PathBuf) -> Result<(Self, GatewayConfig), String> {
        let base = read_base(base_yaml_path)?;
        let overlay: Value = match std::fs::read_to_string(&overlay_path) {
            Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s)
                .map_err(|e| format!("parse overlay {}: {}", overlay_path.display(), e))?,
            _ => Value::Object(Default::default()),
        };

        let effective = build_effective(&base, &overlay)?;
        let store = Self {
            inner: Mutex::new(Inner { base, overlay }),
            base_path: base_yaml_path.to_path_buf(),
            overlay_path,
        };
        Ok((store, effective))
    }

    /// Current effective config (base ⊕ current overlay).
    pub fn effective_config(&self) -> Result<GatewayConfig, String> {
        let inner = self.inner.lock().unwrap();
        build_effective(&inner.base, &inner.overlay)
    }

    /// Apply a JSON merge patch: merge → build → validate → persist → commit.
    /// On any failure the in-memory overlay and the file are left untouched.
    /// Returns the new effective config and the hot/restart classification.
    pub fn apply_patch(&self, patch: Value) -> Result<(GatewayConfig, ApplyResult), Vec<String>> {
        let mut inner = self.inner.lock().unwrap();

        let mut candidate = inner.overlay.clone();
        deep_merge(&mut candidate, &patch);

        let effective = build_effective(&inner.base, &candidate).map_err(|e| vec![e])?;
        effective.validate()?;

        // Persist before committing in-memory so a write failure can't leave
        // memory ahead of disk.
        self.persist(&candidate).map_err(|e| vec![e])?;
        inner.overlay = candidate;

        Ok((effective, classify_patch(&patch)))
    }

    /// Drop all API-driven changes and revert to the hand-written base.
    pub fn clear_overlay(&self) -> Result<GatewayConfig, Vec<String>> {
        let mut inner = self.inner.lock().unwrap();
        let empty = Value::Object(Default::default());
        let effective = build_effective(&inner.base, &empty).map_err(|e| vec![e])?;
        effective.validate()?;
        self.persist(&empty).map_err(|e| vec![e])?;
        inner.overlay = empty;
        Ok(effective)
    }

    /// Re-read the base YAML from disk (picking up external edits) and rebuild
    /// the effective config with the current overlay still applied on top.
    pub fn reload(&self) -> Result<GatewayConfig, Vec<String>> {
        let mut inner = self.inner.lock().unwrap();
        let base = read_base(&self.base_path).map_err(|e| vec![e])?;
        let effective = build_effective(&base, &inner.overlay).map_err(|e| vec![e])?;
        effective.validate()?;
        inner.base = base;
        Ok(effective)
    }

    /// Atomically write the overlay: write to a temp file, fsync, then rename.
    fn persist(&self, overlay: &Value) -> Result<(), String> {
        use std::io::Write;
        let body = serde_json::to_string_pretty(overlay)
            .map_err(|e| format!("serialize overlay: {}", e))?;
        let tmp = self.overlay_path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| format!("create overlay tmp {}: {}", tmp.display(), e))?;
            f.write_all(body.as_bytes())
                .map_err(|e| format!("write overlay tmp: {}", e))?;
            f.sync_all().map_err(|e| format!("fsync overlay tmp: {}", e))?;
        }
        std::fs::rename(&tmp, &self.overlay_path)
            .map_err(|e| format!("rename overlay into place: {}", e))
    }
}

/// Read and parse the base YAML config into a JSON value.
fn read_base(path: &Path) -> Result<Value, String> {
    let yaml = std::fs::read_to_string(path)
        .map_err(|e| format!("read base config {}: {}", path.display(), e))?;
    serde_yaml::from_str(&yaml).map_err(|e| format!("parse base config: {}", e))
}

/// Build the effective `GatewayConfig` from base ⊕ overlay (no validation).
fn build_effective(base: &Value, overlay: &Value) -> Result<GatewayConfig, String> {
    let mut merged = base.clone();
    deep_merge(&mut merged, overlay);
    serde_json::from_value(merged).map_err(|e| format!("merged config invalid: {}", e))
}

/// RFC 7386 (JSON Merge Patch) deep merge: objects merge recursively, a `null`
/// value deletes the key, anything else replaces.
pub fn deep_merge(base: &mut Value, patch: &Value) {
    match patch {
        Value::Object(patch_map) => {
            if !base.is_object() {
                *base = Value::Object(Default::default());
            }
            let base_map = base.as_object_mut().unwrap();
            for (k, v) in patch_map {
                if v.is_null() {
                    base_map.remove(k);
                } else {
                    deep_merge(base_map.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
        }
        _ => *base = patch.clone(),
    }
}

/// Classify the top-level keys of a patch into hot-applicable vs restart-only.
fn classify_patch(patch: &Value) -> ApplyResult {
    let mut result = ApplyResult::default();
    if let Value::Object(map) = patch {
        for (k, v) in map {
            match k.as_str() {
                "routing" | "error_pages_dir" => result.hot_applied.push(k.clone()),
                // Within `server`, only trusted_proxies is picked up by a HotState
                // rebuild; port/timeouts/force_https bind at startup.
                "server" => {
                    let only_trusted = v.as_object()
                        .map(|m| !m.is_empty() && m.keys().all(|sk| sk == "trusted_proxies"))
                        .unwrap_or(false);
                    if only_trusted {
                        result.hot_applied.push("server.trusted_proxies".into());
                    } else {
                        result.requires_restart.push(k.clone());
                    }
                }
                _ => result.requires_restart.push(k.clone()),
            }
        }
    }
    result
}

/// Rebuild [`HotState`] from the effective config and atomically swap it in.
/// Mirrors the startup path in `main.rs` and the `/admin/reload` handler.
pub fn rebuild_hot(cfg: &GatewayConfig, hot: &Arc<ArcSwap<HotState>>) {
    let routing = Arc::new(cfg.routing_table());
    let allowlists = cfg.ip_allowlist_table();
    let cors = cfg.cors_table();
    let trusted_proxies: Vec<ipnet::IpNet> = cfg.server.trusted_proxies.iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    hot.store(Arc::new(HotState::new_full(
        routing,
        allowlists,
        cfg.error_pages_dir.as_deref(),
        cors,
        trusted_proxies,
    )));
}

/// Default overlay path next to the base config: `<stem>.overlay.json`.
pub fn default_overlay_path(base_yaml_path: &str) -> PathBuf {
    let p = Path::new(base_yaml_path);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("config");
    p.parent().unwrap_or_else(|| Path::new(".")).join(format!("{}.overlay.json", stem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Unique temp paths without pulling in a tempfile dep / Date / rng.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    fn tmp_dir() -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("volta_overlay_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const BASE_YAML: &str = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://127.0.0.1:3000"
"#;

    fn store_in(dir: &Path) -> ConfigStore {
        let base = dir.join("gw.yaml");
        std::fs::write(&base, BASE_YAML).unwrap();
        let (store, _) = ConfigStore::load(&base, dir.join("gw.overlay.json")).unwrap();
        store
    }

    // ── deep_merge ───────────────────────────────────────────────

    #[test]
    fn deep_merge_adds_and_overwrites_keys() {
        let mut base = serde_json::json!({"a": 1, "nested": {"x": 1, "y": 2}});
        let patch = serde_json::json!({"b": 2, "nested": {"y": 9, "z": 3}});
        deep_merge(&mut base, &patch);
        assert_eq!(base, serde_json::json!({"a": 1, "b": 2, "nested": {"x": 1, "y": 9, "z": 3}}));
    }

    #[test]
    fn deep_merge_null_deletes_key() {
        let mut base = serde_json::json!({"a": 1, "b": 2});
        deep_merge(&mut base, &serde_json::json!({"b": null}));
        assert_eq!(base, serde_json::json!({"a": 1}));
    }

    #[test]
    fn deep_merge_replaces_non_objects() {
        let mut base = serde_json::json!({"list": [1, 2, 3]});
        deep_merge(&mut base, &serde_json::json!({"list": [9]}));
        assert_eq!(base, serde_json::json!({"list": [9]}));
    }

    // ── apply_patch + persistence round-trip ─────────────────────

    #[test]
    fn apply_patch_persists_and_reloads() {
        let dir = tmp_dir();
        let overlay_path = dir.join("gw.overlay.json");
        let base_path = dir.join("gw.yaml");
        std::fs::write(&base_path, BASE_YAML).unwrap();

        let (store, _) = ConfigStore::load(&base_path, overlay_path.clone()).unwrap();
        let patch = serde_json::json!({
            "routing": [
                {"host": "example.com", "backend": "http://127.0.0.1:3000"},
                {"host": "new.example.com", "backend": "http://127.0.0.1:9000"}
            ]
        });
        let (effective, _) = store.apply_patch(patch).unwrap();
        assert_eq!(effective.routing.len(), 2);

        // Overlay file was written.
        assert!(overlay_path.exists());

        // A fresh load applies the persisted overlay → change survives restart.
        let (_store2, reloaded) = ConfigStore::load(&base_path, overlay_path).unwrap();
        assert_eq!(reloaded.routing.len(), 2);
        assert!(reloaded.routing.iter().any(|r| r.host == "new.example.com"));
    }

    #[test]
    fn apply_patch_rejects_invalid_and_keeps_overlay_unchanged() {
        let dir = tmp_dir();
        let store = store_in(&dir);

        // Empty routing fails validate(). Overlay must roll back.
        let bad = store.apply_patch(serde_json::json!({"routing": []}));
        assert!(bad.is_err());

        // Effective config is still the original single route.
        let eff = store.effective_config().unwrap();
        assert_eq!(eff.routing.len(), 1);
        assert_eq!(eff.routing[0].host, "example.com");
    }

    #[test]
    fn clear_overlay_reverts_to_base() {
        let dir = tmp_dir();
        let store = store_in(&dir);
        store.apply_patch(serde_json::json!({
            "routing": [
                {"host": "example.com", "backend": "http://127.0.0.1:3000"},
                {"host": "extra.com", "backend": "http://127.0.0.1:4000"}
            ]
        })).unwrap();
        assert_eq!(store.effective_config().unwrap().routing.len(), 2);

        let reverted = store.clear_overlay().unwrap();
        assert_eq!(reverted.routing.len(), 1);
        assert_eq!(reverted.routing[0].host, "example.com");
    }

    // ── classify_patch ───────────────────────────────────────────

    #[test]
    fn classify_routing_is_hot() {
        let r = classify_patch(&serde_json::json!({"routing": []}));
        assert_eq!(r.hot_applied, vec!["routing".to_string()]);
        assert!(r.requires_restart.is_empty());
    }

    #[test]
    fn classify_server_port_requires_restart() {
        let r = classify_patch(&serde_json::json!({"server": {"port": 9090}}));
        assert_eq!(r.requires_restart, vec!["server".to_string()]);
        assert!(r.hot_applied.is_empty());
    }

    #[test]
    fn classify_server_trusted_proxies_only_is_hot() {
        let r = classify_patch(&serde_json::json!({"server": {"trusted_proxies": ["10.0.0.0/8"]}}));
        assert_eq!(r.hot_applied, vec!["server.trusted_proxies".to_string()]);
        assert!(r.requires_restart.is_empty());
    }

    #[test]
    fn classify_tls_requires_restart() {
        let r = classify_patch(&serde_json::json!({"tls": {"domains": ["x.com"]}}));
        assert_eq!(r.requires_restart, vec!["tls".to_string()]);
    }
}
