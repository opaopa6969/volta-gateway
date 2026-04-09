//! #8: Per-route response cache with LRU eviction.
//!
//! Cache entry lifecycle (tramli SM):
//!   FRESH → STALE (TTL expired) → EVICTED (LRU or manual purge)
//!
//! Only GET/HEAD responses are cached. Cache-Control: no-store is respected.

use bytes::Bytes;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-route cache configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
    #[serde(default = "default_cache_methods")]
    pub methods: Vec<String>,
    #[serde(default = "default_max_body")]
    pub max_body_size: usize,
    #[serde(default)]
    pub ignore_query: bool,
}

fn default_ttl() -> u64 { 300 }
fn default_cache_methods() -> Vec<String> { vec!["GET".into(), "HEAD".into()] }
fn default_max_body() -> usize { 10_485_760 } // 10MB

/// Cached response entry.
#[derive(Clone)]
struct CacheEntry {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
    created: Instant,
    ttl: Duration,
    /// tramli-inspired state: Fresh → Stale → Evicted
    state: CacheEntryState,
}

#[derive(Clone, Debug, PartialEq)]
enum CacheEntryState {
    Fresh,
    Stale,
}

impl CacheEntry {
    fn is_fresh(&self) -> bool {
        self.state == CacheEntryState::Fresh && self.created.elapsed() < self.ttl
    }

    fn transition_if_stale(&mut self) {
        if self.state == CacheEntryState::Fresh && self.created.elapsed() >= self.ttl {
            self.state = CacheEntryState::Stale;
        }
    }
}

/// LRU response cache. Thread-safe.
#[derive(Clone)]
pub struct ResponseCache {
    entries: Arc<Mutex<HashMap<String, CacheEntry>>>,
    max_entries: usize,
}

impl ResponseCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            max_entries,
        }
    }

    /// Build cache key from request.
    pub fn key(method: &str, host: &str, path: &str, query: Option<&str>, ignore_query: bool) -> String {
        if ignore_query {
            format!("{}:{}:{}", method, host, path)
        } else {
            format!("{}:{}:{}:{}", method, host, path, query.unwrap_or(""))
        }
    }

    /// Lookup cache entry. Returns (status, headers, body, hit) or None.
    pub fn get(&self, key: &str) -> Option<(u16, Vec<(String, String)>, Bytes)> {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get_mut(key) {
            entry.transition_if_stale();
            if entry.is_fresh() {
                return Some((entry.status, entry.headers.clone(), entry.body.clone()));
            }
            // Stale — remove
            entries.remove(key);
        }
        None
    }

    /// Store a response in cache.
    pub fn put(&self, key: String, status: u16, headers: Vec<(String, String)>, body: Bytes, ttl: Duration) {
        let mut entries = self.entries.lock().unwrap();

        // LRU eviction: remove oldest stale entries if at capacity
        if entries.len() >= self.max_entries {
            // Find and remove stale entries first
            let stale_keys: Vec<String> = entries.iter_mut()
                .filter_map(|(k, v)| {
                    v.transition_if_stale();
                    if v.state == CacheEntryState::Stale { Some(k.clone()) } else { None }
                })
                .collect();
            for k in stale_keys {
                entries.remove(&k);
            }

            // If still at capacity, remove oldest entry
            if entries.len() >= self.max_entries {
                if let Some(oldest_key) = entries.iter()
                    .min_by_key(|(_, v)| v.created)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&oldest_key);
                }
            }
        }

        entries.insert(key, CacheEntry {
            status,
            headers,
            body,
            created: Instant::now(),
            ttl,
            state: CacheEntryState::Fresh,
        });
    }

    /// Get cache stats.
    pub fn stats(&self) -> (usize, usize) {
        let entries = self.entries.lock().unwrap();
        let total = entries.len();
        let fresh = entries.values().filter(|e| e.is_fresh()).count();
        (total, fresh)
    }
}

/// Check if response should be cached based on Cache-Control header.
pub fn is_cacheable(cache_control: Option<&str>) -> bool {
    match cache_control {
        Some(cc) => !cc.contains("no-store") && !cc.contains("private"),
        None => true,
    }
}
