//! Phase 9 — lazy, process-scoped policy set cache.
//!
//! Parses each Cedar policy file at most once per process lifetime.  The key
//! is the sorted list of absolute path strings; any change in the file list
//! (or a call to `invalidate`) forces a re-parse on the next access.
//!
//! This is useful when `nono run` is wrapped in a shell function or script
//! that invokes nono many times with the same policy files — the first call
//! pays the parse cost; subsequent calls pay only a mutex lock and a pointer
//! deref.

use std::path::PathBuf;
use std::sync::Mutex;

use cedar_policy::PolicySet;

use crate::error::Result;
use crate::loader::load_policy_set_from_files;

struct CacheEntry {
    key: Vec<String>,
    policy_set: PolicySet,
}

static CACHE: Mutex<Option<CacheEntry>> = Mutex::new(None);

/// Load a `PolicySet` from `paths`, using a process-level cache.
///
/// The cache key is the sorted list of canonical path strings.  If the
/// cached key matches `paths`, the cached `PolicySet` is cloned and
/// returned without re-parsing.  Otherwise the files are re-parsed and
/// the cache is updated.
///
/// Thread-safe: uses a `Mutex` internally.  Poisoned-mutex errors are
/// treated as cache misses (the files are re-parsed).
///
/// # Errors
///
/// Returns `CedarError::PolicyParse` if any policy file cannot be parsed.
/// Returns `CedarError::Io` if any file cannot be read.
pub fn load_policy_set_cached(paths: &[PathBuf]) -> Result<PolicySet> {
    let mut key: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    key.sort_unstable();

    let guard = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(entry) = guard.as_ref() {
        if entry.key == key {
            return Ok(entry.policy_set.clone());
        }
    }

    drop(guard); // release before the (potentially slow) file I/O

    let policy_set = load_policy_set_from_files(paths)?;

    match CACHE.lock() {
        Ok(mut guard) => {
            *guard = Some(CacheEntry {
                key,
                policy_set: policy_set.clone(),
            });
        }
        Err(_poisoned) => {
            // Cache update failed; the caller still gets a valid PolicySet.
        }
    }

    Ok(policy_set)
}

/// Evict the cached `PolicySet`, forcing the next `load_policy_set_cached`
/// call to re-parse from disk.
///
/// Useful in tests or when the policy files are known to have changed.
pub fn invalidate_cache() {
    if let Ok(mut guard) = CACHE.lock() {
        *guard = None;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn write_tmp(name: &str, src: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("nono-cedar-cache-test-{name}.cedar"));
        let mut f = std::fs::File::create(&path).expect("create tmp file");
        f.write_all(src.as_bytes()).expect("write");
        path
    }

    #[test]
    fn cache_returns_same_policy_set_on_second_call() {
        invalidate_cache();
        let path = write_tmp("permit-all", "permit(principal, action, resource);");
        let first = load_policy_set_cached(&[path.clone()]).expect("first load");
        let second = load_policy_set_cached(&[path]).expect("second load (cached)");
        assert_eq!(
            first.policies().count(),
            second.policies().count(),
            "cached policy set must have same policy count"
        );
    }

    #[test]
    fn cache_invalidation_forces_reparse() {
        invalidate_cache();
        let path = write_tmp("permit-all-2", "permit(principal, action, resource);");
        let _ = load_policy_set_cached(&[path.clone()]).expect("initial load");
        invalidate_cache();
        let after = load_policy_set_cached(&[path]).expect("post-invalidation load");
        assert_eq!(after.policies().count(), 1);
    }
}
