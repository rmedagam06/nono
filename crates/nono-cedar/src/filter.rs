//! Cedar capability filter: translates `CedarDecision` results into `CapabilitySet` mutations.
//!
//! After the engine evaluates every capability, the filter applies the decisions:
//! permitted caps are left alone, implicitly-denied caps are removed (or error in
//! `Strict` mode), and explicit-forbid caps always hard-error. `ReadWrite` pairs
//! (two decisions sharing one `cap_index`) are merged first via `merge_decisions`.

use std::collections::HashMap;

use nono::{AccessMode, CapabilitySet};

use crate::engine::{CedarDecision, DecisionOutcome};
use crate::error::{CedarError, Result};

// ── Public types ───────────────────────────────────────────────────────────

/// How the filter responds to implicitly-denied capabilities.
///
/// Explicit `forbid(...)` matches are always a hard error, regardless of mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// Remove implicitly-denied capabilities silently; explicit forbid still errors.
    Narrow,
    /// Treat any denial (implicit or explicit) as a hard error.
    Strict,
}

/// Information about a capability Cedar denied or downgraded.
#[derive(Debug, Clone)]
pub struct DeniedCapInfo {
    /// Flat combined index matching `CedarDecision::cap_index`.
    pub cap_index: usize,
    /// True when an explicit `forbid(...)` policy fired.
    pub is_explicit_forbid: bool,
    /// Human-readable explanation from the engine.
    pub user_message: String,
}

/// Summary returned by `CedarCapabilityFilter::apply` on success.
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// Capabilities removed from the set.
    pub removed_count: usize,
    /// ReadWrite capabilities downgraded to a narrower mode.
    pub downgraded_count: usize,
    /// All denials encountered (including silent ones in Narrow mode).
    pub denied: Vec<DeniedCapInfo>,
}

// ── Internal merge helper ──────────────────────────────────────────────────

#[derive(Debug)]
enum MergeOutcome {
    KeepReadWrite,
    DowngradeToRead,
    DowngradeToWrite,
    Remove,
    HardDeny(String),
}

/// Merge the read and write Cedar decisions for a single `ReadWrite` capability.
///
/// Precedence (highest first):
/// 1. Any explicit forbid on either half → `HardDeny`.
/// 2. Both permit → `KeepReadWrite`.
/// 3. Read permit, write implicit-deny → `DowngradeToRead`.
/// 4. Read implicit-deny, write permit → `DowngradeToWrite`
///    (logs a warning; likely a policy authoring error).
/// 5. Both implicit-deny → `Remove`.
pub fn merge_decisions(read: &CedarDecision, write: &CedarDecision) -> MergeOutcome {
    let read_explicit = matches!(
        read.outcome,
        DecisionOutcome::Deny {
            is_explicit_forbid: true
        }
    );
    let write_explicit = matches!(
        write.outcome,
        DecisionOutcome::Deny {
            is_explicit_forbid: true
        }
    );

    if read_explicit || write_explicit {
        let msg = if read_explicit {
            read.user_message.clone()
        } else {
            write.user_message.clone()
        };
        return MergeOutcome::HardDeny(msg);
    }

    match (&read.outcome, &write.outcome) {
        (DecisionOutcome::Permit, DecisionOutcome::Permit) => MergeOutcome::KeepReadWrite,
        (DecisionOutcome::Permit, DecisionOutcome::Deny { .. }) => MergeOutcome::DowngradeToRead,
        (DecisionOutcome::Deny { .. }, DecisionOutcome::Permit) => {
            tracing::warn!(
                cap_index = read.cap_index,
                "Cedar permits writes but denies reads on cap {}; \
                 downgrading to write-only (likely policy authoring error)",
                read.cap_index,
            );
            MergeOutcome::DowngradeToWrite
        }
        (DecisionOutcome::Deny { .. }, DecisionOutcome::Deny { .. }) => MergeOutcome::Remove,
    }
}

// ── Filter ─────────────────────────────────────────────────────────────────

/// Applies a slice of `CedarDecision`s to a `CapabilitySet`, mutating it in-place.
pub struct CedarCapabilityFilter;

impl CedarCapabilityFilter {
    /// Apply Cedar decisions to `caps`, narrowing or hard-erroring per `mode`.
    ///
    /// The caller must not mutate `caps` between `evaluate_capability_set` and
    /// this call — `cap_index` values must still map to the same capabilities.
    ///
    /// Returns `Err(CedarError::PolicyConflict)` if:
    /// - Any explicit `forbid(...)` matched (regardless of mode), or
    /// - Any denial occurred and `mode == Strict`.
    #[must_use = "check whether Cedar hard-denied a capability"]
    pub fn apply(
        decisions: &[CedarDecision],
        caps: &mut CapabilitySet,
        mode: FilterMode,
    ) -> Result<FilterResult> {
        let n_fs = caps.fs_capabilities().len();

        let mut by_cap: HashMap<usize, Vec<&CedarDecision>> = HashMap::new();
        for d in decisions {
            by_cap.entry(d.cap_index).or_default().push(d);
        }

        let mut cap_indices: Vec<usize> = by_cap.keys().copied().collect();
        cap_indices.sort_unstable();

        let mut indices_to_remove: Vec<usize> = Vec::new();
        let mut denied: Vec<DeniedCapInfo> = Vec::new();
        let mut downgraded_count = 0usize;

        for cap_index in cap_indices {
            let group = &by_cap[&cap_index];
            if group.len() == 1 {
                let single = group[0];
                match &single.outcome {
                    DecisionOutcome::Permit => {}
                    DecisionOutcome::Deny { is_explicit_forbid } => {
                        denied.push(DeniedCapInfo {
                            cap_index,
                            is_explicit_forbid: *is_explicit_forbid,
                            user_message: single.user_message.clone(),
                        });
                        if *is_explicit_forbid || mode == FilterMode::Strict {
                            return Err(CedarError::PolicyConflict(single.user_message.clone()));
                        }
                        indices_to_remove.push(cap_index);
                    }
                }
            } else if group.len() == 2 {
                let (read, write) = if group[0].action.starts_with("read") {
                    (group[0], group[1])
                } else {
                    (group[1], group[0])
                };
                match merge_decisions(read, write) {
                    MergeOutcome::KeepReadWrite => {}
                    MergeOutcome::DowngradeToRead => {
                        if cap_index < n_fs {
                            caps.downgrade_fs_access(cap_index, AccessMode::Read);
                        }
                        downgraded_count += 1;
                        denied.push(DeniedCapInfo {
                            cap_index,
                            is_explicit_forbid: false,
                            user_message: write.user_message.clone(),
                        });
                    }
                    MergeOutcome::DowngradeToWrite => {
                        if mode == FilterMode::Strict {
                            return Err(CedarError::PolicyConflict(read.user_message.clone()));
                        }
                        if cap_index < n_fs {
                            caps.downgrade_fs_access(cap_index, AccessMode::Write);
                        }
                        downgraded_count += 1;
                        denied.push(DeniedCapInfo {
                            cap_index,
                            is_explicit_forbid: false,
                            user_message: read.user_message.clone(),
                        });
                    }
                    MergeOutcome::Remove => {
                        let msg = format!("{}; {}", read.user_message, write.user_message);
                        if mode == FilterMode::Strict {
                            return Err(CedarError::PolicyConflict(msg));
                        }
                        denied.push(DeniedCapInfo {
                            cap_index,
                            is_explicit_forbid: false,
                            user_message: msg,
                        });
                        indices_to_remove.push(cap_index);
                    }
                    MergeOutcome::HardDeny(msg) => {
                        return Err(CedarError::PolicyConflict(msg));
                    }
                }
            } else {
                return Err(CedarError::AuthorizationFailed(format!(
                    "unexpected {} decisions for cap_index {cap_index}",
                    group.len()
                )));
            }
        }

        let removed_count = caps.remove_caps_by_index(&indices_to_remove);

        Ok(FilterResult {
            removed_count,
            downgraded_count,
            denied,
        })
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use nono::{CapabilitySource, FsCapability, UnixSocketCapability, UnixSocketMode, SocketScope};

    use super::*;
    use crate::engine::DecisionOutcome;

    fn permit(cap_index: usize, action: &'static str) -> CedarDecision {
        CedarDecision {
            cap_index,
            action: action.to_string(),
            resource_id: format!("/test/{cap_index}"),
            outcome: DecisionOutcome::Permit,
            user_message: String::new(),
            reasons: Vec::new(),
        }
    }

    fn implicit_deny(cap_index: usize, action: &'static str) -> CedarDecision {
        CedarDecision {
            cap_index,
            action: action.to_string(),
            resource_id: format!("/test/{cap_index}"),
            outcome: DecisionOutcome::Deny {
                is_explicit_forbid: false,
            },
            user_message: format!("implicit deny for {action} /test/{cap_index}"),
            reasons: Vec::new(),
        }
    }

    fn explicit_deny(cap_index: usize, action: &'static str) -> CedarDecision {
        CedarDecision {
            cap_index,
            action: action.to_string(),
            resource_id: format!("/test/{cap_index}"),
            outcome: DecisionOutcome::Deny {
                is_explicit_forbid: true,
            },
            user_message: format!("deny policies [policy0] for {action} /test/{cap_index}"),
            reasons: vec!["policy0".to_string()],
        }
    }

    fn fs_cap(access: AccessMode) -> FsCapability {
        FsCapability {
            original: PathBuf::from("/test/path"),
            resolved: PathBuf::from("/test/path"),
            access,
            is_file: false,
            source: CapabilitySource::User,
        }
    }

    fn unix_cap() -> UnixSocketCapability {
        UnixSocketCapability {
            original: PathBuf::from("/run/test.sock"),
            resolved: PathBuf::from("/run/test.sock"),
            scope: SocketScope::File,
            mode: UnixSocketMode::Connect,
            source: CapabilitySource::User,
        }
    }

    #[test]
    fn all_permit_leaves_caps_unchanged() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::Read));
        caps.add_fs(fs_cap(AccessMode::Write));

        let decisions = vec![permit(0, "read_dir"), permit(1, "write_dir")];
        let result =
            CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Narrow).expect("ok");

        assert_eq!(result.removed_count, 0);
        assert_eq!(result.downgraded_count, 0);
        assert!(result.denied.is_empty());
        assert_eq!(caps.fs_capabilities().len(), 2);
    }

    #[test]
    fn implicit_deny_narrow_removes_cap() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::Read));
        caps.add_fs(fs_cap(AccessMode::Read));

        let decisions = vec![permit(0, "read_dir"), implicit_deny(1, "read_dir")];
        let result =
            CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Narrow).expect("ok");

        assert_eq!(result.removed_count, 1);
        assert_eq!(caps.fs_capabilities().len(), 1);
        assert_eq!(result.denied.len(), 1);
        assert!(!result.denied[0].is_explicit_forbid);
    }

    #[test]
    fn implicit_deny_strict_errors() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::Read));

        let decisions = vec![implicit_deny(0, "read_dir")];
        let err = CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Strict)
            .expect_err("strict should error");

        assert!(matches!(err, CedarError::PolicyConflict(_)));
    }

    #[test]
    fn explicit_forbid_always_errors_in_narrow_mode() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::Read));

        let decisions = vec![explicit_deny(0, "read_dir")];
        let err = CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Narrow)
            .expect_err("explicit forbid must error even in Narrow");

        assert!(matches!(err, CedarError::PolicyConflict(_)));
    }

    #[test]
    fn readwrite_both_permit_keeps_readwrite() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::ReadWrite));

        let decisions = vec![permit(0, "read_dir"), permit(0, "write_dir")];
        let result =
            CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Narrow).expect("ok");

        assert_eq!(result.removed_count, 0);
        assert_eq!(result.downgraded_count, 0);
        assert_eq!(caps.fs_capabilities()[0].access, AccessMode::ReadWrite);
    }

    #[test]
    fn readwrite_write_denied_downgrades_to_read() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::ReadWrite));

        let decisions = vec![permit(0, "read_dir"), implicit_deny(0, "write_dir")];
        let result =
            CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Narrow).expect("ok");

        assert_eq!(result.downgraded_count, 1);
        assert_eq!(result.removed_count, 0);
        assert_eq!(caps.fs_capabilities()[0].access, AccessMode::Read);
        assert_eq!(result.denied.len(), 1);
        assert!(!result.denied[0].is_explicit_forbid);
    }

    #[test]
    fn readwrite_both_denied_removes_cap_in_narrow() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::ReadWrite));

        let decisions = vec![implicit_deny(0, "read_dir"), implicit_deny(0, "write_dir")];
        let result =
            CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Narrow).expect("ok");

        assert_eq!(result.removed_count, 1);
        assert!(caps.fs_capabilities().is_empty());
    }

    #[test]
    fn readwrite_explicit_forbid_hard_errors() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::ReadWrite));

        let decisions = vec![permit(0, "read_dir"), explicit_deny(0, "write_dir")];
        CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Narrow)
            .expect_err("explicit forbid on write half must hard-error");
    }

    #[test]
    fn unix_socket_implicit_deny_removed_in_narrow() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::Read)); // index 0
        caps.add_unix_socket(unix_cap()); // index 1 (n_fs=1)

        let decisions = vec![permit(0, "read_dir"), implicit_deny(1, "connect_unix_socket")];
        let result =
            CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Narrow).expect("ok");

        assert_eq!(result.removed_count, 1);
        assert_eq!(caps.fs_capabilities().len(), 1);
        assert!(caps.unix_socket_capabilities().is_empty());
    }

    #[test]
    fn cap_index_preserved_in_denied_list() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(AccessMode::Read));
        caps.add_fs(fs_cap(AccessMode::Read));
        caps.add_fs(fs_cap(AccessMode::Read));

        let decisions = vec![
            permit(0, "read_dir"),
            implicit_deny(1, "read_dir"),
            permit(2, "read_dir"),
        ];
        let result =
            CedarCapabilityFilter::apply(&decisions, &mut caps, FilterMode::Narrow).expect("ok");

        assert_eq!(result.denied[0].cap_index, 1);
    }

    // ── merge_decisions unit tests ─────────────────────────────────────────

    #[test]
    fn merge_both_permit_is_keep() {
        let r = permit(0, "read_dir");
        let w = permit(0, "write_dir");
        assert!(matches!(merge_decisions(&r, &w), MergeOutcome::KeepReadWrite));
    }

    #[test]
    fn merge_write_denied_is_downgrade_to_read() {
        let r = permit(0, "read_dir");
        let w = implicit_deny(0, "write_dir");
        assert!(matches!(
            merge_decisions(&r, &w),
            MergeOutcome::DowngradeToRead
        ));
    }

    #[test]
    fn merge_both_denied_is_remove() {
        let r = implicit_deny(0, "read_dir");
        let w = implicit_deny(0, "write_dir");
        assert!(matches!(merge_decisions(&r, &w), MergeOutcome::Remove));
    }

    #[test]
    fn merge_explicit_forbid_on_read_is_hard_deny() {
        let r = explicit_deny(0, "read_dir");
        let w = permit(0, "write_dir");
        assert!(matches!(merge_decisions(&r, &w), MergeOutcome::HardDeny(_)));
    }

    #[test]
    fn merge_explicit_forbid_on_write_is_hard_deny() {
        let r = permit(0, "read_dir");
        let w = explicit_deny(0, "write_dir");
        assert!(matches!(merge_decisions(&r, &w), MergeOutcome::HardDeny(_)));
    }
}
