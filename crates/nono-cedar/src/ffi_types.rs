//! Phase 8 — C-ABI-compatible types for future Cedar FFI integration.
//!
//! These types are `repr(C)` and safe to cross the Rust–C boundary once the
//! `bindings/c/src/cedar.rs` module is wired up in a future PR.  They are
//! defined here (in `nono-cedar`) rather than in `bindings/c` so that the
//! nono-cli feature-gate path can use them without depending on the C binding
//! crate.
//!
//! No `extern "C"` symbols are exported from this module — that belongs in
//! `bindings/c/src/cedar.rs`.  This module is purely a type definition layer.

/// C-ABI equivalent of `FilterMode`.
///
/// `0` → Narrow (remove implicitly-denied caps, hard-error on explicit forbid).
/// `1` → Strict (hard-error on any denial).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum NoceCedarFilterMode {
    Narrow = 0,
    Strict = 1,
}

impl From<crate::filter::FilterMode> for NoceCedarFilterMode {
    fn from(m: crate::filter::FilterMode) -> Self {
        match m {
            crate::filter::FilterMode::Narrow => Self::Narrow,
            crate::filter::FilterMode::Strict => Self::Strict,
        }
    }
}

impl From<NoceCedarFilterMode> for crate::filter::FilterMode {
    fn from(m: NoceCedarFilterMode) -> Self {
        match m {
            NoceCedarFilterMode::Narrow => Self::Narrow,
            NoceCedarFilterMode::Strict => Self::Strict,
        }
    }
}

/// C-ABI summary of a single Cedar decision outcome.
///
/// `0` → Permit, `1` → Deny (implicit), `2` → Deny (explicit forbid).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum NoceCedarOutcome {
    Permit = 0,
    ImplicitDeny = 1,
    ExplicitForbid = 2,
}

impl From<&crate::engine::DecisionOutcome> for NoceCedarOutcome {
    fn from(o: &crate::engine::DecisionOutcome) -> Self {
        match o {
            crate::engine::DecisionOutcome::Permit => Self::Permit,
            crate::engine::DecisionOutcome::Deny {
                is_explicit_forbid: false,
            } => Self::ImplicitDeny,
            crate::engine::DecisionOutcome::Deny {
                is_explicit_forbid: true,
            } => Self::ExplicitForbid,
        }
    }
}

/// C-ABI summary of `FilterResult`.
///
/// String fields are NOT included here (they are heap-allocated and would
/// require caller-owned `*mut c_char` pattern from `bindings/c`).  This
/// struct conveys the numeric summary; callers that need denial messages must
/// use the Rust API directly.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NoceCedarFilterSummary {
    pub removed_count: usize,
    pub downgraded_count: usize,
    pub denied_count: usize,
}

impl From<&crate::filter::FilterResult> for NoceCedarFilterSummary {
    fn from(r: &crate::filter::FilterResult) -> Self {
        Self {
            removed_count: r.removed_count,
            downgraded_count: r.downgraded_count,
            denied_count: r.denied.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::FilterMode;

    #[test]
    fn filter_mode_roundtrip() {
        assert_eq!(
            FilterMode::from(NoceCedarFilterMode::from(FilterMode::Narrow)),
            FilterMode::Narrow
        );
        assert_eq!(
            FilterMode::from(NoceCedarFilterMode::from(FilterMode::Strict)),
            FilterMode::Strict
        );
    }

    #[test]
    fn outcome_permit_maps_correctly() {
        let o = crate::engine::DecisionOutcome::Permit;
        assert_eq!(NoceCedarOutcome::from(&o), NoceCedarOutcome::Permit);
    }

    #[test]
    fn outcome_implicit_deny_maps_correctly() {
        let o = crate::engine::DecisionOutcome::Deny {
            is_explicit_forbid: false,
        };
        assert_eq!(NoceCedarOutcome::from(&o), NoceCedarOutcome::ImplicitDeny);
    }

    #[test]
    fn outcome_explicit_forbid_maps_correctly() {
        let o = crate::engine::DecisionOutcome::Deny {
            is_explicit_forbid: true,
        };
        assert_eq!(NoceCedarOutcome::from(&o), NoceCedarOutcome::ExplicitForbid);
    }
}
