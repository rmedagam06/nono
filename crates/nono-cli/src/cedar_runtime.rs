//! Cedar runtime integration: feature-gated real implementation and
//! always-present feature-off stub.
//!
//! Both the real impl and the stub share an identical public signature so
//! call sites in `launch_runtime.rs` and `command_runtime.rs` compile in
//! both configurations without any `#[cfg]` at the call site.
//!
//! # Fail-closed stub
//!
//! When Cedar is not compiled in (`#[cfg(not(feature = "cedar"))]`), any
//! invocation with non-empty `policy_files` returns a hard error:
//! ```text
//! Cedar support not compiled in; rebuild with --features cedar
//! ```
//! The stub NEVER silently ignores `--cedar-policy` flags, so a user who
//! intends Cedar enforcement cannot accidentally run without it.

use nono::{CapabilitySet, NonoError, Result};
use std::path::PathBuf;

use crate::cedar_session::{CedarFilterMode, CedarFilterResult, CedarSessionArgs, DeniedCap};

/// Type alias so callers don't have to spell out the full `Result<Option<…>>`.
pub type MaybeCedarResult = Result<Option<CedarFilterResult>>;

// ── Feature-on: real Cedar implementation ─────────────────────────────────

#[cfg(feature = "cedar")]
pub fn maybe_apply_cedar(
    caps: &mut CapabilitySet,
    policy_files: &[PathBuf],
    entity_files: &[PathBuf],
    session: &CedarSessionArgs,
    mode: CedarFilterMode,
) -> MaybeCedarResult {
    if policy_files.is_empty() {
        return Ok(None);
    }

    use nono_cedar::{
        CedarCapabilityFilter, CedarPolicyEngine, FilterMode as NativeMode, NonoEntityBuilder,
        NonoSession, load_policy_set_from_files, merge_entity_json_with_files, nono_schema,
    };

    // Load policy set — use file-level load (cache is opt-in via load_policy_set_cached).
    let policy_set = load_policy_set_from_files(policy_files)
        .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;
    let schema = nono_schema().map_err(|e| NonoError::CedarPolicy(e.to_string()))?;

    // Build Cedar entities from session context + current capability set resources.
    let groups: Vec<&str> = session.groups.iter().map(String::as_str).collect();
    let roles: Vec<&str> = session.roles.iter().map(String::as_str).collect();
    let mut builder = NonoEntityBuilder::new(
        &session.os_username,
        &session.session_id,
        &session.profile,
        &session.workdir,
        &session.os,
        &groups,
        &roles,
    );

    for cap in caps.fs_capabilities() {
        let path = cap.resolved.to_string_lossy();
        if cap.is_file {
            builder = builder.add_file_resource(&path, false, "unknown");
        } else {
            builder = builder.add_directory_resource(&path, false);
        }
    }
    for cap in caps.unix_socket_capabilities() {
        let path = cap.resolved.to_string_lossy();
        builder = builder.add_unix_socket(&path);
    }

    // Merge builder JSON with any extra entity files.
    let base_json = builder
        .to_json_string()
        .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;
    let entities = merge_entity_json_with_files(&base_json, entity_files)
        .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;

    // Build engine and evaluate.
    let engine = CedarPolicyEngine::new(policy_set, entities, Some(schema));
    let nono_session = NonoSession::new(
        &session.session_id,
        &session.os_username,
        &session.profile,
        &session.workdir,
        &session.os,
    )
    .with_groups(session.groups.iter().map(String::as_str))
    .with_roles(session.roles.iter().map(String::as_str));

    let decisions = engine
        .evaluate_capability_set(caps, &nono_session)
        .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;

    let native_mode = match mode {
        CedarFilterMode::Narrow => NativeMode::Narrow,
        CedarFilterMode::Strict => NativeMode::Strict,
    };

    let filter = CedarCapabilityFilter::apply(&decisions, caps, native_mode)
        .map_err(|e| NonoError::CedarDenied { reason: e.to_string() })?;

    let denied: Vec<DeniedCap> = filter
        .denied
        .into_iter()
        .map(|d| DeniedCap {
            cap_index: d.cap_index,
            is_explicit_forbid: d.is_explicit_forbid,
            user_message: d.user_message,
        })
        .collect();

    Ok(Some(CedarFilterResult {
        removed_count: filter.removed_count,
        downgraded_count: filter.downgraded_count,
        denied,
    }))
}

// ── Feature-off: fail-closed stub ─────────────────────────────────────────

#[cfg(not(feature = "cedar"))]
pub fn maybe_apply_cedar(
    _caps: &mut CapabilitySet,
    policy_files: &[PathBuf],
    _entity_files: &[PathBuf],
    _session: &CedarSessionArgs,
    _mode: CedarFilterMode,
) -> MaybeCedarResult {
    if !policy_files.is_empty() {
        return Err(NonoError::CedarPolicy(
            "Cedar support not compiled in; rebuild with --features cedar".into(),
        ));
    }
    Ok(None)
}
