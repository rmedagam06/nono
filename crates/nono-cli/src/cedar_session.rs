//! Ungated Cedar session types shared between the real Cedar implementation
//! and the feature-off stub.
//!
//! These types are **always** compiled (no `#[cfg(feature = "cedar")]`),
//! which lets `launch_runtime` build `CedarSessionArgs` unconditionally and
//! pass it to `maybe_apply_cedar` regardless of whether the cedar feature is
//! enabled. The cedar feature gate only controls whether nono-cedar is linked
//! and the evaluation actually runs.

use std::path::PathBuf;

/// Session context passed to the Cedar authorization engine.
///
/// Mirrors `nono_cedar::NonoSession` but lives outside the feature gate so
/// call sites in `launch_runtime.rs` and `command_runtime.rs` compile in
/// both configurations.
#[derive(Debug, Clone, Default)]
pub struct CedarSessionArgs {
    /// Stable run identifier (e.g. `"sess-alice-dev-001"`).
    pub session_id: String,
    /// OS user running the sandboxed command (e.g. `"alice"`).
    pub os_username: String,
    /// The nono profile in use (e.g. `"python-dev"`).
    pub profile: String,
    /// Working directory path (e.g. `"/home/alice/code"`).
    pub workdir: String,
    /// `"linux"` or `"macos"`.
    pub os: String,
    /// OS groups the user belongs to.
    pub groups: Vec<String>,
    /// Cedar role names assigned to this session.
    pub roles: Vec<String>,
}

/// How the Cedar filter responds to implicitly-denied capabilities.
///
/// Explicit `forbid(...)` matches are always a hard error, regardless of mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum CedarFilterMode {
    /// Remove implicitly-denied capabilities silently.
    #[default]
    Narrow,
    /// Treat any denial (implicit or explicit) as a hard error.
    Strict,
}

/// Plain-data summary of what Cedar decided — no `CedarDecision` inside.
///
/// Returned by `maybe_apply_cedar` so the call site in `launch_runtime.rs`
/// compiles in both cedar-on and cedar-off configurations.
#[derive(Debug, Clone, Default)]
pub struct CedarFilterResult {
    /// Number of capabilities removed from the set.
    pub removed_count: usize,
    /// Number of ReadWrite capabilities downgraded to a narrower mode.
    pub downgraded_count: usize,
    /// All denials encountered (including silent ones in Narrow mode).
    pub denied: Vec<DeniedCap>,
}

/// Information about a single denied or downgraded capability.
#[derive(Debug, Clone)]
pub struct DeniedCap {
    /// Flat combined index matching `CedarDecision::cap_index`.
    pub cap_index: usize,
    /// Human-readable explanation surfaced to the user.
    pub user_message: String,
}

/// Build a `CedarSessionArgs` from the CLI context available at launch time.
///
/// `session_id`: the already-generated run ID.
/// `profile_name`: the active profile, or `""` if no profile was specified.
/// `workdir`: the resolved working directory.
pub fn build_session_args(
    session_id: &str,
    profile_name: &str,
    workdir: &std::path::Path,
    policy_files: &[PathBuf],
) -> Option<CedarSessionArgs> {
    if policy_files.is_empty() {
        return None;
    }
    let os_username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    Some(CedarSessionArgs {
        session_id: session_id.to_string(),
        os_username,
        profile: profile_name.to_string(),
        workdir: workdir.to_string_lossy().into_owned(),
        os: os.to_string(),
        groups: Vec::new(),
        roles: Vec::new(),
    })
}
