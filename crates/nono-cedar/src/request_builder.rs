//! Translates NONO `CapabilitySet` entries into Cedar evaluation requests.
//!
//! Each [`EvalRequest`] pairs a capability index with the Cedar action,
//! resource type, and resource ID needed to build a `cedar_policy::Request`.
//!
//! A `ReadWrite` filesystem capability produces **two** `EvalRequest`s that
//! share the same `cap_index` — one for the read action and one for the write
//! action. The filter phase merges the two `CedarDecision`s per-index before
//! acting (see `filter.rs` Phase 4).

use nono::{AccessMode, FsCapability, UnixSocketCapability};

/// A single Cedar evaluation request derived from one NONO capability.
///
/// Build the full `cedar_policy::Request` in `CedarPolicyEngine::evaluate_one`.
#[derive(Debug, Clone)]
pub struct EvalRequest {
    /// Index of the originating capability in the `CapabilitySet`'s slice.
    pub cap_index: usize,
    /// Cedar action name, e.g. `"read_file"` or `"write_dir"`.
    pub action: &'static str,
    /// Cedar entity type for the resource, e.g. `"nono::File"`.
    pub resource_type: &'static str,
    /// String used as the Cedar entity ID (typically the canonical path).
    pub resource_id: String,
    /// True when this is the write half of a `ReadWrite` pair.
    pub is_write: bool,
}

/// Escape a string for use inside a Cedar entity UID literal.
///
/// Cedar string literals delimit with `"` and recognise `\"` and `\\`.
/// Normal filesystem paths on Linux/macOS never contain these characters,
/// but we escape defensively so the engine doesn't panic on unusual paths.
fn cedar_escape(s: &str) -> String {
    s.replace('\\', r"\\").replace('"', r#"\""#)
}

/// Build Cedar evaluation requests from a slice of filesystem capabilities.
///
/// `cap_offset` is added to each index so that fs, unix-socket, and
/// network requests share a flat, non-overlapping index space when
/// combined by the engine.
pub fn fs_eval_requests(caps: &[FsCapability], cap_offset: usize) -> Vec<EvalRequest> {
    let mut out = Vec::new();

    for (i, cap) in caps.iter().enumerate() {
        let idx = cap_offset + i;
        let path = cedar_escape(&cap.resolved.to_string_lossy());
        let (resource_type, read_action, write_action) = if cap.is_file {
            ("nono::File", "read_file", "write_file")
        } else {
            ("nono::Directory", "read_dir", "write_dir")
        };

        match cap.access {
            AccessMode::Read => {
                out.push(EvalRequest {
                    cap_index: idx,
                    action: read_action,
                    resource_type,
                    resource_id: path,
                    is_write: false,
                });
            }
            AccessMode::Write => {
                out.push(EvalRequest {
                    cap_index: idx,
                    action: write_action,
                    resource_type,
                    resource_id: path,
                    is_write: true,
                });
            }
            AccessMode::ReadWrite => {
                out.push(EvalRequest {
                    cap_index: idx,
                    action: read_action,
                    resource_type,
                    resource_id: path.clone(),
                    is_write: false,
                });
                out.push(EvalRequest {
                    cap_index: idx,
                    action: write_action,
                    resource_type,
                    resource_id: path,
                    is_write: true,
                });
            }
        }
    }

    out
}

/// Build Cedar evaluation requests from a slice of Unix socket capabilities.
pub fn unix_socket_eval_requests(
    caps: &[UnixSocketCapability],
    cap_offset: usize,
) -> Vec<EvalRequest> {
    caps.iter()
        .enumerate()
        .map(|(i, cap)| EvalRequest {
            cap_index: cap_offset + i,
            action: "connect_unix_socket",
            resource_type: "nono::UnixSocket",
            resource_id: cedar_escape(&cap.resolved.to_string_lossy()),
            is_write: false,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_fs_cap(path: &str, access: AccessMode, is_file: bool) -> FsCapability {
        FsCapability {
            original: path.into(),
            resolved: path.into(),
            access,
            is_file,
            source: nono::CapabilitySource::User,
        }
    }

    #[test]
    fn read_file_produces_one_request() {
        let cap = fake_fs_cap("/home/alice/code/main.rs", AccessMode::Read, true);
        let reqs = fs_eval_requests(&[cap], 0);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].action, "read_file");
        assert_eq!(reqs[0].resource_type, "nono::File");
        assert!(!reqs[0].is_write);
        assert_eq!(reqs[0].cap_index, 0);
    }

    #[test]
    fn write_file_produces_one_request() {
        let cap = fake_fs_cap("/tmp/out.log", AccessMode::Write, true);
        let reqs = fs_eval_requests(&[cap], 0);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].action, "write_file");
        assert!(reqs[0].is_write);
    }

    #[test]
    fn readwrite_file_produces_two_requests_same_index() {
        let cap = fake_fs_cap("/home/alice/data.bin", AccessMode::ReadWrite, true);
        let reqs = fs_eval_requests(&[cap], 0);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].action, "read_file");
        assert_eq!(reqs[1].action, "write_file");
        assert_eq!(reqs[0].cap_index, reqs[1].cap_index);
    }

    #[test]
    fn directory_cap_uses_dir_actions() {
        let cap = fake_fs_cap("/home/alice/code", AccessMode::ReadWrite, false);
        let reqs = fs_eval_requests(&[cap], 0);
        assert_eq!(reqs[0].action, "read_dir");
        assert_eq!(reqs[1].action, "write_dir");
        assert_eq!(reqs[0].resource_type, "nono::Directory");
    }

    #[test]
    fn cap_offset_applied_to_indices() {
        let cap = fake_fs_cap("/tmp/file", AccessMode::Read, true);
        let reqs = fs_eval_requests(&[cap], 5);
        assert_eq!(reqs[0].cap_index, 5);
    }

    #[test]
    fn path_with_special_chars_escaped() {
        let cap = fake_fs_cap(r#"/tmp/file"name"#, AccessMode::Read, true);
        let reqs = fs_eval_requests(&[cap], 0);
        assert!(reqs[0].resource_id.contains(r#"\""#), "quote must be escaped");
    }

    #[test]
    fn unix_socket_request() {
        use nono::{UnixSocketMode, SocketScope};
        let cap = UnixSocketCapability {
            original: "/run/docker.sock".into(),
            resolved: "/run/docker.sock".into(),
            scope: SocketScope::File,
            mode: UnixSocketMode::Connect,
            source: nono::CapabilitySource::User,
        };
        let reqs = unix_socket_eval_requests(&[cap], 10);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].action, "connect_unix_socket");
        assert_eq!(reqs[0].resource_type, "nono::UnixSocket");
        assert_eq!(reqs[0].cap_index, 10);
    }
}
