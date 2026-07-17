//! Cedar authorization engine.
//!
//! `CedarPolicyEngine` evaluates a NONO `CapabilitySet` against a loaded
//! `PolicySet` and `Entities` set. Each filesystem and Unix-socket capability
//! is translated into one or two Cedar `Request`s (see `request_builder`) and
//! evaluated with the Cedar authorizer.
//!
//! Adapted from `sb-policy`'s `Evaluator::evaluate_exec()` (lines 104–152)
//! but generalised for NONO's multi-action, multi-resource model.
//!
//! **Critical**: unlike `sb-policy`, which passes `&Entities::empty()`,
//! this engine always passes `&self.entities` so that attribute checks and
//! entity hierarchy traversal work correctly.

use cedar_policy::{
    Authorizer, Context, Decision, Diagnostics, Entities, EntityUid, PolicySet, Request, Schema,
};
use nono::CapabilitySet;
use serde_json::json;

use crate::error::{CedarError, Result};
use crate::request_builder::{EvalRequest, fs_eval_requests, unix_socket_eval_requests};
use crate::session::NonoSession;

// ── Decision types ─────────────────────────────────────────────────────────

/// Outcome of a single Cedar evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionOutcome {
    /// Cedar returned `Allow`.
    Permit,
    /// Cedar returned `Deny`.
    Deny {
        /// True when one or more explicit `forbid(...)` policies matched.
        /// False means no `permit` matched (implicit deny).
        is_explicit_forbid: bool,
    },
}

/// The result of evaluating one [`EvalRequest`] against Cedar policies.
#[derive(Debug, Clone)]
pub struct CedarDecision {
    /// Index of the originating capability in the `CapabilitySet` slice.
    pub cap_index: usize,
    /// Cedar action that was evaluated (e.g. `"read_file"`).
    pub action: String,
    /// Cedar entity ID of the resource that was evaluated (e.g. a path).
    pub resource_id: String,
    /// Whether Cedar allowed or denied the request.
    pub outcome: DecisionOutcome,
    /// Human-readable denial message for CLI stderr.
    ///
    /// For a `Permit` this is empty. For a `Deny`, it is either the list of
    /// forbid-policy IDs that matched or `"implicit deny (no permit matched)"`.
    /// This message is mandatory and must flow through to the user — the user
    /// must see *why* a capability was blocked, not just that it was.
    pub user_message: String,
    /// Raw Cedar policy IDs from `response.diagnostics().reason()`.
    pub reasons: Vec<String>,
}

// ── Engine ─────────────────────────────────────────────────────────────────

/// Cedar authorization engine for NONO capability evaluation.
///
/// Construct once per run with the pre-loaded policy set, entity set, and
/// optional schema. Then call [`evaluate_capability_set`] to receive one
/// [`CedarDecision`] per [`EvalRequest`] generated from the capability set.
pub struct CedarPolicyEngine {
    policy_set: PolicySet,
    /// Entity set built by `NonoEntityBuilder` for this session.
    ///
    /// Must be non-empty: unlike `sb-policy`, NONO policies reference entity
    /// attributes (`os_username`, `groups`, `sensitive`) and hierarchy
    /// relationships (`Session` → `Role`). Passing an empty entity set would
    /// cause all attribute/hierarchy checks to silently fail.
    entities: Entities,
    authorizer: Authorizer,
    schema: Option<Schema>,
}

impl CedarPolicyEngine {
    /// Create a new engine.
    ///
    /// `entities` must be the entity set produced by `NonoEntityBuilder::build()`
    /// for the current session, including all file/directory/socket resource
    /// entities that policies may reference by attribute.
    pub fn new(policy_set: PolicySet, entities: Entities, schema: Option<Schema>) -> Self {
        Self {
            policy_set,
            entities,
            authorizer: Authorizer::new(),
            schema,
        }
    }

    /// Evaluate all filesystem and Unix-socket capabilities in `caps`.
    ///
    /// Returns one `CedarDecision` per `EvalRequest` generated from the
    /// capability set. A `ReadWrite` filesystem capability produces two
    /// decisions (one for read, one for write) sharing the same `cap_index`.
    ///
    /// Network capabilities (`NetworkMode`) are not evaluated here because
    /// `CapabilitySet` does not enumerate specific endpoints. Network endpoint
    /// evaluation is added in Phase 4/5 when the CLI provides explicit
    /// `NetworkEndpoint` entities.
    pub fn evaluate_capability_set(
        &self,
        caps: &CapabilitySet,
        session: &NonoSession,
    ) -> Result<Vec<CedarDecision>> {
        let fs_caps = caps.fs_capabilities();
        let unix_caps = caps.unix_socket_capabilities();

        let mut requests = fs_eval_requests(fs_caps, 0);
        requests.extend(unix_socket_eval_requests(unix_caps, fs_caps.len()));

        requests
            .iter()
            .map(|req| self.evaluate_one(req, session))
            .collect()
    }

    /// Evaluate a single pre-built request against the engine's policy set.
    pub fn evaluate_one(&self, req: &EvalRequest, session: &NonoSession) -> Result<CedarDecision> {
        let principal_uid = parse_uid(
            &format!("nono::Session::\"{}\"", cedar_escape(&session.session_id)),
            "principal",
        )?;
        let action_uid = parse_uid(&format!("nono::Action::\"{}\"", req.action), "action")?;
        let resource_uid = parse_uid(
            &format!("{}::\"{}\"", req.resource_type, req.resource_id),
            "resource",
        )?;

        let context_json = if req.action == "connect_network" {
            json!({ "profile": session.profile, "os": session.os, "proxy_active": false })
        } else {
            json!({ "profile": session.profile, "os": session.os })
        };
        let context = Context::from_json_value(context_json, None)
            .map_err(|e| CedarError::AuthorizationFailed(e.to_string()))?;

        let cedar_request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            context,
            self.schema.as_ref(),
        )
        .map_err(|e| CedarError::AuthorizationFailed(e.to_string()))?;

        // IMPORTANT: pass &self.entities, NOT &Entities::empty().
        // NONO policies reference User attributes and Role hierarchy.
        // &Entities::empty() would silently fail every attribute check.
        let response =
            self.authorizer
                .is_authorized(&cedar_request, &self.policy_set, &self.entities);

        Ok(build_decision(
            req,
            response.decision(),
            response.diagnostics(),
        ))
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn parse_uid(uid_str: &str, role: &str) -> Result<EntityUid> {
    uid_str.parse().map_err(|e: cedar_policy::ParseErrors| {
        CedarError::AuthorizationFailed(format!("invalid {role} UID {uid_str:?}: {e}"))
    })
}

fn cedar_escape(s: &str) -> String {
    s.replace('\\', r"\\").replace('"', r#"\""#)
}

fn build_decision(req: &EvalRequest, decision: Decision, diag: &Diagnostics) -> CedarDecision {
    match decision {
        Decision::Allow => CedarDecision {
            cap_index: req.cap_index,
            action: req.action.to_string(),
            resource_id: req.resource_id.clone(),
            outcome: DecisionOutcome::Permit,
            user_message: String::new(),
            reasons: Vec::new(),
        },
        Decision::Deny => {
            let reasons: Vec<String> = diag.reason().map(|id| id.to_string()).collect();
            let is_explicit_forbid = !reasons.is_empty();
            let user_message = if reasons.is_empty() {
                format!(
                    "implicit deny (no permit matched) for {} {}",
                    req.action, req.resource_id
                )
            } else {
                format!(
                    "deny policies [{}] for {} {}",
                    reasons.join(", "),
                    req.action,
                    req.resource_id,
                )
            };
            CedarDecision {
                cap_index: req.cap_index,
                action: req.action.to_string(),
                resource_id: req.resource_id.clone(),
                outcome: DecisionOutcome::Deny { is_explicit_forbid },
                user_message,
                reasons,
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_builder::NonoEntityBuilder;

    fn test_session() -> NonoSession {
        NonoSession::new(
            "sess-test-001",
            "alice",
            "python-dev",
            "/home/alice/code",
            "linux",
        )
        .with_groups(["developers"])
        .with_roles(["developer"])
    }

    fn make_engine(policy_src: &str) -> CedarPolicyEngine {
        let policy_set: PolicySet = policy_src.parse().expect("policy parse");
        let entities = NonoEntityBuilder::new(
            "alice",
            "sess-test-001",
            "python-dev",
            "/home/alice/code",
            "linux",
            &["developers"],
            &["developer"],
        )
        .add_file_resource("/home/alice/code/main.rs", false, "alice")
        .add_file_resource("/etc/passwd", true, "root")
        .add_directory_resource("/home/alice/code", false)
        .add_unix_socket("/run/docker.sock")
        .build()
        .expect("entities build");
        CedarPolicyEngine::new(policy_set, entities, None)
    }

    fn file_req(idx: usize, action: &'static str, path: &str) -> EvalRequest {
        EvalRequest {
            cap_index: idx,
            action,
            resource_type: "nono::File",
            resource_id: path.to_string(),
            is_write: action.starts_with("write"),
        }
    }

    fn dir_req(idx: usize, action: &'static str, path: &str) -> EvalRequest {
        EvalRequest {
            cap_index: idx,
            action,
            resource_type: "nono::Directory",
            resource_id: path.to_string(),
            is_write: action.starts_with("write"),
        }
    }

    fn socket_req(idx: usize, path: &str) -> EvalRequest {
        EvalRequest {
            cap_index: idx,
            action: "connect_unix_socket",
            resource_type: "nono::UnixSocket",
            resource_id: path.to_string(),
            is_write: false,
        }
    }

    // ── Baseline test shapes (mirrors sb-policy's three test shapes) ────────

    #[test]
    fn permit_read_file_allows_read_cap() {
        let engine = make_engine("permit(principal, action, resource);");
        let req = file_req(0, "read_file", "/home/alice/code/main.rs");
        let decision = engine.evaluate_one(&req, &test_session()).expect("eval");
        assert_eq!(decision.outcome, DecisionOutcome::Permit);
        assert!(decision.user_message.is_empty());
    }

    #[test]
    fn implicit_deny_when_no_permit_matches() {
        let engine = make_engine(""); // empty policy set → everything implicitly denied
        let req = file_req(0, "read_file", "/home/alice/code/main.rs");
        let decision = engine.evaluate_one(&req, &test_session()).expect("eval");
        assert!(matches!(
            decision.outcome,
            DecisionOutcome::Deny {
                is_explicit_forbid: false
            }
        ));
        assert!(
            decision.user_message.contains("implicit deny"),
            "user_message must contain 'implicit deny', got: {}",
            decision.user_message
        );
        assert!(
            !decision.user_message.is_empty(),
            "user_message must not be empty"
        );
    }

    #[test]
    fn explicit_forbid_overrides_permit() {
        let policy = r#"
            @id("allow-all")
            permit(principal, action, resource);
            @id("forbid-sensitive")
            forbid(
                principal,
                action,
                resource
            ) when { resource.sensitive };
        "#;
        let engine = make_engine(policy);

        // /etc/passwd has sensitive = true in the entity builder above
        let req = file_req(0, "read_file", "/etc/passwd");
        let decision = engine.evaluate_one(&req, &test_session()).expect("eval");
        assert!(matches!(
            decision.outcome,
            DecisionOutcome::Deny {
                is_explicit_forbid: true
            }
        ));
        // Cedar assigns sequential IDs (policy0, policy1, …) when parsing a
        // PolicySet from a string; @id() is metadata, not the policy ID. So we
        // verify that the message names *a* policy (proving it's an explicit
        // forbid, not an implicit deny) without checking the exact ID string.
        assert!(
            decision.user_message.contains("deny policies ["),
            "user_message must list deny policies, got: {}",
            decision.user_message
        );
        assert!(!decision.reasons.is_empty(), "explicit forbid must populate reasons");
    }

    // ── NONO-specific tests ────────────────────────────────────────────────

    #[test]
    fn deny_user_message_is_non_empty() {
        let engine = make_engine("");
        let req = file_req(0, "read_file", "/home/alice/code/main.rs");
        let decision = engine.evaluate_one(&req, &test_session()).expect("eval");
        assert!(
            !decision.user_message.is_empty(),
            "every Deny must carry a non-empty user_message"
        );
    }

    #[test]
    fn permit_user_message_is_empty() {
        let engine = make_engine("permit(principal, action, resource);");
        let req = file_req(0, "read_file", "/home/alice/code/main.rs");
        let decision = engine.evaluate_one(&req, &test_session()).expect("eval");
        assert_eq!(decision.outcome, DecisionOutcome::Permit);
        assert!(
            decision.user_message.is_empty(),
            "Permit decisions must have empty user_message"
        );
    }

    #[test]
    fn cap_index_preserved_in_decision() {
        let engine = make_engine("permit(principal, action, resource);");
        let req = file_req(42, "read_file", "/home/alice/code/main.rs");
        let decision = engine.evaluate_one(&req, &test_session()).expect("eval");
        assert_eq!(decision.cap_index, 42);
    }

    #[test]
    fn unix_socket_permit() {
        let engine = make_engine("permit(principal, action, resource);");
        let req = socket_req(0, "/run/docker.sock");
        let decision = engine.evaluate_one(&req, &test_session()).expect("eval");
        assert_eq!(decision.outcome, DecisionOutcome::Permit);
    }

    #[test]
    fn directory_permit() {
        let engine = make_engine("permit(principal, action, resource);");
        let req = dir_req(0, "read_dir", "/home/alice/code");
        let decision = engine.evaluate_one(&req, &test_session()).expect("eval");
        assert_eq!(decision.outcome, DecisionOutcome::Permit);
    }

    #[test]
    fn network_endpoint_forbid_blocks_connect() {
        let policy = r#"
            @id("allow-all")
            permit(principal, action, resource);
            @id("block-network")
            forbid(principal, action == nono::Action::"connect_network", resource);
        "#;
        let engine = make_engine(policy);
        let req = EvalRequest {
            cap_index: 0,
            action: "connect_network",
            resource_type: "nono::NetworkEndpoint",
            resource_id: "api.example.com:443".to_string(),
            is_write: false,
        };
        let decision = engine.evaluate_one(&req, &test_session()).expect("eval");
        assert!(matches!(
            decision.outcome,
            DecisionOutcome::Deny {
                is_explicit_forbid: true
            }
        ));
    }
}
