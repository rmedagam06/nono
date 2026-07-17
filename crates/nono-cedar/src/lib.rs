//! Cedar authorization layer for nono.
//!
//! This crate evaluates Cedar policies against a NONO `CapabilitySet` before
//! `Sandbox::apply_auto()` makes enforcement irreversible. Cedar can only
//! narrow what the OS sandbox already allows — it cannot grant capabilities
//! the profile system didn't already include.

pub mod engine;
pub mod entity_builder;
pub mod entity_loader;
pub mod error;
pub mod loader;
pub mod request_builder;
pub mod schema;
pub mod session;

pub use engine::{CedarDecision, CedarPolicyEngine, DecisionOutcome};
pub use entity_builder::NonoEntityBuilder;
pub use entity_loader::{load_entities, load_entities_from_files};
pub use error::{CedarError, Result};
pub use loader::{load_policy_set, load_policy_set_from_files};
pub use request_builder::{EvalRequest, fs_eval_requests, unix_socket_eval_requests};
pub use schema::{NONO_CEDAR_SCHEMA, nono_schema};
pub use session::NonoSession;
