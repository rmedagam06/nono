//! Cedar authorization layer for nono.
//!
//! This crate evaluates Cedar policies against a NONO `CapabilitySet` before
//! `Sandbox::apply_auto()` makes enforcement irreversible. Cedar can only
//! narrow what the OS sandbox already allows — it cannot grant capabilities
//! the profile system didn't already include.

pub mod entity_builder;
pub mod entity_loader;
pub mod error;
pub mod loader;
pub mod schema;

pub use entity_builder::NonoEntityBuilder;
pub use entity_loader::{load_entities, load_entities_from_files};
pub use error::{CedarError, Result};
pub use loader::{load_policy_set, load_policy_set_from_files};
pub use schema::{nono_schema, NONO_CEDAR_SCHEMA};
