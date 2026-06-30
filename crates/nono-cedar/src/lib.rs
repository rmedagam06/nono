//! Cedar authorization layer for nono.
//!
//! This crate evaluates Cedar policies against a NONO `CapabilitySet` before
//! `Sandbox::apply_auto()` makes enforcement irreversible. Cedar can only
//! narrow what the OS sandbox already allows — it cannot grant capabilities
//! the profile system didn't already include.
//!
//! # Phase 1 — Foundation
//! This phase covers policy and entity file loading only. The authorization
//! engine (`engine.rs`), entity builder (`entity_builder.rs`), and capability
//! filter (`filter.rs`) are added in subsequent phases.

pub mod entity_loader;
pub mod error;
pub mod loader;

pub use entity_loader::{load_entities, load_entities_from_files};
pub use error::{CedarError, Result};
pub use loader::{load_policy_set, load_policy_set_from_files};
