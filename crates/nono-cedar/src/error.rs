//! Error types for the nono-cedar crate.
//!
//! Mirrors the shape of `sb-policy`'s `PolicyError` but adapted to nono's
//! coding standards (thiserror 2, Edition 2024) and extended for NONO's
//! richer evaluation model (entities, schema, forbid detection).

use thiserror::Error;

/// Errors produced by the Cedar evaluation layer.
#[derive(Debug, Error)]
pub enum CedarError {
    #[error("I/O error reading Cedar file: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cedar policy parse error: {0}")]
    PolicyParse(String),

    #[error("Cedar entity parse error: {0}")]
    EntityParse(String),

    #[error("Cedar schema load error: {0}")]
    SchemaLoad(String),

    /// Returned when a Cedar `forbid` rule explicitly blocks a capability.
    /// Unlike an implicit deny, this is always treated as a hard error
    /// regardless of `FilterMode`.
    #[error("Cedar explicit forbid: {message}")]
    ExplicitForbid { message: String },

    #[error("Cedar authorization error: {0}")]
    AuthorizationFailed(String),
}

pub type Result<T> = std::result::Result<T, CedarError>;
