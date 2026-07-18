//! NONO Cedar schema — embedded at compile time and validated at startup.

use cedar_policy::Schema;

use crate::error::{CedarError, Result};

/// The canonical NONO Cedar schema, embedded from `data/nono.cedarschema`.
///
/// This schema defines all entity types (`Session`, `User`, `Role`, `File`,
/// `Directory`, `NetworkEndpoint`, `UnixSocket`) and the six actions that
/// policies can reference. Every `.cedar` policy file used with nono must
/// be valid against this schema.
pub static NONO_CEDAR_SCHEMA: &str = include_str!("../data/nono.cedarschema");

/// Parse and return the embedded NONO Cedar schema.
///
/// Called during `CedarPolicyEngine` construction to validate entities and
/// policy requests against the schema before any evaluation occurs.
pub fn nono_schema() -> Result<Schema> {
    Schema::from_cedarschema_str(NONO_CEDAR_SCHEMA)
        .map(|(schema, _warnings)| schema)
        .map_err(|e| CedarError::SchemaLoad(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_schema_parses_without_error() {
        nono_schema().expect("NONO Cedar schema must parse cleanly");
    }

    #[test]
    fn schema_string_is_non_empty() {
        assert!(
            !NONO_CEDAR_SCHEMA.trim().is_empty(),
            "embedded schema must not be empty"
        );
    }
}
