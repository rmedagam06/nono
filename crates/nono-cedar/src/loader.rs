//! Cedar policy file loading.
//!
//! Adapted from `sb-policy`'s `Evaluator::from_file()` (lines 73–89) but
//! returns the raw `PolicySet` rather than a bound evaluator, so callers
//! can combine it with entities and a schema in `CedarPolicyEngine`.

use cedar_policy::PolicySet;
use std::path::Path;

use crate::error::{CedarError, Result};

/// Load and parse one Cedar policy file into a `PolicySet`.
#[must_use = "dropping the PolicySet immediately achieves nothing"]
pub fn load_policy_set(path: &Path) -> Result<PolicySet> {
    let src = std::fs::read_to_string(path).map_err(CedarError::Io)?;
    src.parse::<PolicySet>()
        .map_err(|e| CedarError::PolicyParse(e.to_string()))
}

/// Load and merge multiple Cedar policy files into a single `PolicySet`.
///
/// Files are concatenated into a single source string before parsing.
/// This matches Cedar semantics: policy IDs must be unique across the
/// combined set, so authors should use `@id("...")` annotations on each
/// policy to avoid collisions.
pub fn load_policy_set_from_files(paths: &[impl AsRef<Path>]) -> Result<PolicySet> {
    let mut combined = String::new();
    for path in paths {
        let src = std::fs::read_to_string(path.as_ref()).map_err(CedarError::Io)?;
        combined.push_str(&src);
        combined.push('\n');
    }
    combined
        .parse::<PolicySet>()
        .map_err(|e| CedarError::PolicyParse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_tmp(name: &str, src: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nono-cedar-loader-test-{name}.cedar"));
        let mut f = std::fs::File::create(&path).expect("create tmp file");
        f.write_all(src.as_bytes()).expect("write tmp file");
        path
    }

    #[test]
    fn valid_permit_policy_loads() {
        let path = write_tmp("permit", r#"permit(principal, action, resource);"#);
        let ps = load_policy_set(&path).expect("should load");
        assert_eq!(ps.policies().count(), 1);
    }

    #[test]
    fn valid_forbid_policy_loads() {
        // A forbid-all is syntactically valid Cedar — not a parse error.
        let path = write_tmp("forbid_all", "forbid(principal, action, resource);");
        let ps = load_policy_set(&path).expect("forbid-all is valid Cedar syntax");
        assert_eq!(ps.policies().count(), 1);
    }

    #[test]
    fn invalid_policy_returns_parse_error() {
        let path = write_tmp(
            "broken",
            "permit principal action resource", // missing parens and semicolon
        );
        let err = load_policy_set(&path).expect_err("should fail to parse");
        assert!(
            matches!(err, CedarError::PolicyParse(_)),
            "expected PolicyParse, got {err:?}"
        );
        if let CedarError::PolicyParse(msg) = err {
            assert!(!msg.is_empty(), "PolicyParse message must not be empty");
        }
    }

    #[test]
    fn nonexistent_file_returns_io_error() {
        let err = load_policy_set(std::path::Path::new("/nonexistent/path/policy.cedar"))
            .expect_err("should fail on missing file");
        assert!(matches!(err, CedarError::Io(_)));
    }

    #[test]
    fn multiple_files_merge() {
        let p1 = write_tmp("multi1", r#"@id("p1") permit(principal, action, resource);"#);
        let p2 = write_tmp("multi2", r#"@id("p2") forbid(principal, action, resource);"#);
        let ps = load_policy_set_from_files(&[&p1, &p2]).expect("merge should succeed");
        assert_eq!(ps.policies().count(), 2);
    }
}
