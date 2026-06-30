//! Cedar entity JSON loading.
//!
//! Loads entity sets from Cedar's standard JSON format
//! (`Entities::from_json_str`). Multiple files can be merged by combining
//! their entity slices before construction.

use cedar_policy::Entities;
use std::path::Path;

use crate::error::{CedarError, Result};

/// Load Cedar entities from a single JSON file.
///
/// The file must follow Cedar's entity JSON format:
/// `[{ "uid": ..., "attrs": {...}, "parents": [...] }, ...]`
pub fn load_entities(path: &Path) -> Result<Entities> {
    let src = std::fs::read_to_string(path).map_err(CedarError::Io)?;
    // Schema is not available yet at Phase 1; validation happens in Phase 2+.
    Entities::from_json_str(&src, None)
        .map_err(|e| CedarError::EntityParse(e.to_string()))
}

/// Load and merge entities from multiple JSON files.
///
/// Each file is loaded independently; if any file fails, the error is returned
/// immediately. Entity sets are merged using Cedar's `Entities::from_json_str`
/// on the concatenated JSON arrays.
pub fn load_entities_from_files(paths: &[impl AsRef<Path>]) -> Result<Entities> {
    let mut all_entities: Vec<serde_json::Value> = Vec::new();
    for path in paths {
        let src = std::fs::read_to_string(path.as_ref()).map_err(CedarError::Io)?;
        let parsed: serde_json::Value = serde_json::from_str(&src)
            .map_err(|e| CedarError::EntityParse(format!("JSON parse error in {}: {e}", path.as_ref().display())))?;
        let arr = parsed
            .as_array()
            .ok_or_else(|| CedarError::EntityParse(format!(
                "entity file {} must contain a JSON array at the top level",
                path.as_ref().display()
            )))?;
        all_entities.extend(arr.iter().cloned());
    }
    let merged_json = serde_json::to_string(&all_entities)
        .map_err(|e| CedarError::EntityParse(e.to_string()))?;
    Entities::from_json_str(&merged_json, None)
        .map_err(|e| CedarError::EntityParse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_tmp(name: &str, src: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nono-cedar-entities-test-{name}.json"));
        let mut f = std::fs::File::create(&path).expect("create tmp file");
        f.write_all(src.as_bytes()).expect("write tmp file");
        path
    }

    #[test]
    fn empty_entity_list_loads() {
        let path = write_tmp("empty", "[]");
        let entities = load_entities(&path).expect("empty array is valid");
        // Empty Entities: no panic, clean result.
        let _ = entities;
    }

    #[test]
    fn single_entity_loads() {
        let path = write_tmp(
            "single",
            r#"[
              {
                "uid": { "type": "nono::User", "id": "alice" },
                "attrs": { "os_username": "alice", "groups": [] },
                "parents": []
              }
            ]"#,
        );
        load_entities(&path).expect("single valid entity should load");
    }

    #[test]
    fn invalid_json_returns_entity_parse_error() {
        let path = write_tmp("bad_json", "{ not json }");
        let err = load_entities(&path).expect_err("bad JSON should fail");
        assert!(
            matches!(err, CedarError::EntityParse(_)),
            "expected EntityParse, got {err:?}"
        );
    }

    #[test]
    fn non_array_top_level_is_rejected_on_merge() {
        let path = write_tmp("not_array", r#"{"uid": "foo"}"#);
        let err = load_entities_from_files(&[&path]).expect_err("non-array should fail");
        assert!(matches!(err, CedarError::EntityParse(_)));
    }

    #[test]
    fn nonexistent_file_returns_io_error() {
        let err =
            load_entities(std::path::Path::new("/nonexistent/entities.json"))
                .expect_err("missing file should fail");
        assert!(matches!(err, CedarError::Io(_)));
    }

    #[test]
    fn multiple_entity_files_merge() {
        let f1 = write_tmp(
            "merge1",
            r#"[{"uid":{"type":"nono::User","id":"alice"},"attrs":{"os_username":"alice","groups":[]},"parents":[]}]"#,
        );
        let f2 = write_tmp(
            "merge2",
            r#"[{"uid":{"type":"nono::User","id":"bob"},"attrs":{"os_username":"bob","groups":[]},"parents":[]}]"#,
        );
        // Should merge two separate entity files without error.
        load_entities_from_files(&[&f1, &f2]).expect("merge should succeed");
    }
}
