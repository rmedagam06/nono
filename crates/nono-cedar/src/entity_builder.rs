//! Programmatic Cedar entity construction from NONO runtime types.
//!
//! `NonoEntityBuilder` converts nono's runtime context (profile name, session
//! ID, OS username, OS groups, working directory, platform) into the Cedar
//! entity set that the authorization engine evaluates requests against.
//!
//! File and network resource entities are added separately — see
//! `add_file_resource`, `add_directory_resource`, `add_network_endpoint`,
//! `add_unix_socket`.

use cedar_policy::Entities;
use serde_json::{Value, json};

use crate::error::{CedarError, Result};

/// Builder for the Cedar entity set used during a single NONO session.
///
/// Entities are accumulated as JSON values and compiled into a Cedar
/// `Entities` set when `build()` is called. This matches Cedar's standard
/// entity JSON format so the result can be inspected or serialized for
/// debugging.
pub struct NonoEntityBuilder {
    entities: Vec<Value>,
}

impl NonoEntityBuilder {
    /// Create a new builder for a NONO session.
    ///
    /// - `os_username` — the OS user running the sandboxed command (e.g. `"alice"`)
    /// - `session_id` — stable identifier for this run (e.g. `"sess-alice-001"`)
    /// - `profile` — the nono profile name (e.g. `"python-dev"`)
    /// - `workdir` — the working directory path (e.g. `"/home/alice/code"`)
    /// - `os` — `"linux"` or `"macos"`
    /// - `groups` — OS groups the user belongs to
    /// - `roles` — Cedar role names to assign to the session (e.g. `["developer"]`)
    #[must_use]
    pub fn new(
        os_username: &str,
        session_id: &str,
        profile: &str,
        workdir: &str,
        os: &str,
        groups: &[&str],
        roles: &[&str],
    ) -> Self {
        let mut entities: Vec<Value> = Vec::new();

        // Emit one nono::Role entity per role name.
        for role in roles {
            entities.push(json!({
                "uid": { "type": "nono::Role", "id": role },
                "attrs": {},
                "parents": []
            }));
        }

        // Emit the nono::User entity.
        let group_strs: Vec<Value> = groups.iter().map(|g| json!(g)).collect();
        entities.push(json!({
            "uid": { "type": "nono::User", "id": os_username },
            "attrs": {
                "os_username": os_username,
                "groups": group_strs
            },
            "parents": []
        }));

        // Emit the nono::Session entity.
        let role_refs: Vec<Value> = roles
            .iter()
            .map(|r| json!({ "__entity": { "type": "nono::Role", "id": r } }))
            .collect();
        entities.push(json!({
            "uid": { "type": "nono::Session", "id": session_id },
            "attrs": {
                "principal": { "__entity": { "type": "nono::User", "id": os_username } },
                "profile":  profile,
                "workdir":  workdir,
                "os":       os,
                "roles":    role_refs
            },
            "parents": []
        }));

        Self { entities }
    }

    /// Add a `nono::File` resource entity.
    ///
    /// `sensitive` marks files like `/etc/passwd` or SSH keys; policies can
    /// use this attribute to write general-purpose deny rules.
    #[must_use]
    pub fn add_file_resource(mut self, path: &str, sensitive: bool, owner: &str) -> Self {
        self.entities.push(json!({
            "uid": { "type": "nono::File", "id": path },
            "attrs": { "path": path, "sensitive": sensitive, "owner": owner },
            "parents": []
        }));
        self
    }

    /// Add a `nono::Directory` resource entity.
    #[must_use]
    pub fn add_directory_resource(mut self, path: &str, sensitive: bool) -> Self {
        self.entities.push(json!({
            "uid": { "type": "nono::Directory", "id": path },
            "attrs": { "path": path, "sensitive": sensitive },
            "parents": []
        }));
        self
    }

    /// Add a `nono::NetworkEndpoint` resource entity.
    ///
    /// `endpoint_id` should be `"host:port"` (e.g. `"api.anthropic.com:443"`).
    #[must_use]
    pub fn add_network_endpoint(
        mut self,
        endpoint_id: &str,
        host: &str,
        port: i64,
        protocol: &str,
    ) -> Self {
        self.entities.push(json!({
            "uid": { "type": "nono::NetworkEndpoint", "id": endpoint_id },
            "attrs": { "host": host, "port": port, "protocol": protocol },
            "parents": []
        }));
        self
    }

    /// Add a `nono::UnixSocket` resource entity.
    #[must_use]
    pub fn add_unix_socket(mut self, path: &str) -> Self {
        self.entities.push(json!({
            "uid": { "type": "nono::UnixSocket", "id": path },
            "attrs": { "path": path },
            "parents": []
        }));
        self
    }

    /// Compile the accumulated entities into a Cedar `Entities` set.
    ///
    /// No schema validation is applied here; validation happens in
    /// `CedarPolicyEngine::new()` where the schema is available.
    pub fn build(self) -> Result<Entities> {
        let json = serde_json::to_string(&self.entities)
            .map_err(|e| CedarError::EntityParse(e.to_string()))?;
        Entities::from_json_str(&json, None)
            .map_err(|e| CedarError::EntityParse(e.to_string()))
    }

    /// Serialize the entity set to a JSON string for debugging or snapshot tests.
    pub fn to_json_string(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.entities)
            .map_err(|e| CedarError::EntityParse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice_builder() -> NonoEntityBuilder {
        NonoEntityBuilder::new(
            "alice",
            "sess-alice-dev-001",
            "python-dev",
            "/home/alice/code",
            "linux",
            &["developers", "wheel"],
            &["developer"],
        )
    }

    #[test]
    fn basic_session_builds_without_error() {
        alice_builder().build().expect("basic session should build");
    }

    #[test]
    fn json_contains_nono_session_type() {
        let builder = alice_builder();
        let json = builder.to_json_string().expect("serialize");
        assert!(
            json.contains("nono::Session"),
            "JSON must reference nono::Session entity type"
        );
    }

    #[test]
    fn json_contains_nono_user_type() {
        let json = alice_builder().to_json_string().expect("serialize");
        assert!(json.contains("nono::User"));
    }

    #[test]
    fn json_contains_nono_role_type() {
        let json = alice_builder().to_json_string().expect("serialize");
        assert!(json.contains("nono::Role"));
    }

    #[test]
    fn file_resource_appears_in_json() {
        let json = alice_builder()
            .add_file_resource("/etc/passwd", true, "root")
            .to_json_string()
            .expect("serialize");
        assert!(json.contains("nono::File"));
        assert!(json.contains("/etc/passwd"));
    }

    #[test]
    fn directory_resource_appears_in_json() {
        let json = alice_builder()
            .add_directory_resource("/home/alice/code", false)
            .to_json_string()
            .expect("serialize");
        assert!(json.contains("nono::Directory"));
        assert!(json.contains("/home/alice/code"));
    }

    #[test]
    fn network_endpoint_appears_in_json() {
        let json = alice_builder()
            .add_network_endpoint("api.anthropic.com:443", "api.anthropic.com", 443, "tcp")
            .to_json_string()
            .expect("serialize");
        assert!(json.contains("nono::NetworkEndpoint"));
        assert!(json.contains("api.anthropic.com:443"));
    }

    #[test]
    fn unix_socket_appears_in_json() {
        let json = alice_builder()
            .add_unix_socket("/run/docker.sock")
            .to_json_string()
            .expect("serialize");
        assert!(json.contains("nono::UnixSocket"));
        assert!(json.contains("/run/docker.sock"));
    }

    #[test]
    fn session_with_no_roles_builds() {
        NonoEntityBuilder::new(
            "bob",
            "sess-bob-001",
            "default",
            "/home/bob",
            "linux",
            &[],
            &[],
        )
        .build()
        .expect("session with no roles should build");
    }

    #[test]
    fn session_with_multiple_roles_builds() {
        NonoEntityBuilder::new(
            "alice",
            "sess-001",
            "dev",
            "/home/alice",
            "macos",
            &["staff"],
            &["developer", "analyst"],
        )
        .build()
        .expect("multiple roles should build");
    }
}
