//! Runtime session context passed to the Cedar authorization engine.
//!
//! `NonoSession` captures the fields needed to build the Cedar principal
//! entity and the request context for every capability evaluation.

/// Runtime context for a single NONO invocation.
///
/// This is the Cedar principal. The engine creates a `nono::Session` entity
/// from these fields (via `NonoEntityBuilder`) and uses `session_id` as the
/// `nono::Session` entity UID in every Cedar request.
#[derive(Debug, Clone)]
pub struct NonoSession {
    /// Stable identifier for this run (e.g. `"sess-alice-dev-001"`).
    pub session_id: String,
    /// OS user running the sandboxed command (e.g. `"alice"`).
    pub os_username: String,
    /// The nono profile in use (e.g. `"python-dev"`).
    pub profile: String,
    /// The working directory path (e.g. `"/home/alice/code"`).
    pub workdir: String,
    /// `"linux"` or `"macos"` — matched against Cedar context `os` attribute.
    pub os: String,
    /// OS groups the user belongs to.
    pub groups: Vec<String>,
    /// Cedar role names assigned to this session.
    pub roles: Vec<String>,
}

impl NonoSession {
    /// Construct a session with no groups or roles assigned.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        os_username: impl Into<String>,
        profile: impl Into<String>,
        workdir: impl Into<String>,
        os: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            os_username: os_username.into(),
            profile: profile.into(),
            workdir: workdir.into(),
            os: os.into(),
            groups: Vec::new(),
            roles: Vec::new(),
        }
    }

    /// Add OS groups to the session (builder-style).
    #[must_use]
    pub fn with_groups(mut self, groups: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.groups = groups.into_iter().map(Into::into).collect();
        self
    }

    /// Add Cedar roles to the session (builder-style).
    #[must_use]
    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_session_fields_roundtrip() {
        let sess = NonoSession::new("sess-001", "alice", "dev", "/home/alice", "linux")
            .with_groups(["staff", "wheel"])
            .with_roles(["developer"]);

        assert_eq!(sess.session_id, "sess-001");
        assert_eq!(sess.os_username, "alice");
        assert_eq!(sess.profile, "dev");
        assert_eq!(sess.workdir, "/home/alice");
        assert_eq!(sess.os, "linux");
        assert_eq!(sess.groups, ["staff", "wheel"]);
        assert_eq!(sess.roles, ["developer"]);
    }

    #[test]
    fn session_with_no_groups_or_roles() {
        let sess = NonoSession::new("sess-002", "bob", "default", "/home/bob", "macos");
        assert!(sess.groups.is_empty());
        assert!(sess.roles.is_empty());
    }
}
