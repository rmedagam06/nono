//! Handlers for the `nono cedar` subcommand family (Phase 5/6 diagnostics).
//!
//! - `nono cedar validate` — parse and schema-validate Cedar policy files.
//! - `nono cedar eval`     — evaluate a Cedar policy against a single resource.
//! - `nono cedar explain`  — explain Cedar decisions for a simulated capability set.

use std::path::PathBuf;

use nono::{NonoError, Result};

use crate::cli::{CedarArgs, CedarCommands};

pub(crate) fn run_cedar(args: CedarArgs) -> Result<()> {
    match args.command {
        CedarCommands::Validate(a) => run_validate(a),
        CedarCommands::Eval(a) => run_eval(a),
        CedarCommands::Explain(a) => run_explain(a),
    }
}

// ── validate ──────────────────────────────────────────────────────────────

fn run_validate(args: crate::cli::CedarValidateArgs) -> Result<()> {
    #[cfg(feature = "cedar")]
    {
        use nono_cedar::{load_policy_set_from_files, nono_schema};

        let policy_files: Vec<PathBuf> = args.policy.into_iter().collect();
        if policy_files.is_empty() {
            return Err(NonoError::ConfigParse(
                "nono cedar validate: at least one --policy file is required".into(),
            ));
        }
        let _ = load_policy_set_from_files(&policy_files)
            .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;
        if !args.no_schema {
            let _ = nono_schema().map_err(|e| NonoError::CedarPolicy(e.to_string()))?;
        }
        eprintln!(
            "  [nono cedar] {} policy file(s) valid{}",
            policy_files.len(),
            if args.no_schema { "" } else { " (schema validated)" }
        );
        Ok(())
    }
    #[cfg(not(feature = "cedar"))]
    {
        let _ = args;
        Err(NonoError::CedarPolicy(
            "Cedar support not compiled in; rebuild with --features cedar".into(),
        ))
    }
}

// ── eval ──────────────────────────────────────────────────────────────────

fn run_eval(args: crate::cli::CedarEvalArgs) -> Result<()> {
    #[cfg(feature = "cedar")]
    {
        use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability};
        use nono_cedar::{
            CedarPolicyEngine, EvalRequest, NonoEntityBuilder, NonoSession,
            fs_eval_requests, load_policy_set_from_files, merge_entity_json_with_files,
            nono_schema,
        };

        let policy_files: Vec<PathBuf> = args.policy.into_iter().collect();
        if policy_files.is_empty() {
            return Err(NonoError::ConfigParse(
                "nono cedar eval: at least one --policy file is required".into(),
            ));
        }
        let resource = args.resource.ok_or_else(|| {
            NonoError::ConfigParse(
                "nono cedar eval: --resource <PATH> is required".into(),
            )
        })?;
        let action = args.action.unwrap_or_else(|| "read_dir".to_string());

        let policy_set = load_policy_set_from_files(&policy_files)
            .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;
        let schema = nono_schema().map_err(|e| NonoError::CedarPolicy(e.to_string()))?;

        let session_id = "cedar-eval-session";
        let os_username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".into());
        let profile = args.profile.unwrap_or_default();
        let workdir = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let os_name = if cfg!(target_os = "macos") { "macos" } else { "linux" };

        let builder = NonoEntityBuilder::new(
            &os_username,
            session_id,
            &profile,
            &workdir,
            os_name,
            &[],
            &[],
        )
        .add_directory_resource(&resource, false);

        let base_json = builder
            .to_json_string()
            .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;
        let entity_files: Vec<PathBuf> = args.entities.into_iter().collect();
        let entities = merge_entity_json_with_files(&base_json, &entity_files)
            .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;

        let engine = CedarPolicyEngine::new(policy_set, entities, Some(schema));
        let nono_session = NonoSession::new(session_id, &os_username, &profile, &workdir, os_name);

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from(&resource),
            resolved: PathBuf::from(&resource),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        let requests = fs_eval_requests(caps.fs_capabilities(), 0);
        let matching: Vec<&EvalRequest> =
            requests.iter().filter(|r| r.action == action).collect();

        if matching.is_empty() {
            return Err(NonoError::ConfigParse(format!(
                "no Cedar request found for action '{action}'; \
                 valid actions: read_file, write_file, read_dir, write_dir"
            )));
        }

        let decision = engine
            .evaluate_one(matching[0], &nono_session)
            .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;

        println!("resource : {resource}");
        println!("action   : {action}");
        println!(
            "decision : {}",
            match &decision.outcome {
                nono_cedar::DecisionOutcome::Permit => "PERMIT",
                nono_cedar::DecisionOutcome::Deny {
                    is_explicit_forbid: true,
                } => "DENY (explicit forbid)",
                nono_cedar::DecisionOutcome::Deny {
                    is_explicit_forbid: false,
                } => "DENY (implicit — no permit matched)",
            }
        );
        if !decision.user_message.is_empty() {
            println!("message  : {}", decision.user_message);
        }
        if !decision.reasons.is_empty() {
            println!("policies : {}", decision.reasons.join(", "));
        }
        Ok(())
    }
    #[cfg(not(feature = "cedar"))]
    {
        let _ = args;
        Err(NonoError::CedarPolicy(
            "Cedar support not compiled in; rebuild with --features cedar".into(),
        ))
    }
}

// ── explain ───────────────────────────────────────────────────────────────

fn run_explain(args: crate::cli::CedarExplainArgs) -> Result<()> {
    #[cfg(feature = "cedar")]
    {
        use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability};
        use nono_cedar::{
            CedarCapabilityFilter, CedarPolicyEngine, FilterMode, NonoEntityBuilder, NonoSession,
            load_policy_set_from_files, merge_entity_json_with_files, nono_schema,
        };

        let policy_files: Vec<PathBuf> = args.policy.into_iter().collect();
        if policy_files.is_empty() {
            return Err(NonoError::ConfigParse(
                "nono cedar explain: at least one --policy file is required".into(),
            ));
        }
        if args.path.is_empty() {
            return Err(NonoError::ConfigParse(
                "nono cedar explain: at least one --path is required".into(),
            ));
        }

        let policy_set = load_policy_set_from_files(&policy_files)
            .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;
        let schema = nono_schema().map_err(|e| NonoError::CedarPolicy(e.to_string()))?;

        let session_id = "cedar-explain-session";
        let os_username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".into());
        let profile = args.profile.unwrap_or_default();
        let workdir = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let os_name = if cfg!(target_os = "macos") { "macos" } else { "linux" };

        let mut builder = NonoEntityBuilder::new(
            &os_username,
            session_id,
            &profile,
            &workdir,
            os_name,
            &[],
            &[],
        );
        let mut caps = CapabilitySet::new();
        for path in &args.path {
            let path_str = path.to_string_lossy();
            builder = builder.add_directory_resource(&path_str, false);
            caps.add_fs(FsCapability {
                original: path.clone(),
                resolved: path.clone(),
                access: AccessMode::ReadWrite,
                is_file: false,
                source: CapabilitySource::User,
            });
        }

        let base_json = builder
            .to_json_string()
            .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;
        let entity_files: Vec<PathBuf> = args.entities.into_iter().collect();
        let entities = merge_entity_json_with_files(&base_json, &entity_files)
            .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;

        let engine = CedarPolicyEngine::new(policy_set, entities, Some(schema));
        let nono_session = NonoSession::new(session_id, &os_username, &profile, &workdir, os_name);

        let decisions = engine
            .evaluate_capability_set(&caps, &nono_session)
            .map_err(|e| NonoError::CedarPolicy(e.to_string()))?;

        let mode = if args.strict {
            FilterMode::Strict
        } else {
            FilterMode::Narrow
        };
        let result = CedarCapabilityFilter::apply(&decisions, &mut caps, mode)
            .map_err(|e| NonoError::CedarDenied { reason: e.to_string() })?;

        println!(
            "Cedar explain: {} path(s), {} removed, {} downgraded",
            args.path.len(),
            result.removed_count,
            result.downgraded_count,
        );
        for denied in &result.denied {
            let kind = if denied.is_explicit_forbid {
                "FORBID"
            } else {
                "implicit deny"
            };
            println!(
                "  [{}] cap_index={} — {}",
                kind, denied.cap_index, denied.user_message
            );
        }
        if result.denied.is_empty() {
            println!("  All paths permitted by Cedar policy.");
        }
        Ok(())
    }
    #[cfg(not(feature = "cedar"))]
    {
        let _ = args;
        Err(NonoError::CedarPolicy(
            "Cedar support not compiled in; rebuild with --features cedar".into(),
        ))
    }
}
