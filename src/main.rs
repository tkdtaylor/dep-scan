mod cache;
mod cli;
mod config;
mod osv;
mod policy;
mod registry;
mod types;
mod typosquat;

use std::path::Path;
use std::process;

use anyhow::{Context, Result};
use chrono::{TimeDelta, Utc};
use clap::Parser;
use serde::Serialize;

use cache::Cache;
use cli::{Cli, Command, ConfigAction};
use config::Config;
use osv::{OsvClient, registry_to_ecosystem};
use policy::age::AgePolicy;
use policy::dependency_confusion::DependencyConfusionPolicy;
use policy::install_script::InstallScriptPolicy;
use policy::maintainer::MaintainerChangePolicy;
use policy::typosquatting::TyposquattingPolicy;
use policy::vulnerability::VulnerabilityPolicy;
use policy::{Policy, PolicyDetail, aggregate_results};
use registry::crates::CratesRegistry;
use registry::npm::NpmRegistry;
use registry::pypi::PyPiRegistry;
use registry::{Registry, RegistryType};
use types::ScanContext;

/// The result of checking a single package, suitable for JSON serialization.
#[derive(Debug, Serialize)]
struct CheckResult {
    package: String,
    version: String,
    registry: String,
    age_hours: Option<i64>,
    result: String,
    reason: Option<String>,
    policies: Vec<PolicyDetail>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let exit_code = match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:#}");
            2
        }
    };

    process::exit(exit_code);
}

async fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Check {
            packages,
            registry,
            json,
        } => run_check(cli.config.as_deref(), cli.verbose, packages, registry, json).await,
        Command::Install { packages: _ } => {
            println!("Install command is not yet implemented");
            Ok(0)
        }
        Command::Config { action } => {
            run_config(cli.config.as_deref(), action)?;
            Ok(0)
        }
    }
}

fn run_config(config_path: Option<&Path>, action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => {
            let config = Config::load(config_path)?;
            let toml_str = config.to_toml_string()?;
            println!("{toml_str}");
        }
        ConfigAction::Init => {
            let target = Path::new(".dep-scan.toml");
            Config::write_default(target)?;
            println!("Created {}", target.display());
        }
    }
    Ok(())
}

async fn run_check(
    config_path: Option<&Path>,
    verbose: bool,
    packages: Vec<String>,
    registry_flag: Option<String>,
    json_output: bool,
) -> Result<i32> {
    let config = Config::load(config_path)?;

    // Parse registry type (default to npm)
    let reg_type = match registry_flag.as_deref() {
        Some(s) => s
            .parse::<RegistryType>()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        None => RegistryType::Npm,
    };

    // Open cache
    let cache_path = config.resolve_cache_path();
    if let Some(parent) = cache_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create cache directory: {}", parent.display()))?;
    }
    let cache = Cache::new(&cache_path)
        .with_context(|| format!("Failed to open cache at {}", cache_path.display()))?;

    // Build policy list from config
    let mut policies: Vec<Box<dyn Policy>> = Vec::new();
    if config.policies.check_min_age {
        policies.push(Box::new(AgePolicy::new(TimeDelta::hours(
            config.min_package_age_hours as i64,
        ))));
    }
    if config.policies.check_install_scripts {
        policies.push(Box::new(InstallScriptPolicy));
    }
    if config.policies.check_maintainer_changes {
        policies.push(Box::new(MaintainerChangePolicy));
    }
    if config.policies.check_typosquatting {
        policies.push(Box::new(TyposquattingPolicy::with_defaults()));
    }
    if config.policies.check_vulnerabilities {
        policies.push(Box::new(VulnerabilityPolicy::new()));
    }
    // Dependency confusion check (disabled when internal_prefixes is empty)
    policies.push(Box::new(DependencyConfusionPolicy::new(
        config.dependency_confusion.internal_prefixes.clone(),
    )));

    // Create OSV client for vulnerability lookups
    let osv_client = if config.policies.check_vulnerabilities {
        Some(OsvClient::new(config.osv.osv_url.clone()))
    } else {
        None
    };

    // Check each package
    let mut results: Vec<CheckResult> = Vec::new();
    let mut has_failure = false;
    let mut has_error = false;

    for pkg_name in &packages {
        if verbose {
            eprintln!("Checking {pkg_name} on {reg_type}...");
        }

        // Check cache first
        let reg_str = reg_type.to_string();
        if let Ok(Some(entry)) = cache.lookup(pkg_name, "latest", &reg_str) {
            if verbose {
                eprintln!("Cache hit for {pkg_name}");
            }
            // Reconstruct result from cache
            let cached_result = entry.result.clone();
            let is_failure = cached_result == "block" || cached_result == "warn";
            if is_failure {
                has_failure = true;
            }
            results.push(CheckResult {
                package: pkg_name.clone(),
                version: "cached".to_string(),
                registry: reg_str.clone(),
                age_hours: None,
                result: cached_result,
                reason: Some("cached result".to_string()),
                policies: vec![],
            });
            continue;
        }

        // Query registry
        let metadata = match reg_type {
            RegistryType::Npm => {
                let client = NpmRegistry::new(config.registries.npm_url.clone());
                client.get_metadata(pkg_name, None).await
            }
            RegistryType::PyPI => {
                let client = PyPiRegistry::new(config.registries.pypi_url.clone());
                client.get_metadata(pkg_name, None).await
            }
            RegistryType::Crates => {
                let client = CratesRegistry::new(config.registries.crates_url.clone());
                client.get_metadata(pkg_name, None).await
            }
            RegistryType::Go => Err(registry::RegistryError::NetworkError(
                "Go module proxy support coming in next release".to_string(),
            )),
        };

        let metadata = match metadata {
            Ok(m) => m,
            Err(e) => {
                has_error = true;
                results.push(CheckResult {
                    package: pkg_name.clone(),
                    version: "unknown".to_string(),
                    registry: reg_str.clone(),
                    age_hours: None,
                    result: "error".to_string(),
                    reason: Some(format!("{e}")),
                    policies: vec![],
                });
                continue;
            }
        };

        // Calculate age
        let age_hours = metadata.published_at.map(|t| (Utc::now() - t).num_hours());

        // Fetch install scripts (npm only; PyPI does not expose them via JSON API)
        let install_scripts = if config.policies.check_install_scripts
            && reg_type == RegistryType::Npm
        {
            let client = NpmRegistry::new(config.registries.npm_url.clone());
            match client.get_install_scripts(pkg_name, None).await {
                Ok(scripts) => scripts,
                Err(e) => {
                    if verbose {
                        eprintln!("Warning: failed to fetch install scripts for {pkg_name}: {e}");
                    }
                    vec![]
                }
            }
        } else {
            vec![]
        };

        // Fetch previous maintainers from cache if maintainer change checks are enabled
        let previous_maintainers = if config.policies.check_maintainer_changes {
            cache
                .get_previous_maintainers(pkg_name, &reg_str)
                .unwrap_or(None)
        } else {
            None
        };

        // Build scan context and enrich
        let mut ctx = ScanContext::from_metadata(metadata.clone());
        ctx.install_scripts = install_scripts;
        ctx.previous_maintainers = previous_maintainers;

        // Query OSV for known vulnerabilities
        if let Some(ref osv) = osv_client {
            let ecosystem = registry_to_ecosystem(&reg_type);
            match osv
                .query(&metadata.name, &metadata.version, ecosystem)
                .await
            {
                Ok(vulns) => {
                    ctx.vulnerabilities = vulns;
                }
                Err(e) => {
                    if verbose {
                        eprintln!("Warning: OSV lookup failed for {pkg_name}: {e:#}");
                    }
                }
            }
        }

        // Evaluate all policies
        let mut policy_details: Vec<PolicyDetail> = Vec::new();
        for p in &policies {
            let policy_result = p.evaluate(&ctx);
            policy_details.push(PolicyDetail::from_result(p.name(), &policy_result));
        }

        // Aggregate results
        let (result_str, reason) = aggregate_results(&policy_details);

        if result_str == "block" || result_str == "warn" {
            has_failure = true;
        }

        // Record current maintainers in cache for future comparisons
        if config.policies.check_maintainer_changes {
            let _ = cache.record_maintainers(pkg_name, &reg_str, &metadata.maintainers);
        }

        // Store in cache using "latest" as version key to match lookup
        let _ = cache.insert(pkg_name, "latest", &reg_str, &result_str);

        results.push(CheckResult {
            package: metadata.name.clone(),
            version: metadata.version.clone(),
            registry: reg_str,
            age_hours,
            result: result_str,
            reason,
            policies: policy_details,
        });
    }

    // Output results
    if json_output {
        let json = serde_json::to_string_pretty(&results)
            .context("Failed to serialize results to JSON")?;
        println!("{json}");
    } else {
        // Human-readable table
        println!("{:<20} {:<12} {:<10} Result", "Package", "Version", "Age");
        for r in &results {
            let age_display = match r.age_hours {
                Some(h) => format!("{h}h"),
                None => "-".to_string(),
            };
            let result_display = match r.result.as_str() {
                "pass" => "pass".to_string(),
                "warn" => format!("WARN: {}", r.reason.as_deref().unwrap_or("unknown warning")),
                "block" => {
                    format!("BLOCK: {}", r.reason.as_deref().unwrap_or("unknown reason"))
                }
                "error" => {
                    format!("ERROR: {}", r.reason.as_deref().unwrap_or("unknown error"))
                }
                other => other.to_string(),
            };
            println!(
                "{:<20} {:<12} {:<10} {}",
                r.package, r.version, age_display, result_display
            );

            // Per-policy breakdown
            for pd in &r.policies {
                let detail_display = match pd.result.as_str() {
                    "pass" => format!("  {}: pass", pd.policy_name),
                    "warn" => format!(
                        "  {}: WARN — {}",
                        pd.policy_name,
                        pd.reason.as_deref().unwrap_or("unknown")
                    ),
                    "block" => format!(
                        "  {}: BLOCK — {}",
                        pd.policy_name,
                        pd.reason.as_deref().unwrap_or("unknown")
                    ),
                    _ => format!("  {}: {}", pd.policy_name, pd.result),
                };
                println!("{detail_display}");
            }
        }
    }

    // Determine exit code
    if has_error {
        Ok(2)
    } else if has_failure {
        Ok(1)
    } else {
        Ok(0)
    }
}
