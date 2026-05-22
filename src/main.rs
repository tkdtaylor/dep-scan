mod cache;
mod cli;
mod config;
mod lockfile;
mod osv;
mod policy;
mod registry;
mod signed_note;
mod sigstore_verify;
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
use policy::go_sumdb::{GoSumDbPolicy, RealSumDbVerifier};
use policy::install_script::InstallScriptPolicy;
use policy::maintainer::MaintainerChangePolicy;
use policy::npm_provenance::{NpmProvenancePolicy, extract_provenance_identity};
use policy::obfuscation::ObfuscationPolicy;
use policy::popularity::PopularityPolicy;
use policy::pypi_provenance::{PyPiProvenancePolicy, extract_pypi_provenance_identity};
use policy::typosquatting::TyposquattingPolicy;
use policy::vulnerability::VulnerabilityPolicy;
use policy::{Policy, PolicyDetail, aggregate_results};
use registry::crates::CratesRegistry;
use registry::go::GoRegistry;
use registry::go_sumdb::SumDbClient;
use registry::npm::NpmRegistry;
use registry::npm_attestation::NpmAttestationClient;
use registry::pypi::PyPiRegistry;
use registry::pypi_provenance::PyPiProvenanceClient;
use registry::{Registry, RegistryType};
use sigstore_verify::RealSigstoreVerifier;
use types::ScanContext;

/// Decision returned by `verify_hash` for a cache-hit entry.
#[derive(Debug, PartialEq)]
enum HashVerifyDecision {
    /// Both hashes match — the cached verdict is safe to reuse.
    HonorCache,
    /// The hashes differ, a hash is missing from either side, or the registry
    /// fetch failed — the cache row must be invalidated and the package
    /// re-scanned.
    Reverify,
}

/// Decide whether to honor a cached verdict based on the content hash pair.
///
/// Implements the decision table from ADR 003 § "Secure default":
///
/// | Cached hash | Registry hash | Decision      |
/// |-------------|---------------|---------------|
/// | Some(a)     | Some(a)       | HonorCache    |
/// | Some(a)     | Some(b)       | Reverify      |
/// | Some(a)     | None          | Reverify      |
/// | None        | Some(b)       | Reverify      |
/// | None        | None          | Reverify (fail-closed) |
fn verify_hash(cached: Option<&str>, registry: Option<&str>) -> HashVerifyDecision {
    match (cached, registry) {
        (Some(c), Some(r)) if c == r => HashVerifyDecision::HonorCache,
        _ => HashVerifyDecision::Reverify,
    }
}

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
            lockfile,
            lockfile_type,
        } => {
            run_check(
                cli.config.as_deref(),
                cli.verbose,
                packages,
                registry,
                json,
                lockfile,
                lockfile_type,
            )
            .await
        }
        Command::Install {
            packages,
            registry,
            force,
        } => {
            run_install(
                cli.config.as_deref(),
                cli.verbose,
                packages,
                registry,
                force,
            )
            .await
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
    lockfile_path: Option<std::path::PathBuf>,
    lockfile_type_str: Option<String>,
) -> Result<i32> {
    let config = Config::load(config_path)?;

    // Parse lockfile if provided
    let mut all_packages = packages;
    let mut lockfile_registry = None;
    if let Some(ref lf_path) = lockfile_path {
        let format = lockfile_type_str
            .as_deref()
            .map(lockfile::parse_format_type)
            .transpose()?;
        let deps = lockfile::parse(lf_path, format)?;
        if !deps.is_empty() {
            lockfile_registry = Some(deps[0].registry);
        }
        for dep in deps {
            all_packages.push(dep.name);
        }
    }

    // Parse registry type (default to npm, but prefer lockfile-inferred registry)
    let reg_type = match registry_flag.as_deref() {
        Some(s) => s
            .parse::<RegistryType>()
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        None => lockfile_registry.unwrap_or(RegistryType::Npm),
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
    if config.policies.check_obfuscation {
        policies.push(Box::new(ObfuscationPolicy));
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
    // Popularity check (always enabled — warns only, never blocks)
    policies.push(Box::new(PopularityPolicy::new(
        config.popularity.min_downloads,
    )));
    // Dependency confusion check (disabled when internal_prefixes is empty)
    policies.push(Box::new(DependencyConfusionPolicy::new(
        config.dependency_confusion.internal_prefixes.clone(),
    )));

    // npm provenance attestation check (npm only; wired per-package in the scan loop)
    // The policy is added to the pipeline when check_npm_provenance is enabled.
    // Non-npm packages get npm_attestations = None, so the policy returns Pass for them.
    if config.policies.check_npm_provenance {
        use std::sync::Arc;
        policies.push(Box::new(NpmProvenancePolicy::new(
            config.policies.require_npm_provenance,
            Arc::new(RealSigstoreVerifier),
        )));
    }

    // PyPI provenance attestation check (PyPI only; wired per-package in the scan loop).
    // Non-PyPI packages get pypi_attestation = None, so the policy returns Pass for them.
    if config.policies.check_pypi_provenance {
        use std::sync::Arc;
        policies.push(Box::new(PyPiProvenancePolicy::new(
            config.policies.require_pypi_provenance,
            Arc::new(RealSigstoreVerifier),
        )));
    }

    // Go checksum database signature verification (Go only; wired per-package in the scan loop).
    // Non-Go packages get go_sumdb_result = None, so the policy returns Pass for them.
    if config.policies.check_go_sumdb {
        use std::sync::Arc;
        policies.push(Box::new(GoSumDbPolicy::new(
            config.policies.require_go_sumdb,
            Arc::new(RealSumDbVerifier),
        )));
    }

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

    for pkg_name in &all_packages {
        if verbose {
            eprintln!("Checking {pkg_name} on {reg_type}...");
        }

        let reg_str = reg_type.to_string();

        // Fetch metadata from the registry.  This is shared between the
        // verification step (cache-hit) and the full scan path (cache-miss).
        let fetch_result = match reg_type {
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
            RegistryType::Go => {
                let client = GoRegistry::new(
                    config.registries.go_proxy_url.clone(),
                    config.registries.go_sum_db_url.clone(),
                );
                client.get_metadata(pkg_name, None).await
            }
        };

        // Check cache — if there is a hit, verify the content hash before honoring it.
        if let Ok(Some(entry)) = cache.lookup(pkg_name, "latest", &reg_str) {
            match &fetch_result {
                Ok(fresh_meta) => {
                    let decision = verify_hash(
                        entry.content_hash.as_deref(),
                        fresh_meta.content_hash.as_deref(),
                    );
                    if decision == HashVerifyDecision::HonorCache {
                        if verbose {
                            eprintln!("cache hit (verified) for {pkg_name}");
                        }
                        // Reconstruct result from cache — hash matches, verdict is trustworthy.
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
                    } else {
                        // Hash mismatch (or both None) — invalidate and fall through to re-scan.
                        eprintln!("cache hash mismatch for {pkg_name}; re-scanning");
                        let _ = cache.invalidate(pkg_name, "latest", &reg_str);
                        // `fetch_result` is already the fresh metadata; the full scan below
                        // will reuse it without making an extra network call.
                    }
                }
                Err(_) => {
                    // Registry fetch failed — cannot verify; invalidate and fall through to
                    // the error path below, which will surface the same error consistently.
                    eprintln!("cache hash mismatch for {pkg_name}; re-scanning");
                    let _ = cache.invalidate(pkg_name, "latest", &reg_str);
                }
            }
        }

        let mut metadata = match fetch_result {
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

        // Fetch npm provenance attestations (npm only).
        // A 404 from the endpoint → Ok(vec![]) → "no attestations" Warn path.
        // A network/parse error → surfaced as Block (fail-closed per ADR 003).
        let (npm_attestations, npm_attestation_fetch_error) =
            if config.policies.check_npm_provenance && reg_type == RegistryType::Npm {
                let att_client = NpmAttestationClient::new(config.registries.npm_url.clone());
                match att_client
                    .get_attestations(&metadata.name, &metadata.version)
                    .await
                {
                    Ok(bundles) => (Some(bundles), None),
                    Err(e) => (Some(vec![]), Some(e.to_string())),
                }
            } else {
                (None, None)
            };

        // Fetch PyPI PEP 740 provenance attestation (PyPI only).
        // Uses the PEP 691 Simple Index to discover the provenance URL for the
        // selected file (sdist preferred, else first wheel — same rule as task 029).
        // A missing provenance URL → Ok(None) → "no attestation" Warn path.
        // A server error → surfaced as Block (fail-closed).
        let (pypi_attestation, pypi_provenance_fetch_error) =
            if config.policies.check_pypi_provenance && reg_type == RegistryType::PyPI {
                let prov_client = PyPiProvenanceClient::new(config.registries.pypi_url.clone());
                // Identify the selected file using the Simple Index.
                match prov_client.fetch_simple_index(&metadata.name).await {
                    Ok(Some(files)) => {
                        // Select the file using the same rule as task 029.
                        match registry::pypi_provenance::PyPiProvenanceClient::select_file(&files) {
                            Some(selected_file) => {
                                match selected_file.provenance_url.as_deref() {
                                    None => (Some(None), None), // no provenance URL for this file
                                    Some(url) => {
                                        match prov_client.fetch_provenance_url(url).await {
                                            Ok(bundle) => (Some(bundle), None),
                                            Err(e) => (Some(None), Some(e.to_string())),
                                        }
                                    }
                                }
                            }
                            None => (Some(None), None), // no suitable file found
                        }
                    }
                    Ok(None) => (Some(None), None), // legacy mirror — degrade to Warn
                    Err(e) => (Some(None), Some(e.to_string())), // fail-closed
                }
            } else {
                (None, None)
            };

        // Fetch Go checksum database signed entry (Go only).
        // The sumdb URL is configurable for testing and private mirrors.
        // GOSUMDB=off from the environment is intentionally NOT consulted —
        // dep-scan uses check_go_sumdb in its own config (T-034-15).
        //
        // The h1: content hash is extracted from the GoSumDbResult here and
        // set on `metadata.content_hash` to avoid a duplicate HTTP call
        // (GoRegistry::get_metadata no longer fetches the sumdb directly).
        let go_sumdb_result = if config.policies.check_go_sumdb && reg_type == RegistryType::Go {
            // Fetch sumdb for Go modules when the policy is enabled.
            // The h1: content hash is extracted from the entry here and
            // set on `metadata.content_hash`.
            // GOSUMDB=off from the environment is intentionally NOT consulted (T-034-15).
            let sumdb_client = SumDbClient::new(config.registries.go_sum_db_url.clone());
            Some(
                sumdb_client
                    .fetch_entry(&metadata.name, &metadata.version)
                    .await,
            )
        } else {
            None
        };

        // Extract the h1: content hash from the Go sumdb entry (if available) and
        // populate `metadata.content_hash`.  This avoids the duplicate HTTP call
        // that would result from having `GoRegistry::get_metadata` also fetch the
        // sumdb (task 034 refactor).
        if let Some(crate::policy::go_sumdb::GoSumDbResult::Entry(ref entry)) = go_sumdb_result {
            metadata.content_hash = Some(entry.h1_module.clone());
        }

        // Build scan context and enrich
        let mut ctx = ScanContext::from_metadata(metadata.clone());
        ctx.install_scripts = install_scripts;
        ctx.previous_maintainers = previous_maintainers;
        ctx.npm_attestations = npm_attestations;
        ctx.npm_attestation_fetch_error = npm_attestation_fetch_error;
        ctx.pypi_attestation = pypi_attestation;
        ctx.pypi_provenance_fetch_error = pypi_provenance_fetch_error;
        ctx.go_sumdb_result = go_sumdb_result;

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

        // Extract and persist the provenance identity for npm packages that passed
        // attestation verification (task 032).  We run the verifier a second time
        // here to extract the identity without changing the Policy trait surface.
        if config.policies.check_npm_provenance
            && reg_type == RegistryType::Npm
            && result_str == "pass"
            && let (Some(bundles), Some(hash)) = (&ctx.npm_attestations, &metadata.content_hash)
            && let Some((algo, hex)) = hash.split_once(':')
        {
            ctx.provenance_identity =
                extract_provenance_identity(bundles, algo, hex, &RealSigstoreVerifier);
        }

        // Extract and persist the provenance identity for PyPI packages that passed
        // PEP 740 attestation verification (task 033).
        if config.policies.check_pypi_provenance
            && reg_type == RegistryType::PyPI
            && result_str == "pass"
            && let Some(Some(bundle)) = &ctx.pypi_attestation
            && let Some(hash) = &metadata.content_hash
            && let Some((algo, hex)) = hash.split_once(':')
        {
            ctx.provenance_identity =
                extract_pypi_provenance_identity(bundle, algo, hex, &RealSigstoreVerifier);
        }

        // Persist "sum.golang.org" as the provenance identity for Go modules that passed
        // sumdb signature verification (task 034).
        if config.policies.check_go_sumdb && reg_type == RegistryType::Go && result_str == "pass" {
            // Only set if the sumdb check actually contributed to the pass result.
            // If go_sumdb_result is Some(Entry(..)), the signature was verified.
            if let Some(crate::policy::go_sumdb::GoSumDbResult::Entry(_)) = &ctx.go_sumdb_result {
                ctx.provenance_identity = Some("sum.golang.org".to_string());
            }
        }

        // Record current maintainers in cache for future comparisons
        if config.policies.check_maintainer_changes {
            let _ = cache.record_maintainers(pkg_name, &reg_str, &metadata.maintainers);
        }

        // Store in cache using "latest" as version key to match lookup
        let _ = cache.insert(
            pkg_name,
            "latest",
            &reg_str,
            &result_str,
            metadata.content_hash.as_deref(),
            ctx.provenance_identity.as_deref(),
        );

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

/// A RAII wrapper around a temporary requirements file.
///
/// The file is deleted when this struct is dropped, regardless of whether
/// pip succeeded, failed, or panicked.
struct TempReqFile {
    path: std::path::PathBuf,
}

impl TempReqFile {
    /// Create a new temp file in `std::env::temp_dir()` with a random suffix.
    fn create(contents: &str) -> Result<Self> {
        let suffix: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ (d.as_secs() << 32))
            .unwrap_or(12345);
        let path = std::env::temp_dir().join(format!("dep-scan-{suffix}.txt"));
        std::fs::write(&path, contents).with_context(|| {
            format!("Failed to write temp requirements file: {}", path.display())
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempReqFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A package triple: (name, version, content_hash).
type PkgTriple = (String, String, Option<String>);

/// Build pip `--require-hashes` requirements file contents from a list of
/// (name, version, content_hash) triples.
///
/// Returns `Ok(String)` with the file contents if every package has a
/// `sha256:`-prefixed hash. Returns `Err(String)` describing the first
/// problematic package if any hash is missing or uses a non-sha256 algorithm.
///
/// The format per line is:
/// ```text
/// <name>==<version> --hash=sha256:<hex>
/// ```
fn build_pip_requirements(packages: &[PkgTriple]) -> Result<String, String> {
    let mut lines = Vec::with_capacity(packages.len());
    for (name, version, hash_opt) in packages {
        match hash_opt.as_deref() {
            None => {
                return Err(format!("{name} has no verifiable hash"));
            }
            Some(h) => {
                // Validate algorithm prefix — only sha256 is accepted for pip.
                if !h.starts_with("sha256:") {
                    let algo = h.split(':').next().unwrap_or("unknown");
                    return Err(format!(
                        "{name} has unsupported hash algorithm '{algo}' (only sha256 is accepted for pip --require-hashes)"
                    ));
                }
                // Pass the full `sha256:<hex>` verbatim — pip accepts this format.
                lines.push(format!("{name}=={version} --hash={h}"));
            }
        }
    }
    Ok(lines.join("\n") + "\n")
}

async fn run_install(
    config_path: Option<&Path>,
    verbose: bool,
    packages: Vec<String>,
    registry_flag: String,
    force: bool,
) -> Result<i32> {
    // 1. Run the scan (reuse run_check logic)
    let scan_exit = run_check(
        config_path,
        verbose,
        packages.clone(),
        Some(registry_flag.clone()),
        false, // not JSON
        None,  // no lockfile
        None,  // no lockfile type
    )
    .await?;

    // 2. Check scan result
    if scan_exit == 1 && !force {
        eprintln!("\ndep-scan: blocked — resolve policy violations before installing");
        return Ok(1);
    }
    if scan_exit == 1 && force {
        eprintln!("\nWarning: proceeding with installation despite policy violations (--force)");
    }
    if scan_exit == 2 {
        eprintln!("\ndep-scan: scan failed with errors");
        return Ok(2);
    }

    // 3. Build and execute the package manager command
    let reg_type: RegistryType = registry_flag.parse().map_err(|e| anyhow::anyhow!("{e}"))?;

    // For PyPI: attempt --require-hashes passthrough.
    // Re-fetch metadata after the scan so we use the freshly-observed hash
    // (not a potentially-stale cached value), closing the TOCTOU window.
    if reg_type == RegistryType::PyPI {
        return run_pip_install(config_path, verbose, &packages, &registry_flag).await;
    }

    let (cmd, args) = match reg_type {
        RegistryType::Npm => ("npm", vec!["install".to_string()]),
        RegistryType::PyPI => unreachable!("PyPI handled above"),
        RegistryType::Crates => ("cargo", vec!["add".to_string()]),
        RegistryType::Go => ("go", vec!["get".to_string()]),
    };

    let mut full_args = args;
    full_args.extend(packages);

    if verbose {
        eprintln!("Running: {} {}", cmd, full_args.join(" "));
    }

    println!("\nInstalling via {cmd}...");

    let status = std::process::Command::new(cmd)
        .args(&full_args)
        .status()
        .with_context(|| format!("Failed to run '{cmd}'. Is it installed and in PATH?"))?;

    if status.success() {
        Ok(0)
    } else {
        Ok(status.code().unwrap_or(1))
    }
}

/// Execute `pip install` for a list of PyPI packages.
///
/// After the scan has passed (or been force-bypassed), re-fetches metadata for
/// each package and attempts to build a `--require-hashes` requirements file.
/// If every package has a `sha256:` hash, pip is invoked as:
///   `pip install --require-hashes -r <tempfile>`
/// If *any* package is missing a hash or has a non-sha256 hash, falls back to:
///   `pip install <packages>`
/// with a per-package stderr warning.
async fn run_pip_install(
    config_path: Option<&Path>,
    verbose: bool,
    packages: &[String],
    _registry_flag: &str,
) -> Result<i32> {
    let config = Config::load(config_path)?;

    // Re-fetch metadata for each package to get the freshly-observed hash.
    let mut triples: Vec<PkgTriple> = Vec::with_capacity(packages.len());
    let mut fallback_warnings: Vec<(String, String)> = Vec::new(); // (pkg, reason)

    for pkg_name in packages {
        let client = PyPiRegistry::new(config.registries.pypi_url.clone());
        match client.get_metadata(pkg_name, None).await {
            Ok(meta) => {
                let hash = meta.content_hash.clone();
                // Validate hash algorithm proactively so we can warn with the registry URL.
                if let Some(ref h) = hash {
                    if !h.starts_with("sha256:") {
                        let algo = h.split(':').next().unwrap_or("unknown");
                        fallback_warnings.push((
                            pkg_name.clone(),
                            format!("unsupported hash algorithm '{algo}' (only sha256 accepted for pip --require-hashes)"),
                        ));
                    }
                } else {
                    fallback_warnings.push((
                        pkg_name.clone(),
                        format!("no verifiable hash from {}", config.registries.pypi_url),
                    ));
                }
                triples.push((pkg_name.clone(), meta.version.clone(), hash));
            }
            Err(e) => {
                // Registry fetch error — fall back to plain install.
                fallback_warnings.push((pkg_name.clone(), format!("registry fetch failed: {e}")));
                triples.push((pkg_name.clone(), String::new(), None));
            }
        }
    }

    println!("\nInstalling via pip...");

    // If any package triggered a warning, fall back to plain pip install.
    if !fallback_warnings.is_empty() {
        for (pkg, reason) in &fallback_warnings {
            eprintln!(
                "warning: {pkg} has no verifiable hash from {}; pip will not verify integrity at download time",
                config.registries.pypi_url
            );
            if verbose {
                eprintln!("  reason: {reason}");
            }
        }
        // Plain fallback.
        let mut full_args = vec!["install".to_string()];
        full_args.extend(packages.iter().cloned());
        if verbose {
            eprintln!("Running: pip {}", full_args.join(" "));
        }
        let status = std::process::Command::new("pip")
            .args(&full_args)
            .status()
            .with_context(|| "Failed to run 'pip'. Is it installed and in PATH?")?;
        return if status.success() {
            Ok(0)
        } else {
            Ok(status.code().unwrap_or(1))
        };
    }

    // All packages have sha256 hashes — use --require-hashes.
    match build_pip_requirements(&triples) {
        Ok(contents) => {
            let temp_file = TempReqFile::create(&contents)?;
            let temp_path = temp_file.path().to_path_buf();

            if verbose {
                eprintln!(
                    "Running: pip install --require-hashes -r {}",
                    temp_path.display()
                );
            }

            let status = std::process::Command::new("pip")
                .args([
                    "install",
                    "--require-hashes",
                    "-r",
                    temp_path.to_str().unwrap_or(""),
                ])
                .status()
                .with_context(|| "Failed to run 'pip'. Is it installed and in PATH?")?;

            // `temp_file` is dropped here, which removes the temp file.
            drop(temp_file);

            if status.success() {
                Ok(0)
            } else {
                Ok(status.code().unwrap_or(1))
            }
        }
        Err(reason) => {
            // This path is a fallback safety net; the per-package check above
            // should already have caught all missing/non-sha256 hashes.
            eprintln!("warning: falling back to plain pip install: {reason}");
            let mut full_args = vec!["install".to_string()];
            full_args.extend(packages.iter().cloned());
            let status = std::process::Command::new("pip")
                .args(&full_args)
                .status()
                .with_context(|| "Failed to run 'pip'. Is it installed and in PATH?")?;
            if status.success() {
                Ok(0)
            } else {
                Ok(status.code().unwrap_or(1))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-030-01: Matching hashes → honor cache
    #[test]
    fn verify_hash_matching_hashes_honor_cache() {
        let decision = verify_hash(Some("sha256:aaaa"), Some("sha256:aaaa"));
        assert_eq!(
            decision,
            HashVerifyDecision::HonorCache,
            "matching hashes should produce HonorCache"
        );
    }

    // T-030-02: Mismatched hashes → reverify
    #[test]
    fn verify_hash_mismatched_hashes_reverify() {
        let decision = verify_hash(Some("sha256:aaaa"), Some("sha256:bbbb"));
        assert_eq!(
            decision,
            HashVerifyDecision::Reverify,
            "mismatched hashes should produce Reverify"
        );
    }

    // T-030-03: Legacy NULL cached hash → reverify
    #[test]
    fn verify_hash_legacy_null_cached_reverify() {
        let decision = verify_hash(None, Some("sha256:bbbb"));
        assert_eq!(
            decision,
            HashVerifyDecision::Reverify,
            "None cached hash (legacy row) should produce Reverify"
        );
    }

    // T-030-04: Registry stopped publishing digest → reverify
    #[test]
    fn verify_hash_registry_none_reverify() {
        let decision = verify_hash(Some("sha256:aaaa"), None);
        assert_eq!(
            decision,
            HashVerifyDecision::Reverify,
            "None registry hash should produce Reverify"
        );
    }

    // T-030-05: Both None → reverify (fail-closed)
    #[test]
    fn verify_hash_both_none_reverify_fail_closed() {
        let decision = verify_hash(None, None);
        assert_eq!(
            decision,
            HashVerifyDecision::Reverify,
            "both-None should produce Reverify (fail-closed)"
        );
    }

    // ── T-031 unit tests ─────────────────────────────────────────────────────

    // T-031-01: Build requirements file from metadata triples (all hashes present)
    #[test]
    fn build_pip_requirements_all_hashes_present() {
        let packages: Vec<PkgTriple> = vec![
            (
                "requests".to_string(),
                "2.31.0".to_string(),
                Some("sha256:aaaa".to_string()),
            ),
            (
                "urllib3".to_string(),
                "2.0.7".to_string(),
                Some("sha256:bbbb".to_string()),
            ),
        ];
        let result = build_pip_requirements(&packages);
        assert!(result.is_ok(), "expected Ok, got Err: {:?}", result.err());
        let contents = result.unwrap();
        assert!(
            contents.contains("requests==2.31.0 --hash=sha256:aaaa"),
            "missing requests line, got: {contents}"
        );
        assert!(
            contents.contains("urllib3==2.0.7 --hash=sha256:bbbb"),
            "missing urllib3 line, got: {contents}"
        );
    }

    // T-031-02: Builder returns Err when any hash is None
    #[test]
    fn build_pip_requirements_any_hash_none_returns_err() {
        let packages: Vec<PkgTriple> = vec![
            (
                "requests".to_string(),
                "2.31.0".to_string(),
                Some("sha256:aaaa".to_string()),
            ),
            ("evil-pkg".to_string(), "0.1.0".to_string(), None),
        ];
        let result = build_pip_requirements(&packages);
        assert!(result.is_err(), "expected Err when a package has None hash");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("evil-pkg"),
            "error message should name the problematic package, got: {msg}"
        );
    }

    // T-031-03: Hash algorithm prefix is preserved verbatim
    #[test]
    fn build_pip_requirements_hash_prefix_preserved_verbatim() {
        let packages: Vec<PkgTriple> = vec![(
            "mypkg".to_string(),
            "1.0.0".to_string(),
            Some("sha256:abcdef".to_string()),
        )];
        let result = build_pip_requirements(&packages).unwrap();
        assert!(
            result.contains("--hash=sha256:abcdef"),
            "full algo:hex should be preserved verbatim, got: {result}"
        );
    }

    // T-031-04: Non-sha256 algorithm is rejected
    #[test]
    fn build_pip_requirements_non_sha256_rejected() {
        let packages: Vec<PkgTriple> = vec![(
            "mypkg".to_string(),
            "1.0.0".to_string(),
            Some("sha512:abcd".to_string()),
        )];
        let result = build_pip_requirements(&packages);
        assert!(
            result.is_err(),
            "expected Err for non-sha256 hash algorithm"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("sha512"),
            "error message should name the algorithm, got: {msg}"
        );
    }

    // T-031-05: Temp file is removed after successful invocation
    #[test]
    fn temp_req_file_removed_after_success() {
        let temp =
            TempReqFile::create("requests==2.31.0 --hash=sha256:aaaa\n").expect("create temp file");
        let path = temp.path().to_path_buf();
        assert!(path.exists(), "temp file should exist before drop");
        drop(temp);
        assert!(
            !path.exists(),
            "temp file should be removed after drop (success path)"
        );
    }

    // T-031-06: Temp file is removed after failed invocation (drop on Err path)
    #[test]
    fn temp_req_file_removed_after_failure() {
        let temp =
            TempReqFile::create("requests==2.31.0 --hash=sha256:aaaa\n").expect("create temp file");
        let path = temp.path().to_path_buf();
        assert!(path.exists(), "temp file should exist before drop");
        // Simulate the failure path by dropping without running pip.
        drop(temp);
        assert!(
            !path.exists(),
            "temp file should be removed after drop (failure path)"
        );
    }

    // T-031-07: Temp file is removed on early return (RAII / panic safety)
    #[test]
    fn temp_req_file_removed_on_early_return() {
        let path = {
            let temp = TempReqFile::create("urllib3==2.0.7 --hash=sha256:bbbb\n")
                .expect("create temp file");
            let p = temp.path().to_path_buf();
            assert!(p.exists());
            // Simulate early return: `temp` goes out of scope here without
            // pip ever being invoked.
            p
            // `temp` is dropped at end of this block.
        };
        assert!(
            !path.exists(),
            "temp file should be cleaned up on early return / out-of-scope drop"
        );
    }
}
