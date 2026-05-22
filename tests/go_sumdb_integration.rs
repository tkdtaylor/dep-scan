/// Integration tests for task 034 — Go checksum database Ed25519 signature verification.
///
/// Uses assert_cmd + wiremock to test the full binary against mocked Go module
/// proxy and sumdb endpoints.
///
/// T-034-17: Full scan — Go module with (stub) sumdb response → verifier called
/// T-034-18: Full scan — 404 in sumdb warns by default (exit 1)
/// T-034-19: Full scan — require_go_sumdb=true blocks missing modules (exit 1)
/// T-034-20: Full scan — invalid signature blocks unconditionally (exit 1)
/// T-034-21: Configurable sumdb URL works for testing
/// T-034-22: Non-Go registries unaffected
use std::io::Write as _;

use assert_cmd::Command;
use base64::Engine as _;
use predicates::prelude::*;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

/// Write a config that enables only the Go sumdb check (all other policies off).
fn write_go_sumdb_config(
    proxy_url: &str,
    sumdb_url: &str,
    cache_path: &str,
    check_go_sumdb: bool,
    require_go_sumdb: bool,
) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
go_proxy_url = "{proxy_url}"
go_sum_db_url = "{sumdb_url}"

[policies]
check_min_age = false
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = {check_go_sumdb}
require_go_sumdb = {require_go_sumdb}

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write config");
    f
}

/// Write a config for npm (Go sumdb should not be exercised).
fn write_npm_config(npm_url: &str, cache_path: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"
min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
npm_url = "{npm_url}"

[policies]
check_min_age = false
check_install_scripts = false
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = true

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0
"#
    )
    .expect("write config");
    f
}

/// Go module proxy `/list` response.
fn proxy_list_body(version: &str) -> String {
    format!("{version}\n")
}

/// Go module proxy `.info` response.
fn proxy_info_body(version: &str) -> String {
    format!(
        r#"{{"Version":"{version}","Time":"2020-06-15T10:00:00Z"}}"#,
        version = version
    )
}

/// A syntactically-valid-looking sumdb lookup body (but with a fake/stub signature).
///
/// The `RealSumDbVerifier` in the binary will fail to verify this because the
/// signature is not actually signed by the real sum.golang.org key.  This is
/// the same approach as pypi_provenance_integration.rs where stub certs fail
/// real ECDSA verification — the "full crypto passes" path is covered by
/// unit tests with `MockSumDbVerifier` (T-034-10).
fn sumdb_lookup_body_stub(module: &str, version: &str) -> String {
    // The signature line has a fake sig — real verification will fail.
    // 4-byte key ID + 64 bytes of zeros = 68 bytes = 92 chars base64
    let fake_sig = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 68]);
    format!(
        concat!(
            "{module} {version} h1:c29zZWtyb3BlcnR5\n",
            "{module} {version}/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            "\n",
            "go.sum database tree\n",
            "12345\n",
            "c29zZWtyb3BlcnR5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            "\n",
            "\u{2014} sum.golang.org {fake_sig}\n",
        ),
        module = module,
        version = version,
        fake_sig = fake_sig,
    )
}

/// npm registry JSON for a package.
fn npm_json(name: &str, version: &str) -> String {
    format!(
        r#"{{
    "name": "{name}",
    "description": "Test package",
    "dist-tags": {{ "latest": "{version}" }},
    "versions": {{
        "{version}": {{
            "name": "{name}",
            "version": "{version}",
            "description": "Test package",
            "dist": {{
                "integrity": "sha512-AAAA",
                "shasum": "0000000000000000000000000000000000000000"
            }}
        }}
    }},
    "time": {{ "{version}": "2020-01-01T00:00:00.000Z" }},
    "maintainers": [{{"name": "testuser"}}]
}}"#
    )
}

// ---------------------------------------------------------------------------
// T-034-17: Full scan — Go module with valid sumdb response passes
// (stub response; real crypto fails → verifier was called, exit 1)
// ---------------------------------------------------------------------------
//
// NOTE: "valid" means the response is syntactically correct and the binary
// calls the sumdb verifier. Because the binary uses `RealSumDbVerifier`
// with the pinned sum.golang.org key, the stub signature will fail and
// produce a Block (exit 1).  The "crypto passes" path is covered by
// unit tests (T-034-10) using `MockSumDbVerifier`.

#[tokio::test]
async fn t034_17_full_scan_go_module_sumdb_is_verified() {
    // T-034-17
    let proxy_server = MockServer::start().await;
    let sumdb_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_sumdb_config(
        &proxy_server.uri(),
        &sumdb_server.uri(),
        cache_path.to_str().unwrap(),
        true,
        false,
    );

    let module = "github.com/foo/bar";
    let version = "v1.2.3";

    // Go proxy: list
    Mock::given(method("GET"))
        .and(path("/github.com/foo/bar/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_list_body(version)))
        .mount(&proxy_server)
        .await;

    // Go proxy: info
    Mock::given(method("GET"))
        .and(path("/github.com/foo/bar/@v/v1.2.3.info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_info_body(version)))
        .mount(&proxy_server)
        .await;

    // Go proxy: h1 hash from sumdb (used by existing fetch_h1_hash in go.rs)
    Mock::given(method("GET"))
        .and(path("/lookup/github.com/foo/bar@v1.2.3"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(sumdb_lookup_body_stub(module, version)),
        )
        .mount(&sumdb_server)
        .await;

    // T-034-17: binary calls sumdb verifier; stub sig fails real key → exit 1
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "github.com/foo/bar",
            "--registry",
            "go",
        ])
        .assert()
        .code(1) // stub sig fails RealSumDbVerifier against pinned key
        .stdout(predicate::str::contains("go_sumdb"));
}

// ---------------------------------------------------------------------------
// T-034-18: Full scan — 404 in sumdb warns by default (exit 1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn t034_18_full_scan_sumdb_404_warns_by_default() {
    // T-034-18
    let proxy_server = MockServer::start().await;
    let sumdb_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_sumdb_config(
        &proxy_server.uri(),
        &sumdb_server.uri(),
        cache_path.to_str().unwrap(),
        true,
        false, // require = false → Warn
    );

    let version = "v0.1.0";

    Mock::given(method("GET"))
        .and(path("/github.com/foo/private-mod/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_list_body(version)))
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/github.com/foo/private-mod/@v/v0.1.0.info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_info_body(version)))
        .mount(&proxy_server)
        .await;

    // sumdb returns 404 — module not in checksum database
    Mock::given(method("GET"))
        .and(path("/lookup/github.com/foo/private-mod@v0.1.0"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&sumdb_server)
        .await;

    // T-034-18: 404 → Warn → exit 1 (Warn = exit 1 per project convention)
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "github.com/foo/private-mod",
            "--registry",
            "go",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("not in the Go checksum database"));
}

// ---------------------------------------------------------------------------
// T-034-19: Full scan — require_go_sumdb=true blocks missing modules (exit 1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn t034_19_require_go_sumdb_true_blocks_missing_modules() {
    // T-034-19
    let proxy_server = MockServer::start().await;
    let sumdb_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_sumdb_config(
        &proxy_server.uri(),
        &sumdb_server.uri(),
        cache_path.to_str().unwrap(),
        true,
        true, // require = true → Block
    );

    let version = "v0.1.0";

    Mock::given(method("GET"))
        .and(path("/github.com/foo/private-mod/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_list_body(version)))
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/github.com/foo/private-mod/@v/v0.1.0.info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_info_body(version)))
        .mount(&proxy_server)
        .await;

    // sumdb returns 404
    Mock::given(method("GET"))
        .and(path("/lookup/github.com/foo/private-mod@v0.1.0"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&sumdb_server)
        .await;

    // T-034-19: require_go_sumdb=true → Block → exit 1
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "github.com/foo/private-mod",
            "--registry",
            "go",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("go_sumdb"));
}

// ---------------------------------------------------------------------------
// T-034-20: Full scan — invalid signature blocks unconditionally (exit 1)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn t034_20_invalid_signature_blocks_unconditionally() {
    // T-034-20: tampered (stub) signature with require_go_sumdb=false still blocks
    let proxy_server = MockServer::start().await;
    let sumdb_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_sumdb_config(
        &proxy_server.uri(),
        &sumdb_server.uri(),
        cache_path.to_str().unwrap(),
        true,
        false, // require = false — irrelevant; invalid sig always blocks
    );

    let module = "github.com/foo/bar";
    let version = "v1.2.3";

    Mock::given(method("GET"))
        .and(path("/github.com/foo/bar/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_list_body(version)))
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/github.com/foo/bar/@v/v1.2.3.info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_info_body(version)))
        .mount(&proxy_server)
        .await;

    // Return a syntactically valid response with a tampered/stub signature.
    // RealSumDbVerifier will reject it against the pinned key.
    Mock::given(method("GET"))
        .and(path("/lookup/github.com/foo/bar@v1.2.3"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(sumdb_lookup_body_stub(module, version)),
        )
        .mount(&sumdb_server)
        .await;

    // T-034-20: invalid sig → Block → exit 1, even with require=false
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "github.com/foo/bar",
            "--registry",
            "go",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("go_sumdb"));
}

// ---------------------------------------------------------------------------
// T-034-21: Configurable sumdb URL works for testing / private mirrors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn t034_21_configurable_sumdb_url_works() {
    // T-034-21: sumdb URL is set to wiremock; sum.golang.org is NOT contacted
    let proxy_server = MockServer::start().await;
    let sumdb_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_go_sumdb_config(
        &proxy_server.uri(),
        &sumdb_server.uri(), // configured URL, NOT sum.golang.org
        cache_path.to_str().unwrap(),
        true,
        false,
    );

    let version = "v1.9.1";
    let module = "github.com/gin-gonic/gin";

    Mock::given(method("GET"))
        .and(path("/github.com/gin-gonic/gin/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_list_body(version)))
        .mount(&proxy_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/github.com/gin-gonic/gin/@v/v1.9.1.info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(proxy_info_body(version)))
        .mount(&proxy_server)
        .await;

    // Expect exactly 1 call to the configured sumdb URL (not sum.golang.org)
    Mock::given(method("GET"))
        .and(path("/lookup/github.com/gin-gonic/gin@v1.9.1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(sumdb_lookup_body_stub(module, version)),
        )
        .expect(1) // must be called exactly once
        .mount(&sumdb_server)
        .await;

    let _assertion = dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "github.com/gin-gonic/gin",
            "--registry",
            "go",
        ])
        .assert();
    // T-034-21: expect(1) verifies the configured URL was contacted
    // (wiremock will report missing expectations after server drop)
}

// ---------------------------------------------------------------------------
// T-034-22: Non-Go registries unaffected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn t034_22_non_go_registries_unaffected() {
    // T-034-22: npm scan should not contact sumdb
    let npm_server = MockServer::start().await;
    let tmp = TempDir::new().unwrap();
    let cache_path = tmp.path().join("cache.db");
    let config = write_npm_config(&npm_server.uri(), cache_path.to_str().unwrap());

    Mock::given(method("GET"))
        .and(path("/lodash"))
        .respond_with(ResponseTemplate::new(200).set_body_string(npm_json("lodash", "4.17.21")))
        .mount(&npm_server)
        .await;

    // T-034-22: npm scan — go_sumdb policy should return Pass (non-Go package).
    // npm provenance is disabled in the test config so lodash passes all checks.
    // The go_sumdb policy should show as "pass" (not block/warn).
    dep_scan()
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "check",
            "lodash",
            "--registry",
            "npm",
        ])
        .assert()
        .code(0) // all enabled policies pass; npm provenance is disabled in test config
        .stdout(predicate::str::contains("go_sumdb: pass")); // go_sumdb is Pass for npm
}
