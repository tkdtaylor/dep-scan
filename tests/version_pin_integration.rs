// SPDX-License-Identifier: Apache-2.0
//! Integration tests for task 113: the `PINNED_VERSION` published channel.
//!
//! Tests T-113-01 through T-113-03 confirm the pin file exists, is byte-exactly
//! `"v" + CARGO_PKG_VERSION + "\n"`, and is a single LF-terminated `v`-semver
//! line. The `CARGO_PKG_VERSION` comparison (never a hardcoded literal) is the
//! lockstep gate: a version bump that misses either `Cargo.toml` or
//! `PINNED_VERSION` fails this test, and therefore fails CI on the
//! release-prep commit.
//!
//! Tests T-113-04 through T-113-06 are grep-style doc-contract assertions on
//! README.md, RELEASE_CHECKLIST.md, and docs/spec/interfaces.md.
//!
//! Test T-113-07 (`#[cfg(unix)]`) confirms `install.sh --dry-run
//! --version=<pin>` exits 0 and echoes the pin plus the composed release URL,
//! fully offline (a dry-run with a pin skips the GitHub API "latest" lookup
//! and exits before any download).

use std::fs;
use std::path::Path;

fn pin_path() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/PINNED_VERSION"))
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

// ---------------------------------------------------------------------------
// T-113-01: PINNED_VERSION exists at the repo root.
// ---------------------------------------------------------------------------
#[test]
fn t113_01_pinned_version_file_exists() {
    let contents = fs::read_to_string(pin_path());
    assert!(
        contents.is_ok(),
        "T-113-01: PINNED_VERSION must exist at the repo root: {:?}",
        contents.err()
    );
}

// ---------------------------------------------------------------------------
// T-113-02: Content is byte-exactly "v" + CARGO_PKG_VERSION + "\n".
// ---------------------------------------------------------------------------
#[test]
fn t113_02_content_matches_cargo_pkg_version_exactly() {
    let contents = fs::read_to_string(pin_path()).expect("T-113-02: PINNED_VERSION must exist");
    let expected = format!("v{}\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        contents, expected,
        "T-113-02: PINNED_VERSION content must be exactly \"v\" + CARGO_PKG_VERSION + \"\\n\" \
         (this is the lockstep gate against Cargo.toml, asserted via env!, never a hardcoded \
         literal)"
    );
}

// ---------------------------------------------------------------------------
// T-113-03: Single v-prefixed semver line, LF only, no stray whitespace.
// ---------------------------------------------------------------------------
#[test]
fn t113_03_single_v_semver_line_lf_only() {
    let contents = fs::read_to_string(pin_path()).expect("T-113-03: PINNED_VERSION must exist");

    assert_eq!(
        contents.matches('\n').count(),
        1,
        "T-113-03: PINNED_VERSION must contain exactly one newline: {contents:?}"
    );
    assert!(
        contents.ends_with('\n'),
        "T-113-03: PINNED_VERSION must end with a newline: {contents:?}"
    );
    assert!(
        !contents.contains('\r'),
        "T-113-03: PINNED_VERSION must not contain CR (LF only): {contents:?}"
    );

    let trimmed = contents.trim_end_matches('\n');
    assert!(
        !trimmed.starts_with(' ')
            && !trimmed.starts_with('\t')
            && !trimmed.ends_with(' ')
            && !trimmed.ends_with('\t'),
        "T-113-03: no leading/trailing spaces or tabs: {trimmed:?}"
    );

    // Manual v<major>.<minor>.<patch> parse (no regex crate; std only).
    let semver = trimmed
        .strip_prefix('v')
        .unwrap_or_else(|| panic!("T-113-03: pin must start with 'v': {trimmed:?}"));
    let parts: Vec<&str> = semver.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "T-113-03: pin must be v<major>.<minor>.<patch>: {trimmed:?}"
    );
    for part in &parts {
        part.parse::<u64>().unwrap_or_else(|e| {
            panic!("T-113-03: version component {part:?} is not a valid u64: {e}")
        });
    }
}

// ---------------------------------------------------------------------------
// T-113-04: README documents the channel and both consumer conventions.
// ---------------------------------------------------------------------------
#[test]
fn t113_04_readme_documents_channel_and_conventions() {
    let readme =
        fs::read_to_string(repo_root().join("README.md")).expect("T-113-04: README.md must exist");

    assert!(
        readme.contains("## Version pinning for consumers"),
        "T-113-04: README.md must have a '## Version pinning for consumers' heading"
    );
    assert!(
        readme.contains("https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION"),
        "T-113-04: README.md must contain the literal raw URL"
    );
    assert!(
        readme.contains("--version="),
        "T-113-04: README.md must document the install.sh --version= pass-through"
    );
    assert!(
        readme.contains("dep-scan --version"),
        "T-113-04: README.md must document the host drift check via `dep-scan --version`"
    );

    // The ## Contents index must link to the new section.
    let contents_idx = readme
        .find("## Contents")
        .expect("T-113-04: README.md must have a ## Contents index");
    let next_heading = readme[contents_idx + "## Contents".len()..]
        .find("\n## ")
        .map(|off| contents_idx + "## Contents".len() + off)
        .unwrap_or(readme.len());
    let contents_section = &readme[contents_idx..next_heading];
    assert!(
        contents_section.contains("#version-pinning-for-consumers"),
        "T-113-04: the ## Contents index must link to #version-pinning-for-consumers: {contents_section}"
    );
}

// ---------------------------------------------------------------------------
// T-113-05: RELEASE_CHECKLIST.md includes the pin bump in release prep.
// ---------------------------------------------------------------------------
#[test]
fn t113_05_release_checklist_includes_pin_bump() {
    let checklist = fs::read_to_string(repo_root().join("RELEASE_CHECKLIST.md"))
        .expect("T-113-05: RELEASE_CHECKLIST.md must exist");

    let section_2_start = checklist
        .find("## 2. Release prep")
        .expect("T-113-05: RELEASE_CHECKLIST.md must have a '## 2. Release prep' section");
    let section_3_start = checklist
        .find("## 3.")
        .expect("T-113-05: RELEASE_CHECKLIST.md must have a '## 3.' section after release prep");
    assert!(
        section_3_start > section_2_start,
        "T-113-05: section 3 must come after section 2"
    );
    let section_2 = &checklist[section_2_start..section_3_start];

    assert!(
        section_2.contains("PINNED_VERSION"),
        "T-113-05: section '2. Release prep' must mention PINNED_VERSION: {section_2}"
    );

    // The step-5 `git add` line must include PINNED_VERSION.
    let git_add_line = section_2
        .lines()
        .find(|l| l.contains("git add") && l.contains("Cargo.toml"))
        .unwrap_or_else(|| {
            panic!("T-113-05: no 'git add Cargo.toml ...' line found in: {section_2}")
        });
    assert!(
        git_add_line.contains("PINNED_VERSION"),
        "T-113-05: the release-prep git add line must include PINNED_VERSION: {git_add_line:?}"
    );
}

// ---------------------------------------------------------------------------
// T-113-06: interfaces.md documents the published pin channel.
// ---------------------------------------------------------------------------
#[test]
fn t113_06_interfaces_md_documents_pin_channel() {
    let interfaces = fs::read_to_string(repo_root().join("docs/spec/interfaces.md"))
        .expect("T-113-06: docs/spec/interfaces.md must exist");

    assert!(
        interfaces.contains("PINNED_VERSION"),
        "T-113-06: interfaces.md must document PINNED_VERSION"
    );
    assert!(
        interfaces
            .contains("https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION"),
        "T-113-06: interfaces.md must contain the raw URL"
    );
    assert!(
        interfaces.contains('"') && interfaces.contains("\"v\" + semver"),
        "T-113-06: interfaces.md must document the exact format (single line, \"v\" + semver + LF)"
    );
    assert!(
        interfaces.contains("Stability")
            && interfaces.contains("stable")
            && interfaces.contains("major version bump"),
        "T-113-06: interfaces.md must carry a stability statement for the pin channel"
    );
}

// ---------------------------------------------------------------------------
// T-113-07 (unix only): the pin value drives install.sh verbatim in dry-run,
// fully offline.
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[test]
fn t113_07_install_sh_dry_run_consumes_pin_verbatim() {
    let contents = fs::read_to_string(pin_path()).expect("T-113-07: PINNED_VERSION must exist");
    let pin = contents.trim_end_matches('\n');

    let output = std::process::Command::new("bash")
        .arg(repo_root().join("install.sh"))
        .arg("--dry-run")
        .arg(format!("--version={pin}"))
        .current_dir(repo_root())
        .output()
        .expect("T-113-07: failed to spawn bash install.sh");

    assert!(
        output.status.success(),
        "T-113-07: install.sh --dry-run --version={pin} must exit 0. stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected_pinned_line = format!("Pinned version: {pin}");
    assert!(
        stdout.contains(&expected_pinned_line),
        "T-113-07: stdout must contain {expected_pinned_line:?}: {stdout}"
    );

    let expected_url_prefix =
        format!("https://github.com/tkdtaylor/dep-scan/releases/download/{pin}/dep-scan-{pin}-");
    assert!(
        stdout.contains(&expected_url_prefix),
        "T-113-07: stdout must contain the composed release URL prefix {expected_url_prefix:?}: {stdout}"
    );

    // Offline proof: a dry-run with a pin never hits the GitHub "latest" API
    // lookup (get_latest_version), so no "Latest version:" line appears.
    assert!(
        !stdout.contains("Latest version:"),
        "T-113-07: a pinned dry-run must not call get_latest_version: {stdout}"
    );
}
