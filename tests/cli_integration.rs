// SPDX-License-Identifier: Apache-2.0
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn dep_scan() -> Command {
    Command::cargo_bin("dep-scan").expect("binary should exist")
}

// T-002-08: --help prints usage
#[test]
fn help_flag_shows_usage() {
    dep_scan()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("dep-scan"))
        .stdout(predicate::str::contains("check"));
}

// T-002-09: check --help prints check usage
#[test]
fn check_help_shows_check_usage() {
    dep_scan()
        .args(["check", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("package"))
        .stdout(predicate::str::contains("--registry"));
}

// T-002-10: install requires --registry flag
#[test]
fn install_requires_registry_flag() {
    dep_scan()
        .args(["install", "lodash"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--registry"));
}

// T-002-11: no args shows help or exits non-zero
#[test]
fn no_args_exits_non_zero() {
    dep_scan().assert().failure();
}

// T-003-09: config show prints current config
#[test]
fn config_show_prints_config() {
    dep_scan()
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("min_package_age_hours"))
        .stdout(predicate::str::contains("48"));
}

// T-003-10: config init creates default file
#[test]
fn config_init_creates_default_file() {
    let tmp_dir = TempDir::new().unwrap();
    dep_scan()
        .args(["config", "init"])
        .current_dir(tmp_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(".dep-scan.toml"));

    let config_path = tmp_dir.path().join(".dep-scan.toml");
    assert!(config_path.exists(), ".dep-scan.toml should be created");

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("min_package_age_hours"),
        "Config file should contain min_package_age_hours"
    );
    assert!(
        content.contains("48"),
        "Config file should contain default value 48"
    );
    assert!(
        content.contains("registry.npmjs.org"),
        "Config file should contain npm registry URL"
    );
}
