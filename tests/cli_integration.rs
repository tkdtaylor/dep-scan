use assert_cmd::Command;
use predicates::prelude::*;

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

// T-002-10: install prints not yet implemented
#[test]
fn install_prints_not_yet_implemented() {
    dep_scan()
        .args(["install", "lodash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not yet implemented"));
}

// T-002-11: no args shows help or exits non-zero
#[test]
fn no_args_exits_non_zero() {
    dep_scan().assert().failure();
}
