# Task 012 — Install script extraction + analysis policy

**Status:** backlog
**Depends on:** 010

## Objective

Extract install scripts from package metadata and analyze them for suspicious patterns.

## Acceptance criteria

- [x] npm: Extract `scripts.preinstall`, `scripts.postinstall`, `scripts.install` from version data
- [x] PyPI: Heuristic — flag setup.py usage as limited analysis
- [x] Install scripts populated in ScanContext.install_scripts
- [x] src/policy/install_script.rs: `InstallScriptPolicy` implements `Policy`
- [x] Pattern matching for: eval, exec, child_process, subprocess, os.system, base64 strings >40 chars, HTTP URLs, env var reads
- [x] Each pattern has severity (warn vs block)
- [x] Returns Block for high-severity, Warn for medium
- [x] Tests with known malicious patterns, clean scripts, edge cases
- [x] All tests pass, clippy clean, fmt clean
