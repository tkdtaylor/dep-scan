# Task 012 — Install script extraction + analysis policy

**Status:** backlog
**Depends on:** 010

## Objective

Extract install scripts from package metadata and analyze them for suspicious patterns.

## Acceptance criteria

- [ ] npm: Extract `scripts.preinstall`, `scripts.postinstall`, `scripts.install` from version data
- [ ] PyPI: Heuristic — flag setup.py usage as limited analysis
- [ ] Install scripts populated in ScanContext.install_scripts
- [ ] src/policy/install_script.rs: `InstallScriptPolicy` implements `Policy`
- [ ] Pattern matching for: eval, exec, child_process, subprocess, os.system, base64 strings >40 chars, HTTP URLs, env var reads
- [ ] Each pattern has severity (warn vs block)
- [ ] Returns Block for high-severity, Warn for medium
- [ ] Tests with known malicious patterns, clean scripts, edge cases
- [ ] All tests pass, clippy clean, fmt clean
