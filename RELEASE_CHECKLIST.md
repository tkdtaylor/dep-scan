# Release checklist

Use this checklist every time a dep-scan release is cut. It exists because
the v1.2.0 rollback exposed the gap — see
[`docs/architecture/agent-rules.md`](docs/architecture/agent-rules.md) for
the retro.

---

## 1. Pre-release — local CI gates

Run all four gates and confirm they are green before touching version numbers.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
```

Also confirm:

- [ ] All planned tasks are committed and in `docs/tasks/completed/`
- [ ] Working tree is clean (`git status` shows nothing)
- [ ] Drift audit clean (re-run `scripts/check-task-state.sh`)

---

## 2. Release prep

Update these files, then commit as a single `chore: cut vX.Y.Z` commit.

1. **`Cargo.toml`** — bump `version = "X.Y.Z"`.
2. **`CHANGELOG.md`** — add a `## [X.Y.Z] — YYYY-MM-DD` section with all
   changes since the last release. Update the diff-link at the bottom.
3. **Test count** — get the authoritative number and paste it into the
   CHANGELOG "Stats" block:
   ```bash
   cargo test 2>&1 | grep "test result:" | awk '{s+=$4} END {print s}'
   ```
4. **`Cargo.lock`** — will auto-update on the next `cargo build`; stage it.
5. Commit:
   ```bash
   git add Cargo.toml Cargo.lock CHANGELOG.md
   git commit -m "chore: cut vX.Y.Z"
   ```

---

## 3. Explicit authorization gate

**Stop here.** Do not tag or push until the maintainer or user explicitly says
something equivalent to:

> "Yes, tag and push vX.Y.Z."

Prior statements such as "keep going", "ship it", "fix them all", or "looks
good" do **not** constitute authorization to tag. If there is any ambiguity,
ask. This gate exists because of the v1.2.0 incident; see
[`docs/architecture/agent-rules.md`](docs/architecture/agent-rules.md).

---

## 4. Tag and push

After explicit authorization:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

The release workflow in `.github/workflows/release.yml` triggers on `v*` tags
and builds cross-platform binaries.

---

## 5. Post-tag verification

- [ ] Watch the GitHub Actions release workflow — all five platform builds
      must succeed (linux-x86_64, linux-aarch64, macos-x86_64, macos-aarch64,
      windows-x86_64)
- [ ] Download a release artifact and verify `sha256sums.txt` locally:
      ```bash
      sha256sum -c sha256sums.txt
      ```
- [ ] If cosign signing (task 068) has landed: run `cosign verify-blob` on a
      downloaded artifact against the published `.sig` + `.crt`
- [ ] Confirm the GitHub Release page looks correct (description, assets)

---

## 6. Post-release housekeeping

- [ ] Update `docs/plans/roadmap.md` with a new milestone block for the
      shipped version
- [ ] Move any task files deferred to a future release to `docs/tasks/backlog/`
      with a deferral note
- [ ] Run `cargo audit` once more to confirm no new advisories since the tag
- [ ] Announce (GitHub release notes are the primary channel; no other steps
      required for now)

---

## 7. Rollback playbook

If something is wrong after tagging (broken CI, bad binary, incorrect
CHANGELOG):

```bash
# Delete tag locally
git tag -d vX.Y.Z

# Delete tag on remote
git push origin :refs/tags/vX.Y.Z
```

- Delete the GitHub Release in the UI (Releases → Edit → Delete).
- If the `chore: cut vX.Y.Z` commit itself is wrong, revert it:
  ```bash
  git revert HEAD --no-edit
  git push origin main
  ```
- Document what went wrong: add a note to the CHANGELOG or a new section in
  `docs/architecture/agent-rules.md`.
