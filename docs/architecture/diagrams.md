# Architecture Diagrams

**Project:** dep-scan
**Last updated:** 2026-06-21 (task 108 — transitive walker, SBOM/VEX renderers, interchange signer in the component view)

C4-structured Mermaid diagrams covering the system at three progressively detailed levels (Context → Container → Component), plus runtime sequence flows showing how the pieces collaborate. See [overview.md](overview.md) for prose context, [decisions/](decisions/) for the ADRs referenced here, and [`../spec/architecture.md`](../spec/architecture.md) for the structured element catalog these diagrams render.

These diagrams are part of the **authoritative spec** for this project. Code changes that contradict a diagram either invalidate the change or invalidate the diagram; one must be updated to match the other in the same commit.

GitHub and most IDE markdown previewers render Mermaid natively — no build step required.

---

## 1. System Context — who uses it and what it touches

```mermaid
C4Context
    title System Context for dep-scan

    Person(user, "CLI user", "Developer or CI job running dep-scan")

    System(depscan, "dep-scan", "Scans + verifies dependencies before install")

    System_Ext(npm, "npm registry", "Package metadata + sigstore provenance")
    System_Ext(pypi, "PyPI", "Package metadata + PEP 740 provenance")
    System_Ext(crates, "crates.io", "Crate metadata + cksum")
    System_Ext(goproxy, "Go module proxy", "Module metadata + version info")
    System_Ext(sumdb, "sum.golang.org", "Signed-tree-head verification")
    System_Ext(osv, "OSV.dev", "Vulnerability database")
    System_Ext(pkgmgr, "Wrapped package manager", "npm / pip / cargo / go")

    Rel(user, depscan, "Runs", "CLI")
    Rel(depscan, npm, "Fetches metadata + attestations", "HTTPS")
    Rel(depscan, pypi, "Fetches Simple Index + provenance", "HTTPS")
    Rel(depscan, crates, "Fetches metadata + owners", "HTTPS")
    Rel(depscan, goproxy, "Fetches module info", "HTTPS")
    Rel(depscan, sumdb, "Fetches signed lookup", "HTTPS")
    Rel(depscan, osv, "Queries vulnerabilities", "HTTPS")
    Rel(depscan, pkgmgr, "exec on scan pass", "subprocess")
```

> **Build-time trust roots are not shown** — the sigstore Fulcio + Rekor *verification* roots and the sum.golang.org public key are embedded via `include_bytes!` / `const` and are **not** runtime dependencies for verification. See [ADR 003 § Embedded trust roots](decisions/003-content-hash-cache-integrity.md).
>
> **Keyless interchange signing is a separate runtime outbound** (task 087, [behaviors B-030](../spec/behaviors.md#b-030-signing-identity-resolution-and-fail-closed)): when emitting a signed `--format osv|cyclonedx|spdx|vex` report online, dep-scan calls Fulcio (cert issuance) + Rekor (log entry) over HTTPS using the configurable `signing.fulcio_url` / `signing.rekor_url`. Offline, the `OperatorKeySigner` signs locally from `signing.key_path` with no network. This is the only place dep-scan makes a runtime sigstore *signing* call; verification remains offline against the embedded roots.

---

## 2. Containers — deployable units inside the system

```mermaid
C4Container
    title Container view of dep-scan

    Person(user, "CLI user")

    System_Boundary(boundary, "dep-scan host") {
        Container(binary, "dep-scan binary", "Rust 1.88, edition 2024", "Single statically-linked CLI binary")
        ContainerDb(cache, "Cache DB", "SQLite (rusqlite 0.39, WAL, mode 0600)", "Local scan-verdict + maintainer history")
    }

    System_Ext(registries, "Package registries", "npm, PyPI, crates.io, Go proxy, sumdb")
    System_Ext(osv, "OSV.dev")
    System_Ext(pkgmgr, "Wrapped package manager")

    Rel(user, binary, "Invokes")
    Rel(binary, cache, "Reads + writes verdicts", "SQLite file I/O")
    Rel(binary, registries, "Fetches metadata + provenance", "HTTPS")
    Rel(binary, osv, "Queries", "HTTPS")
    Rel(binary, pkgmgr, "exec on pass", "subprocess")
```

dep-scan is a one-shot CLI — there's no long-lived process. The cache DB is the only persistent state.

---

## 3. Components — what's inside the binary

```mermaid
C4Component
    title Components inside the dep-scan binary

    Container(cli, "CLI / main", "clap derive", "Subcommand parsing, dispatch, output")
    Container(config, "Config layer", "serde + toml", "Layered config (defaults < TOML < env < flags)")
    Container(validation, "Validation", "Pure functions", "Rejects -prefixed names, Go path/version")

    Container(registry, "Registry layer", "reqwest + tokio", "npm, PyPI, crates.io, Go proxy clients + provenance/sumdb companions")
    Container(lockfile, "Lockfile parser", "serde", "Parses package-lock.json, requirements.txt, Cargo.lock, go.sum")
    Container(osv, "OSV client", "reqwest", "Vulnerability lookups")
    Container(typosquat, "Typosquat detector", "Custom Levenshtein", "Edit-distance + popular-package lists (256-char bound)")

    Container(policy, "Policy layer", "12 modules", "age, install_scripts, obfuscation, typosquatting, vulnerability, maintainer_change, popularity, dependency_confusion, npm_provenance, pypi_provenance, go_sumdb, mutable_ref (+ vcs_host gate)")
    Container(sigstore, "Sigstore verifier", "x509-parser + p256", "Fulcio chain walk + DSSE + Rekor inclusion + timestamp window")
    Container(signednote, "Signed-note parser/verifier", "ed25519-dalek + p256", "RFC sumdb-style envelope; shared by sumdb + Rekor checkpoint")

    Container(transitive, "Transitive walker", "DFS + fetch pool", "Opt-in DFS over EdgeProvider/NodeScanner; depth-limit, cycle detection, verdict roll-up (ADR 009/011)")
    Container(vcs, "VCS fetch + manifest", "gitoxide", "Sandboxed read-only git fetch; manifest-fallback edge discovery for git deps (ADR 008/011)")
    Container(interchange, "Interchange + signer", "serde_json + DSSE", "SBOM (CycloneDX/SPDX) + OpenVEX renderers; DSSE-signs interchange output (ADR 005/006/010)")

    Container(cache, "Cache layer", "rusqlite", "Content-hash decision matrix, fail-closed")
    Container(types, "Types", "—", "PackageMetadata, ScanContext, PolicyResult")

    Rel(cli, config, "Loads")
    Rel(cli, validation, "Calls before any subprocess")
    Rel(cli, registry, "Fetches metadata")
    Rel(cli, lockfile, "Parses input")
    Rel(cli, osv, "Enriches ScanContext")
    Rel(cli, policy, "Runs pipeline")
    Rel(cli, cache, "Reads + writes verdicts")
    Rel(cli, transitive, "Walks deps when --transitive")
    Rel(cli, interchange, "Renders + signs --format output")
    Rel(transitive, vcs, "Fetches git-sourced deps")
    Rel(transitive, policy, "Scans each node")
    Rel(policy, sigstore, "Used by P-09, P-10")
    Rel(policy, signednote, "Used by P-11")
    Rel(sigstore, signednote, "Reuses note parser")
    Rel(policy, typosquat, "Used by P-04")
```

---

## 4. Runtime — `dep-scan install` happy path

```mermaid
sequenceDiagram
    autonumber
    actor user as CLI user
    participant cli as dep-scan CLI
    participant val as validation.rs
    participant reg as registry client
    participant cache as cache.rs (SQLite)
    participant pol as policy pipeline
    participant sig as sigstore_verify
    participant pkg as wrapped pkg mgr (e.g. npm)

    user->>cli: dep-scan install express --registry npm
    cli->>val: reject -prefixed tokens
    val-->>cli: ok

    cli->>reg: get_metadata("express", None)
    reg-->>cli: PackageMetadata { version="5.0.1", content_hash=sha512:... }

    cli->>cache: lookup("express", "5.0.1", "npm")
    alt cache hit
        cache-->>cli: row { content_hash=cached_h, verdict=pass }
        cli->>cli: compare cached_h vs registry h (decision matrix)
        alt match
            cli->>cli: honor cached verdict, skip pipeline
        else mismatch or sha1: or both-None
            cli->>pol: run policies
        end
    else cache miss
        cli->>pol: run policies (P-01 .. P-11)
        pol->>sig: verify npm provenance (P-09)
        sig-->>pol: Pass + provenance_identity
        pol-->>cli: aggregate=pass
        cli->>cache: write row { content_hash=h, provenance_identity, scanned_at=now }
    end

    alt verdict=pass
        cli->>cli: emit --verbose audit log line
        cli->>pkg: exec npm install express
        pkg-->>cli: exit 0
        cli-->>user: exit 0
    else verdict=warn/block and not --force
        cli-->>user: exit 1 (no exec)
    end
```

---

## 5. Runtime — sigstore verification pipeline (P-09 / P-10)

The step order below mirrors `verify_dsse_bundle` in [`src/sigstore_verify.rs`](../../src/sigstore_verify.rs). Notable: subject-digest match runs **before** the chain walk so a digest mismatch produces a distinct error; the structural Fulcio-OID check runs **last** as a belt-and-braces assertion.

```mermaid
sequenceDiagram
    autonumber
    participant pol as npm_provenance / pypi_provenance
    participant sig as sigstore_verify
    participant snote as signed_note
    participant roots as embedded Fulcio + Rekor roots

    pol->>sig: verify(bundle, metadata.content_hash)
    sig->>sig: 1. decode DSSE payload
    sig->>sig: 2. parse SLSA + subject digest match vs metadata.content_hash
    sig->>sig: 3. extract leaf cert from verificationMaterial
    sig->>sig: 4. parse leaf cert (x509-parser)
    sig->>roots: 5. Fulcio chain walk against fulcio-roots/*.der
    roots-->>sig: chain ok
    sig->>sig: 6. extract public key from leaf
    sig->>sig: 7. DSSE signature verify (ECDSA P-256 over PAE)
    sig->>snote: 8. parse + verify_ecdsa_p256 (inclusion proof + signed checkpoint)
    snote-->>sig: ParsedNote (reused, no second parse)
    sig->>roots: verify Rekor signature against rekor-roots/rekor.pub
    roots-->>sig: signature ok
    sig->>sig: 9. integratedTime ∈ (notBefore, notAfter) of leaf cert
    sig->>sig: 10. extract first URI SAN as identity
    sig->>sig: 11. structural Fulcio OID check (belt-and-braces, LAST)
    sig-->>pol: Ok(provenance_identity)
```

Any failure ⇒ `PolicyResult::Block(reason naming the failing step)`. See [behaviors.md § B-018](../spec/behaviors.md#b-018-sigstore-verification-pipeline-npm--pypi).

---

## 6. Runtime — cache decision matrix

```mermaid
flowchart TD
    Lookup[Cache lookup<br/>name, resolved_version, registry] --> Hit{Row exists?}
    Hit -->|No| Scan[Full scan]
    Hit -->|Yes| FetchReg[Fetch registry digest]
    FetchReg --> Sha1{Cached starts with sha1:?}
    Sha1 -->|Yes| Scan
    Sha1 -->|No| Compare{cached vs registry}
    Compare -->|cached == registry| Honor[Honor cached verdict]
    Compare -->|cached != registry| Invalidate1[Invalidate + re-scan]
    Compare -->|cached set, registry None| Invalidate2[Invalidate + re-scan]
    Compare -->|cached None, registry set| ReScan1["Legacy row, upgrade + re-scan"]
    Compare -->|both None| ReScan2["Both-None: never honor, re-scan"]
    Compare -->|fetch fails| ReScan3[Re-scan, treat as failure-to-verify]
    Scan --> Write[Write cache row]
    Honor --> Done[Use verdict]
    Invalidate1 --> Scan
    Invalidate2 --> Scan
    ReScan1 --> Scan
    ReScan2 --> Scan
    ReScan3 --> Scan
```

The decision matrix is in [`../spec/data-model.md` § Cache decision matrix](../spec/data-model.md#cache-decision-matrix) and is verified by fitness functions F-002, F-007, and F-008 (see [fitness-functions.md § Rules](../spec/fitness-functions.md#rules)).

---

## Drift-audit checklist

When working on dep-scan, ask: does my change require any of these updates?

| Change | Updates required |
|--------|------------------|
| New external dependency (registry, API) | Section 1 (Context), Section 2 (Container) |
| New policy module | Section 3 (Component), [behaviors.md](../spec/behaviors.md) P-NN entry |
| New verification step in sigstore pipeline | Section 5 sequence, [behaviors.md § B-018](../spec/behaviors.md#b-018-sigstore-verification-pipeline-npm--pypi) |
| New CLI subcommand or flag | [interfaces.md](../spec/interfaces.md), Section 4 sequence if it changes flow |
| New cache decision branch | Section 6 flowchart, [data-model.md § Cache decision matrix](../spec/data-model.md#cache-decision-matrix), [F-NNN](../spec/fitness-functions.md) |
| New embedded trust root | [ADR 003 § Embedded trust roots](decisions/003-content-hash-cache-integrity.md), [architecture.md § Cross-cutting decisions](../spec/architecture.md#5-cross-cutting-decisions) |
