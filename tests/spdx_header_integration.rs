// SPDX-License-Identifier: Apache-2.0
//! Task 111: every first-party `.rs` file under `src/` must carry the SPDX
//! license header as its literal first line. Regression guard for the
//! relicense follow-up (see docs/tasks/completed/111-apache-relicense-followup.md).

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const EXPECTED_HEADER: &str = "// SPDX-License-Identifier: Apache-2.0";

/// Recursively collect every `*.rs` path under `dir`. No third-party crate:
/// directory-based walk, so a new file added anywhere under `src/` is picked
/// up automatically without touching this test (T-111-02).
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("failed to read dir {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn all_first_party_rs_files_have_spdx_header() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);

    assert!(
        !files.is_empty(),
        "expected to find first-party .rs files under {}; walk found none (bug in the walk, not a pass)",
        src_dir.display()
    );

    let mut missing = Vec::new();
    for file in &files {
        let f = fs::File::open(file)
            .unwrap_or_else(|e| panic!("failed to open {}: {e}", file.display()));
        let mut first_line = String::new();
        BufReader::new(f)
            .read_line(&mut first_line)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", file.display()));
        if first_line.trim_end_matches(['\n', '\r']) != EXPECTED_HEADER {
            missing.push(file.display().to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "the following first-party .rs files are missing the SPDX header as line 1:\n{}",
        missing.join("\n")
    );
}
