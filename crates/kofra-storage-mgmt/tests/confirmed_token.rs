//! The confirmed token is read in one module only, behind the confirmation
//! checks (tenancy design §6.4: "A CI grep keeps it there"). The compiler
//! holds most of it: a `Confirmation` is opaque and made only from a
//! console credential, which only authentication can make, and a `Pass`
//! for the confirmed token is made only in `tokens.rs`. This test is the
//! grep for the rest, over every source file of the repository:
//!
//! 1. The confirmed token's secret name, or anything ending in
//!    `_CONFIRMED`, appears in code only where the Worker reads its
//!    settings (`workers/kofra-api/src/config.rs`), which puts it straight
//!    into `Tokens`.
//! 2. Only `tokens.rs` names the confirmed class or makes a pass, and the
//!    sign-up pass is asked for exactly once, by the tenancy port.
//! 3. Only `ports.rs` and `confirm.rs` name what a confirmation is, only
//!    authentication makes a console credential's proof, and the test-only
//!    confirmations are reached from tests only: the `test-support`
//!    feature is enabled from `[dev-dependencies]` only.
//!
//! 4. Only the Worker's settings reader reads its environment.
//!
//! Comments and a file's top-level `#[cfg(test)] mod tests` are not code
//! for these rules, nor are test directories. The Worker's wasm32 build
//! also refuses to compile with the test-only confirmations.

use std::{fs, path::Path};

/// Built at run time, so this file does not name it.
fn secret_name() -> String {
    ["STORAGE", "MGMT", "TOKEN", "CONFIRMED"].join("_")
}

const SKIP_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".git",
    ".venv",
    ".wrangler",
    "dist",
];
const CODE_EXT: &[&str] = &[
    "rs", "toml", "mjs", "js", "ts", "json", "yaml", "yml", "sh", "py", "go",
];

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(kind) = e.file_type() else { continue };
        if kind.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(root, &path, out);
            }
            continue;
        }
        let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("");
        if !kind.is_file() || !CODE_EXT.contains(&ext) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let rel = path
            .strip_prefix(root)
            .expect("under the root")
            .to_string_lossy()
            .replace('\\', "/");
        out.push((rel, text));
    }
}

fn repository() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = root.canonicalize().expect("repository root");
    let mut files = Vec::new();
    walk(&root, &root, &mut files);
    assert!(
        files
            .iter()
            .any(|(p, _)| p == "crates/kofra-storage-mgmt/src/tokens.rs"),
        "the walk must reach the sources"
    );
    files
}

/// The code lines of a non-test Rust source: no comments, nothing from
/// `#[cfg(test)] mod tests` on. `None` for test files and the contract
/// copy. Any other `#[cfg(test)]` item fails the test, so none can hide
/// the code after it.
fn code_lines(path: &str, text: &str) -> Option<Vec<(usize, String)>> {
    let is_src = path.ends_with(".rs") && path.contains("/src/");
    if !is_src || path.contains("/tests/") || path.starts_with("crates/mgmt-types/") {
        return None;
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        // Only a top-level test module ends the code; an indented one is
        // scanned like any other line.
        if *l == "#[cfg(test)]" {
            let next = lines[i + 1..]
                .iter()
                .map(|n| n.trim())
                .find(|n| !n.is_empty())
                .unwrap_or("");
            assert!(
                next == "mod tests {",
                "{path}:{}: a #[cfg(test)] item other than `mod tests` would hide code from this test",
                i + 1
            );
            break;
        }
        if !l.trim_start().starts_with("//") {
            out.push((i + 1, (*l).to_owned()));
        }
    }
    Some(out)
}

fn hits(files: &[(String, String)], allowed: &[&str], patterns: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, text) in files {
        if allowed.contains(&path.as_str()) {
            continue;
        }
        let Some(lines) = code_lines(path, text) else {
            continue;
        };
        for (n, line) in lines {
            if patterns.iter().any(|p| line.contains(p)) {
                out.push(format!("{path}:{n}: {}", line.trim()));
            }
        }
    }
    out
}

#[test]
fn the_confirmed_tokens_secret_is_read_only_by_the_settings() {
    let name = secret_name();
    let files = repository();
    let found: Vec<&str> = files
        .iter()
        .filter(|(p, text)| {
            !p.contains("/tests/") && (text.contains(&name) || text.contains("_CONFIRMED"))
        })
        .map(|(p, _)| p.as_str())
        .collect();
    assert_eq!(found, ["workers/kofra-api/src/config.rs"]);
}

/// The Worker reads its variables and secrets in one place, which hands
/// them to the settings: no other code can read the confirmed token under
/// another spelling of its name.
#[test]
fn only_the_settings_reader_reads_the_workers_environment() {
    let files = repository();
    let found = hits(
        &files,
        &["workers/kofra-api/src/lib.rs"],
        &["Reflect::get(env", ".secret(", ".var(", "secret_store"],
    );
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn only_the_tokens_module_reaches_the_confirmed_token() {
    let files = repository();
    let found = hits(
        &files,
        &["crates/kofra-storage-mgmt/src/tokens.rs"],
        &[
            "TokenClass::Confirmed",
            "TokenClass::{",
            "TokenClass::*",
            "TokenClass as",
            "Pass(",
            "signup_pass",
        ],
    );
    // The tenancy port asks for the sign-up pass, once; nothing else does.
    let tenancy = "crates/kofra-storage-mgmt/src/tenancy.rs:";
    let (signup, other): (Vec<String>, Vec<String>) = found
        .into_iter()
        .partition(|h| h.starts_with(tenancy) && h.contains("self.tokens.signup_pass()"));
    assert!(other.is_empty(), "{other:#?}");
    assert_eq!(signup.len(), 1, "{signup:#?}");
}

#[test]
fn only_confirm_decides_that_a_request_is_confirmed() {
    let files = repository();
    let what = hits(
        &files,
        &[
            "crates/kofra-api-core/src/ports.rs",
            "crates/kofra-api-core/src/confirm.rs",
        ],
        &[
            "ConfirmationKind",
            "confirm::testing",
            "testing::",
            "testing}",
            "testing,",
            "Confirmation(",
        ],
    );
    assert!(what.is_empty(), "{what:#?}");
    let proof = hits(
        &files,
        &["crates/kofra-api-core/src/auth.rs"],
        &["ConsoleProof("],
    );
    assert!(proof.is_empty(), "{proof:#?}");
    // The pipeline takes the confirmation from `confirm::of`, and only it
    // and `confirm` call that.
    let of = hits(
        &files,
        &[
            "crates/kofra-api-core/src/pipeline.rs",
            "crates/kofra-api-core/src/confirm.rs",
        ],
        &["confirm::of("],
    );
    assert!(of.is_empty(), "{of:#?}");
    let pipeline = &files
        .iter()
        .find(|(p, _)| p == "crates/kofra-api-core/src/pipeline.rs")
        .expect("pipeline")
        .1;
    assert!(pipeline.contains("confirmation: crate::confirm::of(&self.principal)"));
}

/// The test-only confirmations are compiled in only for tests: every
/// manifest line that names the `test-support` feature is the feature's
/// own definition or a `[dev-dependencies]` entry.
#[test]
fn test_confirmations_are_enabled_from_dev_dependencies_only() {
    let mut seen = 0;
    for (path, text) in repository() {
        if !path.ends_with("Cargo.toml") {
            continue;
        }
        let mut section = String::new();
        for (n, line) in text.lines().enumerate() {
            let l = line.trim();
            if l.starts_with('[') {
                section = l.to_owned();
                continue;
            }
            if l.starts_with('#') || !l.contains("test-support") {
                continue;
            }
            seen += 1;
            let feature_def = path == "crates/kofra-api-core/Cargo.toml"
                && section == "[features]"
                && l == "test-support = []";
            assert!(
                feature_def || section == "[dev-dependencies]",
                "{path}:{}: `test-support` outside [dev-dependencies]",
                n + 1
            );
        }
    }
    assert!(seen >= 2, "the feature and its dev-dependencies were found");
}
