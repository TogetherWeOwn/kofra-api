//! The confirmed token is read in one module only, behind the confirmation
//! checks (tenancy design §6.4: "A CI grep keeps it there"). This test is
//! that grep, over every source file of the repository:
//!
//! 1. The confirmed token's secret name appears in code only where the
//!    Worker reads its settings (`workers/kofra-api/src/config.rs`), which
//!    puts it straight into `Tokens`.
//! 2. Only `tokens.rs` names the confirmed class or makes a sign-up pass,
//!    and only the tenancy port asks for one: no other code can reach the
//!    confirmed token. (The checked copy of the contract crate defines the
//!    class and is exempt.)
//! 3. Only `kofra-api-core`'s `confirm.rs` decides that a request is
//!    confirmed: no other source makes a `Confirmation` or sets one on an
//!    `Acting`.
//!
//! Comments and everything from a file's first `#[cfg(test)]` on are not
//! code for these rules, nor are test directories.

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

/// The code lines of a non-test Rust source: no comments, nothing from the
/// first `#[cfg(test)]` on. `None` for test files and the contract copy.
fn code_lines(path: &str, text: &str) -> Option<Vec<(usize, String)>> {
    let is_src = path.ends_with(".rs") && path.contains("/src/");
    if !is_src || path.contains("/tests/") || path.starts_with("crates/mgmt-types/") {
        return None;
    }
    Some(
        text.lines()
            .enumerate()
            .take_while(|(_, l)| l.trim() != "#[cfg(test)]")
            .filter(|(_, l)| !l.trim_start().starts_with("//"))
            .map(|(i, l)| (i + 1, l.to_owned()))
            .collect(),
    )
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
        .filter(|(p, text)| !p.contains("/tests/") && text.contains(&name))
        .map(|(p, _)| p.as_str())
        .collect();
    assert_eq!(found, ["workers/kofra-api/src/config.rs"]);
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
            "Pass(",
            "signup_pass",
        ],
    );
    // The tenancy port asks for the sign-up pass; nothing else does.
    let found: Vec<String> = found
        .into_iter()
        .filter(|h| {
            !(h.starts_with("crates/kofra-storage-mgmt/src/tenancy.rs:")
                && h.contains("self.tokens.signup_pass()"))
        })
        .collect();
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn only_confirm_decides_that_a_request_is_confirmed() {
    let files = repository();
    let found = hits(
        &files,
        &["crates/kofra-api-core/src/confirm.rs"],
        &[
            "Confirmation::Console",
            "Confirmation::Record",
            "confirmation: Some(",
        ],
    );
    assert!(found.is_empty(), "{found:#?}");
    // The pipeline takes the confirmation from `confirm::of`.
    let pipeline = &files
        .iter()
        .find(|(p, _)| p == "crates/kofra-api-core/src/pipeline.rs")
        .expect("pipeline")
        .1;
    assert!(pipeline.contains("confirmation: crate::confirm::of(&self.principal)"));
}
