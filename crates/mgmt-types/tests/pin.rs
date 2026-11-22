//! This crate is a checked copy of the storage management plane's wire
//! contract crate. `PIN` names the upstream commit and the SHA-256 of the
//! copied tree (the generated `Cargo.toml` and `src/`); this test
//! recomputes the hash, so a local edit, a missing or an added file, or a
//! partial upgrade fails CI. Nothing else may sit in the crate: no build
//! script, no other target.
//!
//! The hash: for `Cargo.toml` and every file under `src/`, sorted by path
//! bytewise, one line `<sha256 hex>  <path>\n` (as `sha256sum` prints it);
//! then the SHA-256 of those lines. The same value comes from
//! `{ printf 'Cargo.toml\0'; find src -type f -print0; } | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum`
//! in the crate's directory.

use std::{fs, path::Path};

use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every file under `dir`, as paths relative to `root` with `/`; fails on
/// anything that is not a regular file or a directory, or on a name that is
/// not plain.
fn files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("directory entry"))
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let kind = fs::symlink_metadata(&path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .file_type();
        let rel = path
            .strip_prefix(root)
            .expect("under the crate")
            .to_str()
            .expect("UTF-8 path")
            .replace('\\', "/");
        assert!(
            rel.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b)),
            "{rel}: not a plain file name"
        );
        if kind.is_dir() {
            files(root, &path, out);
        } else {
            assert!(kind.is_file(), "{rel}: not a regular file");
            out.push(rel);
        }
    }
}

fn tree_hash(root: &Path) -> String {
    let mut paths = vec!["Cargo.toml".to_owned()];
    files(root, &root.join("src"), &mut paths);
    paths.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut manifest = Sha256::new();
    for p in &paths {
        let bytes = fs::read(root.join(p)).unwrap_or_else(|e| panic!("read {p}: {e}"));
        manifest.update(format!("{}  {p}\n", hex(&Sha256::digest(&bytes))));
    }
    hex(&manifest.finalize())
}

/// The names in `dir`, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut n: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    n.sort();
    n
}

#[test]
fn the_crate_holds_the_copy_and_this_test_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(names(root), ["Cargo.toml", "PIN", "src", "tests"]);
    assert_eq!(names(&root.join("tests")), ["pin.rs"]);
}

#[test]
fn the_source_tree_matches_its_pin() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let pin = fs::read_to_string(root.join("PIN")).expect("PIN");
    let mut parts = pin.trim_end_matches('\n').split(' ');
    let (Some(commit), Some(hash), None) = (parts.next(), parts.next(), parts.next()) else {
        panic!("PIN is not `<commit> <sha256>`");
    };
    let lower_hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    assert!(lower_hex(commit, 40), "PIN commit is not 40 lowercase hex");
    assert!(lower_hex(hash, 64), "PIN hash is not 64 lowercase hex");
    assert_eq!(
        tree_hash(root),
        hash,
        "src/ differs from the copy pinned at {commit}: re-run the copy, never edit src/"
    );
}
