#!/usr/bin/env bash
# Builds the Worker into build/ with pinned tools only. worker-build would
# otherwise download esbuild, wasm-bindgen and wasm-opt itself, unchecked:
# - wasm-bindgen: the CLI of the version in Cargo.lock, installed with
#   `cargo install --locked wasm-bindgen-cli@<version>` (from crates.io,
#   checksummed by Cargo), found on PATH or in WASM_BINDGEN_BIN;
# - esbuild: the copy pnpm installed from the lockfile (wrangler's own);
# - wasm-opt: not run (`--no-opt`); the release profile already builds
#   for size with LTO.
# Every build of the Worker (local, the e2e, CI, a deploy) runs this script.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
want=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' ../../Cargo.lock)
bin=${WASM_BINDGEN_BIN:-$(command -v wasm-bindgen || true)}
if [ -z "$bin" ]; then
  echo "build.sh: wasm-bindgen $want is needed: cargo install --locked wasm-bindgen-cli@$want" >&2
  exit 1
fi
have=$("$bin" --version | awk '{ print $2 }')
if [ "$have" != "$want" ]; then
  echo "build.sh: wasm-bindgen $have found, $want needed (Cargo.lock)" >&2
  exit 1
fi
esbuild=$(node -p "require.resolve('esbuild/bin/esbuild', { paths: [require.resolve('wrangler')] })")
WASM_BINDGEN_BIN="$bin" ESBUILD_BIN="$esbuild" worker-build --release --no-opt
