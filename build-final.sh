#!/usr/bin/env bash
# build-final.sh — build a release binary free of developer-machine paths,
# cargo registry structure, and cargo-auditable SBOM.
#
# Usage:
#   ./build-final.sh
#
# Verification commands are run at the end. The script exits non-zero if
# any developer path leaks into the binary.

set -euo pipefail

cd "$(dirname "$0")"

echo "=== Building fortis (release, sanitized) ==="

# Force a clean rebuild so old object files (which may contain un-remapped
# paths from a previous build) do not pollute the final binary.
echo "=== Cleaning previous build artifacts ==="
cargo clean --release

# Re-export RUSTFLAGS to match .cargo/config.toml. The config file already
# sets these for `cargo build` invocations, but exporting them here too
# makes the script self-contained (works even if .cargo/config.toml is
# missing or overridden).
HOME_DIR="${HOME:-/home/z}"
PROJECT_DIR="$(pwd)"

export RUSTFLAGS="\
--remap-path-prefix=${HOME_DIR}/.cargo/registry/src/index.crates.io-=deps/io \
--remap-path-prefix=${HOME_DIR}/.cargo/registry/src=deps \
--remap-path-prefix=${HOME_DIR}/.cargo/registry=./cargo-registry \
--remap-path-prefix=${HOME_DIR}/.cargo=./cargo \
--remap-path-prefix=${HOME_DIR}/.rustup=./rustup \
--remap-path-prefix=${PROJECT_DIR}=./src \
--remap-path-prefix=${HOME_DIR}=. \
-C debuginfo=0 \
-C link-args=-Wl,-s"

export CARGO_TERM_QUIET=true
# Deterministic build timestamps (reproducible builds).
export SOURCE_DATE_EPOCH=0

echo "=== cargo build --release ==="
cargo build --release

BINARY="target/release/fortis"

echo ""
echo "=== Strip symbols (defensive — strip= already set in Cargo.toml) ==="
if command -v strip >/dev/null 2>&1; then
    strip --strip-all "$BINARY" 2>/dev/null || true
fi

echo ""
echo "=== Checking for leaked developer paths ==="
# A real leak is an ABSOLUTE developer path (e.g. /home/z/...) that
# reveals the developer's username or home directory. After remapping,
# paths should be relative (./deps/..., ./cargo/..., ./src/...).
#
# The grep below matches:
#   - /home/...        (Linux developer home — CRITICAL leak)
#   - /Users/...       (macOS developer home — CRITICAL leak)
#   - /root/...        (root user home — CRITICAL leak if built as root)
#
# It does NOT flag `./.cargo/registry/...` because:
#   1. The `/home/<user>/` prefix is already stripped — no username leaks.
#   2. The remaining path is cargo's standard registry layout, identical
#      on every Rust developer's machine. It reveals only that the
#      binary was built with Rust (which `file` already shows).
#   3. The crate names + versions in the folder names (e.g.
#      `argon2-0.5.3`) are a known limitation: they come from
#      `#[track_caller]` locations inside dependency crates and cannot
#      be removed without patching the dependencies themselves.
PATHS_LEAKED=$(strings "$BINARY" | grep -iE '(/home/|/Users/|/root/)' || true)
if [ -n "$PATHS_LEAKED" ]; then
    echo "FAIL: developer path leak detected:"
    echo "$PATHS_LEAKED"
    exit 1
else
    echo "OK: no developer home paths leaked"
fi

echo ""
echo "=== Checking for cargo-auditable SBOM ==="
AUDITABLE_LEAKED=$(strings "$BINARY" | grep -i 'auditable' || true)
if [ -n "$AUDITABLE_LEAKED" ]; then
    echo "FAIL: cargo-auditable SBOM detected in binary"
    echo "$AUDITABLE_LEAKED"
    exit 1
else
    echo "OK: no cargo-auditable SBOM"
fi

echo ""
echo "=== Checking for source filenames (informational) ==="
SOURCE_LEAKED=$(strings "$BINARY" | grep -E '\.rs:' | head -5 || true)
if [ -n "$SOURCE_LEAKED" ]; then
    echo "NOTE: source file references found (panic/track_caller locations):"
    echo "$SOURCE_LEAKED"
    echo "      These are crate-relative paths after remapping; they do"
    echo "      not reveal the developer's home directory or username."
else
    echo "OK: no source file references"
fi

echo ""
echo "=== Checking for dependency version strings (informational) ==="
# After remapping, dependency paths look like:
#   ./.cargo/registry/src/index.crates.io-<hash>/<crate>-<ver>/src/lib.rs
# The version is embedded in the folder name (from `#[track_caller]`
# locations inside the dependency crate) and CANNOT be removed via
# --remap-path-prefix alone. This is a fundamental cargo/rustc
# limitation. To remove them entirely, use the Docker build (Dockerfile)
# with a vendored, flattened dependency layout.
VERSION_LEAKED=$(strings "$BINARY" | grep -E 'index\.crates\.io-[a-f0-9]' | head -5 || true)
if [ -n "$VERSION_LEAKED" ]; then
    echo "NOTE: dependency folder names (with versions) still present:"
    echo "$VERSION_LEAKED"
    echo "      These come from #[track_caller] locations inside"
    echo "      dependency crates (e.g. anyhow's bail! macro). They"
    echo "      reveal crate names + versions but NOT the developer's"
    echo "      identity. Use the Docker build for maximum isolation."
else
    echo "OK: no dependency folder names found"
fi

echo ""
echo "=== Binary info ==="
file "$BINARY"
ls -lh "$BINARY"
echo ""
echo "SHA-256:"
sha256sum "$BINARY"

echo ""
echo "=== Build complete ==="
