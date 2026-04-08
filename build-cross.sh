#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')}"
OUT_DIR="dist"
BINARY="sox"

echo "=== Building $BINARY v$VERSION ==="
echo ""

mkdir -p "$OUT_DIR"

# ─────────────────────────────────────────────
# 1. macOS (native)
# ─────────────────────────────────────────────
echo "▸ [1/3] macOS aarch64 (native)..."
cargo build --release --target aarch64-apple-darwin 2>&1 | tail -1
cp "target/aarch64-apple-darwin/release/$BINARY" "$OUT_DIR/${BINARY}-v${VERSION}-macos-arm64"
echo "  ✓ $OUT_DIR/${BINARY}-v${VERSION}-macos-arm64"

# ─────────────────────────────────────────────
# 2. Windows x86_64 (mingw)
# ─────────────────────────────────────────────
echo "▸ [2/3] Windows x86_64 (mingw)..."

# Ensure target is installed
rustup target add x86_64-pc-windows-gnu 2>/dev/null || true

# Check for mingw
if ! command -v x86_64-w64-mingw32-gcc &>/dev/null; then
    echo "  ✗ Missing mingw. Install: brew install mingw-w64"
    exit 1
fi

# Configure linker for this target
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="x86_64-w64-mingw32-gcc"

cargo build --release --target x86_64-pc-windows-gnu 2>&1 | tail -1
cp "target/x86_64-pc-windows-gnu/release/${BINARY}.exe" "$OUT_DIR/${BINARY}-v${VERSION}-windows-amd64.exe"
echo "  ✓ $OUT_DIR/${BINARY}-v${VERSION}-windows-amd64.exe"

# ─────────────────────────────────────────────
# 3. Linux x86_64 (musl — static binary)
# ─────────────────────────────────────────────
echo "▸ [3/3] Linux x86_64 (musl, static)..."

# Ensure target is installed
rustup target add x86_64-unknown-linux-musl 2>/dev/null || true

# Try to find musl cross-compiler
MUSL_CC=""
for cc in x86_64-linux-musl-gcc x86_64-unknown-linux-musl-gcc musl-gcc; do
    if command -v "$cc" &>/dev/null; then
        MUSL_CC="$cc"
        break
    fi
done

if [ -z "$MUSL_CC" ]; then
    echo "  ⚠ No musl-gcc found. Attempting to install via brew..."
    if command -v brew &>/dev/null; then
        brew install filosottile/musl-cross/musl-cross 2>&1 | tail -3
        MUSL_CC="x86_64-linux-musl-gcc"
    fi
fi

if [ -z "$MUSL_CC" ] || ! command -v "$MUSL_CC" &>/dev/null; then
    echo "  ✗ Cannot find musl cross-compiler."
    echo "    Install: brew install filosottile/musl-cross/musl-cross"
    echo "    Or use Docker: docker run --rm -v \$(pwd):/src rust:alpine sh -c 'cd /src && cargo build --release'"
    exit 1
fi

export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$MUSL_CC"
export CC_x86_64_unknown_linux_musl="$MUSL_CC"

cargo build --release --target x86_64-unknown-linux-musl 2>&1 | tail -1
cp "target/x86_64-unknown-linux-musl/release/$BINARY" "$OUT_DIR/${BINARY}-v${VERSION}-linux-amd64"
echo "  ✓ $OUT_DIR/${BINARY}-v${VERSION}-linux-amd64"

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo "=== Build Complete ==="
echo ""
ls -lh "$OUT_DIR/${BINARY}-v${VERSION}-"* 2>/dev/null | awk '{print $5, $NF}'
echo ""
echo "All binaries in: $OUT_DIR/"
