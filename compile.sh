#!/bin/bash
# Cross-compile qsftp for x86_64 Linux, aarch64 Linux, and aarch64 macOS (Apple Silicon)
# Outputs tarballs to ./to_github/ matching install.sh naming convention
#
# Works on both Linux and macOS:
#   - Linux targets use `cross` (Docker-based) when not on Linux
#   - macOS target builds natively on macOS, skipped on Linux

set -euo pipefail

VERSION="v$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')"
OUTDIR="./to_github"
BINARIES="qsshd qsftp qscp qssh"
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

TARGETS=(
    "x86_64-unknown-linux-gnu:x86_64:linux"
    "aarch64-unknown-linux-gnu:aarch64:linux"
    "aarch64-apple-darwin:aarch64:darwin"
)

needs_cross() {
    local target="$1"
    case "${HOST_OS}" in
        Linux)
            # Native on Linux x86_64, cross-compile aarch64
            [ "$target" = "x86_64-unknown-linux-gnu" ] && [ "$HOST_ARCH" = "x86_64" ] && return 1
            [ "$target" = "aarch64-unknown-linux-gnu" ] && [ "$HOST_ARCH" = "aarch64" ] && return 1
            [[ "$target" == *"-linux-"* ]] && return 0
            return 0
            ;;
        Darwin)
            # Native on macOS ARM, everything else needs cross
            [ "$target" = "aarch64-apple-darwin" ] && [ "$HOST_ARCH" = "arm64" ] && return 1
            return 0
            ;;
    esac
    return 0
}

can_build() {
    local target="$1"
    if needs_cross "$target"; then
        if command -v cross &>/dev/null; then
            return 0
        fi
        # No cross tool available — can't cross-compile
        return 1
    fi
    return 0
}

echo "==> Building qsftp ${VERSION}"
echo "==> Host: ${HOST_OS} ${HOST_ARCH}"
echo "==> Output: ${OUTDIR}/"
echo

rm -rf "${OUTDIR}"
mkdir -p "${OUTDIR}"

BUILT=0
SKIPPED=0

for entry in "${TARGETS[@]}"; do
    IFS=':' read -r target arch os <<< "$entry"
    tarball="qsftp-${VERSION}-${arch}-${os}.tar.gz"

    if ! can_build "$target"; then
        echo "--- Skipping ${target} (can't cross-compile from ${HOST_OS}, install 'cross' for Docker-based builds) ---"
        echo
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    echo "--- Building ${target} ---"

    rustup target add "${target}" 2>/dev/null || true

    if needs_cross "$target"; then
        cross build --release --target "${target}"
    else
        cargo build --release --target "${target}"
    fi

    # Package binaries into tarball
    STAGE=$(mktemp -d)
    for bin in ${BINARIES}; do
        cp "target/${target}/release/${bin}" "${STAGE}/${bin}"
    done
    tar -czf "${OUTDIR}/${tarball}" -C "${STAGE}" .
    rm -rf "${STAGE}"

    echo "==> ${OUTDIR}/${tarball}"
    echo
    BUILT=$((BUILT + 1))
done

echo "=== Done: ${BUILT} built, ${SKIPPED} skipped ==="
ls -lh "${OUTDIR}/"

# Build native executable for current host
echo
echo "--- Building native executable for host (${HOST_OS} ${HOST_ARCH}) ---"
cargo build --release

# Copy binaries to project root
for bin in ${BINARIES}; do
    cp "target/release/${bin}" "./${bin}"
    echo "==> Copied ./${bin}"
done
