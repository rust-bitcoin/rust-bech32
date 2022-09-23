#!/bin/sh
#
# CI test script for rust-bech32.
#
# The "strict" feature is used to configure cargo to deny all warnings, always use it in test runs.

set -eu
set -x

# Some tests require certain toolchain types.
NIGHTLY=false
MIN_VERSION=false
if cargo --version | grep nightly; then
    NIGHTLY=true
fi
if cargo --version | grep 1.41; then
    MIN_VERSION=true
fi

# Sanity, check tools exist.
cargo --version
rustc --version

# Run the linter if told to.
if [ "${DO_LINT-false}" = true ]
then
    cargo clippy --all-features --all-targets -- -D warnings
fi

# Run formatter if told to.
if [ "${DO_FMT-false}" = true ]; then
    if [ "$NIGHTLY" = false ]; then
        echo "DO_FMT requires a nightly toolchain (consider using RUSTUP_TOOLCHAIN)"
        exit 1
    fi
    rustup component add rustfmt
    cargo fmt --check
fi

check () {
    cargo build --no-default-features --features="strict $1"
    cargo test --no-default-features --features="strict $1"
}

# Check without features ("strict" is a CI feature only, see above).
check ""

# Check "arrayvec" feature alone.
if [ "$MIN_VERSION" != true ]; then
    check "arrayvec"
fi

# Check "alloc" feature alone.
check "alloc"

# Check "alloc" & "arrayvec" features together.
if [ "$MIN_VERSION" != true ]; then
    check "alloc arrayvec"
fi

# Check "std" feature (implies "alloc", so this is equivalent to --all-features).
cargo build --no-default-features --features="std"
cargo test --no-default-features --features="std"

# Check "std" & "arrayvec" features together.
if [ "$MIN_VERSION" != true ]; then
    check "std arrayvec"
fi

exit 0
