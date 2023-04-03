#!/bin/sh
#
# CI test script for rust-bech32.

set -eu
set -x

# "arrayvec" feature breaks the MSRV, its added manually in DO_FEATURE_MATRIX loop below.
FEATURES="std alloc"

# Some tests require certain toolchain types.
NIGHTLY=false
MSRV=false
if cargo --version | grep nightly; then
    NIGHTLY=true
fi
if cargo --version | grep "1\.48"; then
    MSRV=true
fi

build_and_test () {
    cargo build --no-default-features --features="$1"
    cargo test --no-default-features --features="$1"
}

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

if [ "${DO_FEATURE_MATRIX-false}" = true ]; then
    # No features
    build_and_test ""

    # Feature combos
    build_and_test "std"
    build_and_test "alloc"
    build_and_test "std alloc"
    # arrayvec breaks the MSRV
    if [ $MSRV = false
       ]; then
        build_and_test "arrayvec"
        build_and_test "std arrayvec"
        build_and_test "alloc arrayvec"
    fi
fi

exit 0
