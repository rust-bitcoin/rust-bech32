#!/bin/sh
#
# CI test script for rust-bech32.
#
# The "strict" feature is used to configure cargo to deny all warnings, always use it in test runs.

set -ex

FEATURES="std alloc"

# Some tests require certain toolchain types.
NIGHTLY=false
if cargo --version | grep nightly; then
    NIGHTLY=true
fi

# Sanity, check tools exist.
cargo --version
rustc --version

# Run the linter if told to.
if [ "$DO_LINT" = true ]
then
    cargo clippy --all-features --all-targets -- -D warnings
fi

# Run formatter if told to.
if [ "$DO_FMT" = true ]; then
    if [ "$NIGHTLY" = false ]; then
        echo "DO_FMT requires a nightly toolchain (consider using RUSTUP_TOOLCHAIN)"
        exit 1
    fi
    rustup component add rustfmt
    cargo fmt --check
fi

# Check without features ("strict" is a CI feature only, see above).
cargo build --no-default-features --features="strict"
cargo test --no-default-features --features="strict"

# Check "std" feature (implies "alloc", so this is equivalent to --all-features).
cargo build --no-default-features --features="strict std"
cargo test --no-default-features --features="strict std"

# Check "alloc" feature alone.
cargo build --no-default-features --features="strict alloc"
cargo test --no-default-features --features="strict alloc"

exit 0
