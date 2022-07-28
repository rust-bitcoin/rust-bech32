#!/bin/sh
#
# CI test script for rust-bech32.
#
# The "strict" feature is used to configure cargo to deny all warnings, always use it in test runs.

set -ex

# Sanity, check tools exist.
cargo --version
rustc --version

# Check without features ("strict" is a CI feature only, see above).
cargo build --no-default-features --features="strict"
cargo test --no-default-features --features="strict"

# Check "std" feature (implies "alloc").
cargo build --no-default-features --features="strict std"
cargo test --no-default-features --features="strict std"

# Check "alloc" feature alone.
cargo build --no-default-features --features="strict alloc"
cargo test --no-default-features --features="strict alloc"

exit 0
