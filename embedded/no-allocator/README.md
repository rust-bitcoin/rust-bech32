# no_std test crate without an allocator

This crate is based on the blog post found at:

 https://blog.dbrgn.ch/2019/12/24/testing-for-no-std-compatibility/

Its purpose is to test that the `rust-bech32` library can be built in a `no_std` environment without
a global allocator.

Build with: `cargo rustc -- -C link-arg=-nostartfiles`.
