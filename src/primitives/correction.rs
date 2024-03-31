// SPDX-License-Identifier: MIT

//! Error Correction
//!
//! Implements the Berlekamp-Massey algorithm to locate errors, with Forney's
//! equation to identify the error values, in a BCH-encoded string.
//!

/// **One more than** the maximum length (in characters) of a checksum which
/// can be error-corrected without an allocator.
///
/// When the **alloc** feature is enabled, this constant is practically irrelevant.
/// When the feature is disabled, it represents a length beyond which this library
/// does not support error correction.
///
/// If you need this value to be increased, please file an issue describing your
/// usecase. Bear in mind that an increased value will increase memory usage for
/// all users, and the focus of this library is the Bitcoin ecosystem, so we may
/// not be able to accept your request.
// This constant is also used when comparing bech32 residues against the
// bech32/bech32m targets, which should work with no-alloc. Therefore this
// constant must be > 6 (the length of the bech32(m) checksum).
//
// Otherwise it basically represents a tradeoff between stack usage and the
// size of error types, vs functionality in a no-alloc setting. The value
// of 7 covers bech32 and bech32m. To get the descriptor checksum we need a
// value and the descriptor checksum. To also get codex32 it should be >13,
// and for "long codex32" >15 ... but consider that no-alloc contexts are
// likely to be underpowered and will struggle to do correction on these
// big codes anyway.
//
// Perhaps we will want to add a feature gate, off by default, that boosts
// this to 16, or maybe even higher. But we will wait for implementors who
// complain.
pub const NO_ALLOC_MAX_LENGTH: usize = 7;
