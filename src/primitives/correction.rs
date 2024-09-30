// SPDX-License-Identifier: MIT

//! Error Correction
//!
//! Implements the Berlekamp-Massey algorithm to locate errors, with Forney's
//! equation to identify the error values, in a BCH-encoded string.
//!

use crate::primitives::decode::{
    CheckedHrpstringError, ChecksumError, InvalidResidueError, SegwitHrpstringError,
};
#[cfg(feature = "alloc")]
use crate::DecodeError;

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

/// Trait describing an error for which an error correction algorithm is applicable.
///
/// Essentially, this trait represents an error which contains an [`InvalidResidueError`]
/// variant.
pub trait CorrectableError {
    /// Given a decoding error, if this is a "checksum failed" error, extract
    /// that specific error type.
    ///
    /// There are many ways in which decoding a checksummed string might fail.
    /// If the string was well-formed in all respects except that the final
    /// checksum characters appear to be wrong, it is possible to run an
    /// error correction algorithm to attempt to extract errors.
    ///
    /// In all other cases we do not have enough information to do correction.
    ///
    /// This is the function that implementors should implement.
    fn residue_error(&self) -> Option<&InvalidResidueError>;
}

impl CorrectableError for InvalidResidueError {
    fn residue_error(&self) -> Option<&InvalidResidueError> { Some(self) }
}

impl CorrectableError for ChecksumError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            ChecksumError::InvalidResidue(ref e) => Some(e),
            _ => None,
        }
    }
}

impl CorrectableError for SegwitHrpstringError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            SegwitHrpstringError::Checksum(ref e) => e.residue_error(),
            _ => None,
        }
    }
}

impl CorrectableError for CheckedHrpstringError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            CheckedHrpstringError::Checksum(ref e) => e.residue_error(),
            _ => None,
        }
    }
}

#[cfg(feature = "alloc")]
impl CorrectableError for crate::segwit::DecodeError {
    fn residue_error(&self) -> Option<&InvalidResidueError> { self.0.residue_error() }
}

#[cfg(feature = "alloc")]
impl CorrectableError for DecodeError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            DecodeError::Checksum(ref e) => e.residue_error(),
            _ => None,
        }
    }
}
