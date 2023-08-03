// SPDX-License-Identifier: MIT

//! Segregated Witness functionality - useful for enforcing parts of [`BIP-173`] and [`BIP-350`].
//!
//! [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
//! [BIP-350]: <https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki>

use core::fmt;

use crate::primitives::gf32::Fe32;

/// Returns true if given field element represents a valid segwit version.
pub fn is_valid_witness_version(witness_version: Fe32) -> bool {
    validate_witness_version(witness_version).is_ok()
}

/// Returns true if `length` represents a valid witness program length for `witness_version`.
pub fn is_valid_witness_program_length(length: usize, witness_version: Fe32) -> bool {
    validate_witness_program_length(length, witness_version).is_ok()
}

/// Checks that the given field element represents a valid segwit witness version.
pub fn validate_witness_version(witness_version: Fe32) -> Result<(), InvalidWitnessVersionError> {
    if witness_version.to_u8() > 16 {
        Err(InvalidWitnessVersionError(witness_version))
    } else {
        Ok(())
    }
}

/// Validates the segwit witness program `length` rules for witness `version`.
pub fn validate_witness_program_length(
    length: usize,
    version: Fe32,
) -> Result<(), WitnessLengthError> {
    use WitnessLengthError::*;

    if length < 2 {
        return Err(TooShort);
    }
    if length > 40 {
        return Err(TooLong);
    }
    if version == Fe32::Q && length != 20 && length != 32 {
        return Err(InvalidSegwitV0);
    }
    Ok(())
}

/// Field element does not represent a valid witness version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidWitnessVersionError(Fe32);

impl fmt::Display for InvalidWitnessVersionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "field element does not represent a valid witness version")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidWitnessVersionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Witness program invalid because of incorrect length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WitnessLengthError {
    /// The witness data is too short.
    TooShort,
    /// The witness data is too long.
    TooLong,
    /// The segwit v0 witness is not 20 or 32 bytes long.
    InvalidSegwitV0,
}

impl fmt::Display for WitnessLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use WitnessLengthError::*;

        match *self {
            TooShort => write!(f, "witness program is less than 2 bytes long"),
            TooLong => write!(f, "witness program is more than 40 bytes long"),
            InvalidSegwitV0 => write!(f, "the segwit v0 witness is not 20 or 32 bytes long"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WitnessLengthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use WitnessLengthError::*;

        match *self {
            TooShort | TooLong | InvalidSegwitV0 => None,
        }
    }
}
