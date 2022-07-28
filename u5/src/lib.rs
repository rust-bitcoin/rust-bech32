// Written by Clark Moody and the rust-bitcoin developers.
// SPDX-License-Identifier: MIT

//! A 5 bit unsigned integer.
//!
//! An integer in the range 0..32 used by [`bech32`] encoding.
//!
//! [`bech32`]: <https://docs.rs/bech32/>
//!

#![deny(missing_docs)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![cfg_attr(feature = "strict", deny(warnings))]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

use core::convert::TryFrom;
use core::fmt;

/// Integer in the range `0..32` i.e., a a 5 bit integer.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub struct u5(u8);

impl u5 {
    /// The zero value.
    pub const ZERO: u5 = u5(0);

    /// Constructs a `u5` from the low 5 bits of `value`.
    pub fn from_low_5_bits(value: u8) -> Self { u5(value & 0x1f) }

    /// Returns a copy of the underlying `u8` value.
    pub fn to_u8(self) -> u8 { self.0 }
}

impl From<u5> for u8 {
    fn from(v: u5) -> u8 { v.0 }
}

impl TryFrom<u8> for u5 {
    type Error = OverflowError;

    /// Errors if `value` is out of range.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 31 {
            Err(OverflowError(value))
        } else {
            Ok(u5(value))
        }
    }
}

impl AsRef<u8> for u5 {
    fn as_ref(&self) -> &u8 { &self.0 }
}

/// Value is invalid, overflows a `u5`.
#[derive(Clone, Debug, PartialEq)]
pub struct OverflowError(u8);

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "value is invalid, overflows a u5)")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OverflowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}
