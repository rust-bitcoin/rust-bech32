// Written by the rust-bitcoin developers.
// SPDX-License-Identifier: MIT

//! Provides the internal nuts and bolts that enable bech32 encoding/decoding.
//!
//! The bech32 format is defined in BIP-173 and BIP-350. From BIP-173:
//!
//! > We first describe the general checksummed base32 format called Bech32 and then define
//! > Segregated Witness addresses using it.
//!
//! This module implements the more general bech32 format.
//!
//! ## Overview
//!
//! - [gf32](gf32): GF32 elements, i.e. "bech32 characters".
//! - [checksum](checksum): generic degree-2 BCH code checksum generation and locating, including
//!   traits for people to define their own correction (error location and correction).
//! - [hrp](hrp): Human-readable part (1-83 ASCII characters).
//! - [hrpstring](hrpstring): checksummed strings of GF32 elements, optionally with an HRP and a 1
//!   (separator); this also contains functionality for going from u5 to u8 and back.

pub mod checksum;
pub mod gf32;
pub mod hrp;
pub mod hrpstring;
pub mod iter;
