// Written by the rust-bitcoin developers.
// SPDX-License-Identifier: MIT

//! Provides the internal nuts and bolts that enable bech32 encoding/decoding.
//!
//! ## Overview
//!
//! - `gf32`: GF32 elements, i.e. "bech32 characters".
//! - `hrp`: human-readable part.

pub mod gf32;
pub mod hrp;
