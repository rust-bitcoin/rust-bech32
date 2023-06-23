// SPDX-License-Identifier: MIT

//! Iterator Adaptors
//!
//! This module provides iterator adaptors that can be used to verify and generate checksums, HRP
//! strings, etc., in a variety of ways, without any allocations.
//!
//! In general, directly using these adaptors is not very ergonomic, and users are recommended to
//! instead use the higher-level functions at the root of this crate.
//!
//! # Examples
//!
//! ```rust
//! use bech32::{Bech32, ByteIterExt, Fe32IterExt, Fe32, Hrp};
//!
//! let witness_prog = [
//!     0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
//!     0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
//!     0xf1, 0x43, 0x3b, 0xd6,
//! ];
//! let hrp = Hrp::parse_unchecked("bc");
//! let witness_version = Fe32::Q; // Witness version 0.
//! let iterator = witness_prog
//!     .iter()
//!     .copied()
//!     .bytes_to_fes() // Convert bytes to field elements in-line.
//!     .char_iter::<Bech32>(&hrp, Some(witness_version));
//! let hrpstring: String = iterator.collect();
//! assert_eq!(hrpstring.to_uppercase(), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4");
//! ```

use crate::primitives::checksum::{self, Checksum, PackedFe32};
use crate::primitives::gf32::Fe32;
use crate::primitives::hrp::{self, Hrp};

/// Extension trait for byte iterators which provides an adaptor to GF32 elements
pub trait ByteIterExt: Sized + Iterator<Item = u8> {
    /// Obtain the GF32 iterator
    fn bytes_to_fes(mut self) -> ByteToFeIter<Self> {
        ByteToFeIter { last_byte: self.next(), bit_offset: 0, iter: self }
    }
}
impl<I> ByteIterExt for I where I: Iterator<Item = u8> {}

/// Iterator adaptor that converts bytes to GF32 elements. If the total number
/// of bits is not a multiple of 5, it right-pads with 0 bits.
#[derive(Clone, PartialEq, Eq)]
pub struct ByteToFeIter<I: Iterator<Item = u8>> {
    last_byte: Option<u8>,
    bit_offset: usize,
    iter: I,
}

impl<I> Iterator for ByteToFeIter<I>
where
    I: Iterator<Item = u8>,
{
    type Item = Fe32;
    fn next(&mut self) -> Option<Fe32> {
        use core::cmp::Ordering::*;

        let bit_offset = {
            let ret = self.bit_offset;
            self.bit_offset = (self.bit_offset + 5) % 8;
            ret
        };

        if let Some(last) = self.last_byte {
            match bit_offset.cmp(&3) {
                Less => Some(Fe32((last >> (3 - bit_offset)) & 0x1f)),
                Equal => {
                    self.last_byte = self.iter.next();
                    Some(Fe32(last & 0x1f))
                }
                Greater => {
                    self.last_byte = self.iter.next();
                    let next = self.last_byte.unwrap_or(0);
                    Some(Fe32(((last << (bit_offset - 3)) | (next >> (11 - bit_offset))) & 0x1f))
                }
            }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min, max) = self.iter.size_hint();
        let (min, max) = match self.last_byte {
            // +1 because we set last_byte with call to `next`.
            Some(_) => (min + 1, max.map(|max| max + 1)),
            None => (min, max),
        };

        let min = bytes_len_to_fes_len(min);
        let max = max.map(bytes_len_to_fes_len);

        (min, max)
    }
}

/// The number of fes encoded by n bytes, rounded up because we pad the fes.
fn bytes_len_to_fes_len(bytes: usize) -> usize {
    let bits = bytes * 8;
    (bits + 4) / 5
}

/// Extension trait for field element iterators
pub trait Fe32IterExt: Sized + Iterator<Item = Fe32> {
    /// Adapts the `Fe32` iterator to output bytes instead.
    ///
    /// If the total number of bits is not a multiple of 8, any trailing bits
    /// are simply dropped.
    fn fes_to_bytes(mut self) -> FeToByteIter<Self> {
        FeToByteIter { last_fe: self.next(), bit_offset: 0, iter: self }
    }

    /// Adapts the `Fe32` iterator to output characters of the encoded bech32 string.
    fn char_iter<Ck: Checksum>(
        self,
        hrp: &Hrp,
        witness_version: Option<Fe32>,
    ) -> CharIter<Self, Ck> {
        CharIter::new(self, hrp, witness_version)
    }
}

impl<I> Fe32IterExt for I where I: Iterator<Item = Fe32> {}

/// Iterator adaptor that converts GF32 elements to bytes. If the total number
/// of bits is not a multiple of 8, any trailing bits are dropped.
///
/// Note that if there are 5 or more trailing bits, the result will be that
/// an entire field element is dropped. If this occurs, the input was an
/// invalid length for a bech32 string, but this iterator does not do any
/// checks for this.
#[derive(Clone, PartialEq, Eq)]
pub struct FeToByteIter<I: Iterator<Item = Fe32>> {
    last_fe: Option<Fe32>,
    bit_offset: usize,
    iter: I,
}

impl<I> Iterator for FeToByteIter<I>
where
    I: Iterator<Item = Fe32>,
{
    type Item = u8;
    fn next(&mut self) -> Option<u8> {
        let bit_offset = {
            let ret = self.bit_offset;
            self.bit_offset = (self.bit_offset + 8) % 5;
            ret
        };

        if let Some(last) = self.last_fe {
            let mut ret = last.0 << (3 + bit_offset);

            self.last_fe = self.iter.next();
            let next1 = self.last_fe?;
            if bit_offset > 2 {
                self.last_fe = self.iter.next();
                let next2 = self.last_fe?;
                ret |= next1.0 << (bit_offset - 2);
                ret |= next2.0 >> (7 - bit_offset);
            } else {
                ret |= next1.0 >> (2 - bit_offset);
                if self.bit_offset == 0 {
                    self.last_fe = self.iter.next();
                }
            }

            Some(ret)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // If the total number of bits is not a multiple of 8, any trailing bits are dropped.
        let fes_len_to_bytes_len = |n| n * 5 / 8;

        let (fes_min, fes_max) = self.iter.size_hint();
        let min = fes_len_to_bytes_len(fes_min);
        let max = fes_max.map(|max| fes_len_to_bytes_len(max) + 1);
        (min, max)
    }
}

/// Iterator adaptor which takes a stream of field elements, converts it to characters prefixed by
/// an HRP (and separator), and suffixed by the checksum i.e., converts the data in a stream of
/// field elements into stream of characters representing the encoded bech32 string.
pub struct CharIter<'hrp, I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    /// `None` once the hrp has been yielded.
    hrp_iter: Option<hrp::LowercaseCharIter<'hrp>>,
    /// `None` once witness version has been yielded.
    witness_version: Option<Fe32>,
    /// Iterator over the data to be encoded.
    fe_iter: I,
    /// Number of characters of the checksum still to be yielded.
    checksum_remaining: usize,
    /// The checksum engine.
    checksum_engine: checksum::Engine<Ck>,
}

impl<'hrp, I, Ck> CharIter<'hrp, I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    // Currently no checks done on validity of witness version.
    fn new(fe_iter: I, hrp: &'hrp Hrp, witness_version: Option<Fe32>) -> Self {
        let mut checksum_engine = checksum::Engine::new();
        checksum_engine.input_hrp(hrp);

        Self {
            hrp_iter: Some(hrp.lowercase_char_iter()),
            witness_version,
            fe_iter,
            checksum_remaining: Ck::CHECKSUM_LENGTH,
            checksum_engine,
        }
    }
}

impl<'hrp, I, Ck> Iterator for CharIter<'hrp, I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    type Item = char;

    fn next(&mut self) -> Option<char> {
        if let Some(ref mut hrp_iter) = self.hrp_iter {
            match hrp_iter.next() {
                Some(c) => return Some(c),
                None => {
                    self.hrp_iter = None;
                    return Some('1');
                }
            }
        }
        if let Some(witness_version) = self.witness_version {
            self.witness_version = None;
            self.checksum_engine.input_fe(witness_version);
            return Some(witness_version.to_char());
        }

        if let Some(fe) = self.fe_iter.next() {
            self.checksum_engine.input_fe(fe);
            return Some(fe.to_char());
        }

        if self.checksum_remaining == 0 {
            None
        } else {
            if self.checksum_remaining == Ck::CHECKSUM_LENGTH {
                self.checksum_engine.input_target_residue();
            }
            self.checksum_remaining -= 1;
            Some(Fe32(self.checksum_engine.residue().unpack(self.checksum_remaining)).to_char())
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (mut min, mut max) = match &self.hrp_iter {
            Some(iter) => {
                let (mut min, mut max) = iter.size_hint();
                min += 1;
                max = max.map(|max| max + 1);
                (min, max)
            }
            None => (0, Some(0)),
        };

        if self.witness_version.is_some() {
            min += 1;
            max = max.map(|max| max + 1);
        }

        let (fe_min, fe_max) = self.fe_iter.size_hint();
        min += fe_min;
        if let Some(fe_max) = fe_max {
            max = max.map(|max| max + fe_max);
        }
        min += self.checksum_remaining;
        max = max.map(|max| max + self.checksum_remaining);

        (min, max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterator_adaptors() {
        // This test is based on the test vector
        // BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4: 0014751e76e8199196d454941c45d1b3a323f1433bd6
        // from BIP-173.

        // 1. Convert bytes to field elements, via iterator
        #[rustfmt::skip]
        let data = [
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
            0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
            0xf1, 0x43, 0x3b, 0xd6,
        ];

        assert!(data
            .iter()
            .copied()
            .bytes_to_fes()
            .map(Fe32::to_char)
            .eq("w508d6qejxtdg4y5r3zarvary0c5xw7k".chars()));

        // 2. Convert field elements to bytes, via iterator
        let char_len = "w508d6qejxtdg4y5r3zarvary0c5xw7k".len();
        assert_eq!(data.iter().copied().bytes_to_fes().size_hint(), (char_len, Some(char_len)));

        let fe_iter = "w508d6qejxtdg4y5r3zarvary0c5xw7k"
            .bytes()
            .map(|b| Fe32::from_char(char::from(b)).unwrap());

        assert!(fe_iter.clone().fes_to_bytes().eq(data.iter().copied()));

        let iter = data.iter().copied().bytes_to_fes();
        assert_eq!(iter.size_hint().0, char_len);

        let hrp = Hrp::parse_unchecked("bc");
        let iter = iter.char_iter::<crate::Bech32>(&hrp, Some(Fe32::Q));

        let checksummed_len = 2 + 1 + 1 + char_len + 6;
        assert_eq!(iter.size_hint().0, checksummed_len);

        let encoded = iter.collect::<String>();
        println!("{}", encoded);

        assert_eq!(encoded, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        //        assert!(iter.eq("bc1w508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".chars()));
    }
}
