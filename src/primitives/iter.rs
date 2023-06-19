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
//! use bech32::primitives::iter::{ByteIterExt, Fe32IterExt};
//! use bech32::primitives::gf32::Fe32;
//! use bech32::primitives::hrp::Hrp;
//! use bech32::primitives::Bech32;
//!
//! let witness_prog = [
//!     0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
//!     0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
//!     0xf1, 0x43, 0x3b, 0xd6,
//! ];
//! let hrp = Hrp::parse_unchecked("bc");
//! let iterator = witness_prog
//!     .iter()
//!     .copied() // Iterate over bytes.
//!     .bytes_to_fes() // Convert bytes to field elements in-line.
//!     .with_witness_v0() // Pre-pend witness version.
//!     .checksum::<Bech32>() // Convert to a [`ChecksumIter`] (append a bech32 checksum).
//!     .with_checksummed_hrp(&hrp) // Feed HRP into the checksum.
//!     .hrp_char(&hrp); // Turn the fe stream into a char stream with HRP.
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
    /// Adapts the Fe32 iterator to output bytes instead.
    ///
    /// If the total number of bits is not a multiple of 8, any trailing bits
    /// are simply dropped.
    fn fes_to_bytes(mut self) -> FeToByteIter<Self> {
        FeToByteIter { last_fe: self.next(), bit_offset: 0, iter: self }
    }

    /// Adapts the Fe32 iterator by prepending `Fe::32:Q` (witness version 0).
    fn with_witness_v0(self) -> WitnessVersionIter<Self> { self.with_witness_version(Fe32::Q) }

    /// Adapts the Fe32 iterator by prepending `Fe::32:P` (witness version 1).
    fn with_witness_v1(self) -> WitnessVersionIter<Self> { self.with_witness_version(Fe32::P) }

    /// Adapts the Fe32 iterator by prepending `fe` (witness version).
    ///
    /// Accepts any `Fe32`, does no checks on the validity of `witness_version`.
    fn with_witness_version(self, witness_version: Fe32) -> WitnessVersionIter<Self> {
        WitnessVersionIter { witness_version: Some(witness_version), iter: self }
    }

    /// Adapts the Fe32 iterator to append a checksum to the end of the data.
    ///
    /// Because the HRP of a bech32 string needs to be expanded before being
    /// checksummed, this iterator is a little bit inconvenient to use on raw
    /// data. The [`ChecksumIter::with_checksummed_hrp`] methods may be of use.
    fn checksum<Ck: Checksum>(self) -> ChecksumIter<Self, Ck> {
        ChecksumIter {
            iter: self,
            checksum_remaining: Ck::CHECKSUM_LENGTH,
            checksum_engine: checksum::Engine::new(),
        }
    }

    /// Adapts the Fe32 iterator to output characters using `hrp` for the human-readable part.
    ///
    /// Note, `hrp` is expected to be the same as that fed into the checksum engine with
    /// `with_checksummed_hrp`.
    fn hrp_char(self, hrp: &Hrp) -> HrpCharIter<'_, Self> {
        HrpCharIter { hrp_iter: hrp.lowercase_char_iter(), fe_iter: self, hrp_done: false }
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

/// Iterator adaptor that just prepends a single character to a field element stream.
///
/// More ergonomic to use than `std::iter::once(fe).chain(iter)`.
pub struct WitnessVersionIter<I>
where
    I: Iterator<Item = Fe32>,
{
    witness_version: Option<Fe32>,
    iter: I,
}

impl<I> Iterator for WitnessVersionIter<I>
where
    I: Iterator<Item = Fe32>,
{
    type Item = Fe32;

    fn next(&mut self) -> Option<Fe32> { self.witness_version.take().or_else(|| self.iter.next()) }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min, max) = self.iter.size_hint();
        match self.witness_version {
            None => (min, max),
            Some(_) => (min + 1, max.map(|max| max + 1)),
        }
    }
}

/// Iterator adaptor for field-element-yielding iterator, which tacks a
/// checksum onto the end of the yielded data.
#[derive(Clone, PartialEq, Eq)]
pub struct ChecksumIter<I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    iter: I,
    checksum_remaining: usize,
    checksum_engine: checksum::Engine<Ck>,
}

impl<I, Ck> ChecksumIter<I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    /// Helper function to input an HRP into the underlying checksum engine of the iterator.
    ///
    /// This function is infallible, but if you feed it a non-ASCII `hrp` it probably will
    /// cause your checksum engine to produce useless results.
    ///
    /// Also, if you call this function after the iterator has already yielded a value then
    /// you will get useless results.
    pub fn with_checksummed_hrp(mut self, hrp: &Hrp) -> Self {
        self.checksum_engine.input_hrp(hrp);
        self
    }

    /// Helper function to input an extra field element into the underling
    /// checksum engine of the iterator.
    pub fn with_checksummed_fe(mut self, fe: Fe32) -> Self {
        self.checksum_engine.input_fe(fe);
        self
    }
}

impl<I, Ck> Iterator for ChecksumIter<I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    type Item = Fe32;

    fn next(&mut self) -> Option<Fe32> {
        match self.iter.next() {
            Some(fe) => {
                self.checksum_engine.input_fe(fe);
                Some(fe)
            }
            None =>
                if self.checksum_remaining == 0 {
                    None
                } else {
                    if self.checksum_remaining == Ck::CHECKSUM_LENGTH {
                        self.checksum_engine.input_target_residue();
                    }
                    self.checksum_remaining -= 1;
                    Some(Fe32(self.checksum_engine.residue().unpack(self.checksum_remaining)))
                },
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min, max) = self.iter.size_hint();
        (min + self.checksum_remaining, max.map(|max| max + self.checksum_remaining))
    }
}

/// Iterator adaptor which takes a stream of field elements, converts it to characters prefixed by
/// an HRP. If `fe_iter` is a checksummed iter, it is expected that the `hrp` strings are identical.
pub struct HrpCharIter<'hrp, I>
where
    I: Iterator<Item = Fe32>,
{
    hrp_iter: hrp::LowercaseCharIter<'hrp>,
    fe_iter: I,
    hrp_done: bool,
}

impl<'hrp, I> Iterator for HrpCharIter<'hrp, I>
where
    I: Iterator<Item = Fe32>,
{
    type Item = char;

    fn next(&mut self) -> Option<char> {
        if !self.hrp_done {
            match self.hrp_iter.next() {
                Some(c) => return Some(c),
                None => {
                    self.hrp_done = true;
                    return Some('1');
                }
            }
        }
        self.fe_iter.next().map(Fe32::to_char)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min, max) = self.fe_iter.size_hint();
        let add = if !self.hrp_done {
            self.hrp_iter.len() + 1 // hrp | SEP
        } else {
            0
        };

        (min + add, max.map(|max| max + add))
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

        let checksummed_len = char_len + 6;
        let iter = iter.checksum::<crate::primitives::Bech32>();
        assert_eq!(iter.size_hint().0, checksummed_len);

        let hrp = Hrp::parse_unchecked("bc");
        // Does not add the hrp to the iterator, only adds it to the checksum engine.
        let iter = iter.with_checksummed_hrp(&hrp);
        assert_eq!(iter.size_hint().0, checksummed_len);

        // Does not add the separator to the iterator, only adds it to the checksum engine.
        let iter = iter.with_checksummed_fe(Fe32::Q);
        assert_eq!(iter.size_hint().0, checksummed_len);

        let iter = iter.map(Fe32::to_char);
        assert_eq!(iter.size_hint().0, checksummed_len);

        assert!(iter.eq("w508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".chars()));
    }
}
