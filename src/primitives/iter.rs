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
//!
//! // You can get a checksum iterator over field elements.
//! let iter = witness_prog
//!     .iter()
//!     .copied()
//!     .bytes_to_fes()
//!     .checksummed::<Bech32>()
//!     .with_witness_version(Fe32::Q); // Optionally add witness version.
//!
//! // Or if you have an HRP and witness version.
//!
//! let hrp = Hrp::parse_unchecked("bc");
//! let witness_version = Fe32::Q; // Witness version 0.
//!
//! let iterator = witness_prog
//!     .iter()
//!     .copied()
//!     .bytes_to_fes()
//!     .hrp_checksummed::<Bech32>(&hrp, witness_version) // Converts to an `HrpChecksummed`
//!     .hrpstring_chars();
//! let hrpstring: String = iterator.collect();
//! assert_eq!(hrpstring.to_uppercase(), "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4");
//! ```

use crate::primitives::checksum::{self, Checksum, PackedFe32};
use crate::primitives::gf32::Fe32;
use crate::primitives::hrp::{self, Hrp};

/// Extension trait for byte iterators which provides an adaptor to GF32 elements.
pub trait ByteIterExt: Sized + Iterator<Item = u8> {
    /// Adapts the byte iterator to output GF32 field elements instead.
    ///
    /// If the total number of bits is not a multiple of 5 we pad with 0s
    fn bytes_to_fes(mut self) -> BytesToFes<Self> {
        BytesToFes { last_byte: self.next(), bit_offset: 0, iter: self }
    }
}

impl<I> ByteIterExt for I where I: Iterator<Item = u8> {}

/// Extension trait for field element iterators.
pub trait Fe32IterExt: Sized + Iterator<Item = Fe32> {
    /// Adapts the `Fe32` iterator to output bytes instead.
    ///
    /// If the total number of bits is not a multiple of 8, any trailing bits
    /// are simply dropped.
    fn fes_to_bytes(mut self) -> FesToBytes<Self> {
        FesToBytes { last_fe: self.next(), bit_offset: 0, iter: self }
    }

    /// Adapts the Fe32 data iterator using `hrp` and `witness_version`, and then appends a checksum.
    fn hrp_checksummed<Ck: Checksum>(
        self,
        hrp: &Hrp,
        witness_version: Fe32,
    ) -> HrpChecksummed<Self, Ck> {
        Checksummed::new(self).with_witness_version(witness_version).hrp_checksummed(hrp)
    }

    /// Adapts the Fe32 iterator to append a checksum to the end of the data.
    fn checksummed<Ck: Checksum>(self) -> Checksummed<Self, Ck> { Checksummed::new(self) }
}

impl<I> Fe32IterExt for I where I: Iterator<Item = Fe32> {}

/// Iterator adaptor that converts bytes to GF32 elements.
///
/// If the total number of bits is not a multiple of 5, it right-pads with 0 bits.
#[derive(Clone, PartialEq, Eq)]
pub struct BytesToFes<I: Iterator<Item = u8>> {
    last_byte: Option<u8>,
    bit_offset: usize,
    iter: I,
}

impl<I> Iterator for BytesToFes<I>
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

/// Iterator adaptor that converts GF32 elements to bytes.
///
/// If the total number of bits is not a multiple of 8, any trailing bits are dropped.
///
/// Note that if there are 5 or more trailing bits, the result will be that an entire field element
/// is dropped. If this occurs, the input was an invalid length for a bech32 string, but this
/// iterator does not do any checks for this.
#[derive(Clone, PartialEq, Eq)]
pub struct FesToBytes<I: Iterator<Item = Fe32>> {
    last_fe: Option<Fe32>,
    bit_offset: usize,
    iter: I,
}

impl<I> Iterator for FesToBytes<I>
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
        // +1 because we set last_fe with call to `next`.
        let min = fes_len_to_bytes_len(fes_min) + 1;
        let max = fes_max.map(|max| fes_len_to_bytes_len(max) + 1);
        (min, max)
    }
}

/// Iterator adaptor for field-element-yielding iterator, which tacks a checksum onto the end of the
/// yielded data.
#[derive(Clone, PartialEq, Eq)]
pub struct Checksummed<I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    witness_version: Option<Fe32>,
    iter: I,
    checksum_remaining: usize,
    checksum_engine: checksum::Engine<Ck>,
}

impl<I, Ck> Checksummed<I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    /// Creates a new checksummed iterator which adapts a data iterator of field elements by
    /// appending a checksum.
    pub fn new(data: I) -> Checksummed<I, Ck> {
        Checksummed {
            witness_version: None,
            iter: data,
            checksum_remaining: Ck::CHECKSUM_LENGTH,
            checksum_engine: checksum::Engine::new(),
        }
    }

    /// Adapts a [`Checksummed`] iterator by prepending a witness version.
    ///
    /// Must be called before the `Checksummed` iterator has yielded any results.
    pub fn with_witness_version(mut self, witness_version: Fe32) -> Checksummed<I, Ck> {
        self.witness_version = Some(witness_version);
        self
    }

    /// Adapts a [`Checksummed`] iterator into an `HrpChecksummed` iterator.
    ///
    /// Must be called before the `Checksummed` iterator has yielded any results.
    pub fn hrp_checksummed(self, hrp: &Hrp) -> HrpChecksummed<I, Ck> {
        HrpChecksummed::new(hrp, self)
    }
}

impl<I, Ck> Iterator for Checksummed<I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    type Item = Fe32;

    fn next(&mut self) -> Option<Fe32> {
        if let Some(witness_version) = self.witness_version {
            self.witness_version = None;
            self.checksum_engine.input_fe(witness_version);
            return Some(witness_version);
        }

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
        let wit = match self.witness_version {
            Some(_) => 1,
            None => 0,
        };
        let add = wit + self.checksum_remaining;
        let (min, max) = self.iter.size_hint();

        (min + add, max.map(|max| max + add))
    }
}

/// Iterator adaptor for a checksummed iterator that inputs the HRP into the checksum algorithm
/// before yielding the data followed by the checksum.
#[derive(Clone, PartialEq, Eq)]
pub struct HrpChecksummed<'hrp, I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    /// The HRP to input into the checksum algorithm.
    hrp: &'hrp Hrp,
    /// A field element iterator with or without the witness version.
    iter: Checksummed<I, Ck>,
}

impl<'hrp, I, Ck> HrpChecksummed<'hrp, I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    /// Adapts an checksummed iterator by inputting the HRP to the checksum algorithm.
    ///
    /// `iter` may or may not include the witness version.
    pub fn new(hrp: &'hrp Hrp, mut iter: Checksummed<I, Ck>) -> HrpChecksummed<'hrp, I, Ck> {
        iter.checksum_engine.input_hrp(hrp);
        Self { hrp, iter }
    }

    /// Adapts the iterator to yield characters representing the bech32 encoding.
    pub fn hrpstring_chars(self) -> HrpstringChars<'hrp, I, Ck> { HrpstringChars::new(self) }
}

impl<'hrp, I, Ck> Iterator for HrpChecksummed<'hrp, I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    type Item = Fe32;
    fn next(&mut self) -> Option<Fe32> { self.iter.next() }
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

/// Iterator adaptor which takes a stream of field elements, converts it to characters prefixed by
/// an HRP (and separator), and suffixed by the checksum i.e., converts the data in a stream of
/// field elements into stream of characters representing the encoded bech32 string.
pub struct HrpstringChars<'hrp, I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    /// `None` once the hrp has been yielded.
    hrp_iter: Option<hrp::LowercaseCharIter<'hrp>>,
    /// Iterator over field elements made up of the optional witness version, the data to be
    /// encoded, plus the checksum.
    checksummed: HrpChecksummed<'hrp, I, Ck>,
}

impl<'hrp, I, Ck> HrpstringChars<'hrp, I, Ck>
where
    I: Iterator<Item = Fe32>,
    Ck: Checksum,
{
    /// Adapts the `HrpChecksummed` iterator to yield characters representing the bech32 encoding.
    pub fn new(checksummed: HrpChecksummed<'hrp, I, Ck>) -> Self {
        Self { hrp_iter: Some(checksummed.hrp.lowercase_char_iter()), checksummed }
    }
}

impl<'a, I, Ck> Iterator for HrpstringChars<'a, I, Ck>
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

        self.checksummed.next().map(|fe| fe.to_char())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.hrp_iter {
            // We have yielded the hrp and separator already.
            None => self.checksummed.size_hint(),
            // Yet to finish yielding the hrp (and the separator).
            Some(hrp_iter) => {
                let (hrp_min, hrp_max) = hrp_iter.size_hint();
                let (chk_min, chk_max) = self.checksummed.size_hint();

                let min = hrp_min + 1 + chk_min; // +1 for the separator.

                // To provide a max boundary we need to have gotten a value from the hrp iter as well as the
                // checksummed iter, otherwise we have to return None since we cannot know the maximum.
                let max = match (hrp_max, chk_max) {
                    (Some(hrp_max), Some(chk_max)) => Some(hrp_max + 1 + chk_max),
                    (_, _) => None,
                };

                (min, max)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bech32;

    // Tests below using this data, are based on the test vector (from BIP-173):
    // BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4: 0014751e76e8199196d454941c45d1b3a323f1433bd6
    #[rustfmt::skip]
    const DATA: [u8; 20] = [
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
        0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
        0xf1, 0x43, 0x3b, 0xd6,
    ];

    #[test]
    fn byte_iter_ext() {
        assert!(DATA
            .iter()
            .copied()
            .bytes_to_fes()
            .map(Fe32::to_char)
            .eq("w508d6qejxtdg4y5r3zarvary0c5xw7k".chars()));
    }

    #[test]
    fn bytes_to_fes_size_hint() {
        let char_len = "w508d6qejxtdg4y5r3zarvary0c5xw7k".len();
        assert_eq!(DATA.iter().copied().bytes_to_fes().size_hint(), (char_len, Some(char_len)));
    }

    #[test]
    fn fe32_iter_ext() {
        let fe_iter = "w508d6qejxtdg4y5r3zarvary0c5xw7k"
            .bytes()
            .map(|b| Fe32::from_char(char::from(b)).unwrap());

        assert!(fe_iter.clone().fes_to_bytes().eq(DATA.iter().copied()));
    }

    #[test]
    fn fes_to_bytes_size_hint() {
        let fe_iter = "w508d6qejxtdg4y5r3zarvary0c5xw7k"
            .bytes()
            .map(|b| Fe32::from_char(char::from(b)).unwrap());

        let got_hint = fe_iter.clone().fes_to_bytes().size_hint();
        let want_hint = DATA.iter().size_hint();

        assert_eq!(got_hint, want_hint)
    }

    #[test]
    fn hrpstring_iter() {
        let iter = DATA.iter().copied().bytes_to_fes();

        let hrp = Hrp::parse_unchecked("bc");
        let iter = iter.hrp_checksummed::<Bech32>(&hrp, Fe32::Q).hrpstring_chars();

        assert!(iter.eq("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".chars()));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn hrpstring_iter_collect() {
        let iter = DATA.iter().copied().bytes_to_fes();

        let hrp = Hrp::parse_unchecked("bc");
        let iter = iter.hrp_checksummed::<Bech32>(&hrp, Fe32::Q).hrpstring_chars();

        let encoded = iter.collect::<String>();
        assert_eq!(encoded, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn hrpstring_iter_size_hint() {
        let char_len = "w508d6qejxtdg4y5r3zarvary0c5xw7k".len();
        let iter = DATA.iter().copied().bytes_to_fes();

        let hrp = Hrp::parse_unchecked("bc");
        let iter = iter.hrp_checksummed::<Bech32>(&hrp, Fe32::Q).hrpstring_chars();

        let checksummed_len = 2 + 1 + 1 + char_len + 6; // bc + SEP + Q + chars + checksum
        assert_eq!(iter.size_hint().0, checksummed_len);
    }
}
