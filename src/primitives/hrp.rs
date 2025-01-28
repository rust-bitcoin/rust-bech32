// SPDX-License-Identifier: MIT

//! Provides an [`Hrp`] type that represents the human-readable part of a bech32 encoded string.
//!
//! > The human-readable part, which is intended to convey the type of data, or anything else that
//! > is relevant to the reader. This part MUST contain 1 to 83 US-ASCII characters, with each
//! > character having a value in the range [33-126]. HRP validity may be further restricted by
//! > specific applications.
//!
//! ref: [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#user-content-Bech32)

#[cfg(all(feature = "alloc", not(feature = "std"), not(test)))]
use alloc::string::String;
use core::cmp::Ordering;
use core::fmt::{self, Write};
use core::iter::FusedIterator;
use core::{slice, str};

/// Maximum length of the human-readable part, as defined by BIP-173.
const MAX_HRP_LEN: usize = 83;

// Defines HRP constants for the different bitcoin networks.
// You can also access these at `crate::hrp::BC` etc.
#[rustfmt::skip]
macro_rules! define_hrp_const {
    (
        #[$doc:meta]
        pub const $name:ident $size:literal $v:expr;
    ) => {
        #[$doc]
        pub const $name: Hrp = Hrp { buf: [
            $v[0], $v[1], $v[2], $v[3],
            0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ], size: $size };
    };
}
define_hrp_const! {
    /// The human-readable part used by the Bitcoin mainnet network.
    pub const BC 2 [98, 99, 0, 0];
}
define_hrp_const! {
    /// The human-readable part used by the Bitcoin testnet networks (testnet, signet).
    pub const TB 2 [116, 98, 0, 0];
}
define_hrp_const! {
    /// The human-readable part used when running a Bitcoin regtest network.
    pub const BCRT 4 [98, 99, 114, 116];
}

/// The human-readable part (human readable prefix before the '1' separator).
#[derive(Clone, Copy, Debug)]
pub struct Hrp {
    /// ASCII byte values, guaranteed not to be mixed-case.
    buf: [u8; MAX_HRP_LEN],
    /// Number of characters currently stored in this HRP.
    size: usize,
}

impl Hrp {
    /// Parses the human-readable part checking it is valid as defined by [BIP-173].
    ///
    /// This does _not_ check that the `hrp` is an in-use HRP within Bitcoin (eg, "bc"), rather it
    /// checks that the HRP string is valid as per the specification in [BIP-173]:
    ///
    /// > The human-readable part, which is intended to convey the type of data, or anything else that
    /// > is relevant to the reader. This part MUST contain 1 to 83 US-ASCII characters, with each
    /// > character having a value in the range [33-126]. HRP validity may be further restricted by
    /// > specific applications.
    ///
    /// [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
    pub fn parse(hrp: &str) -> Result<Self, Error> {
        use Error::*;

        if hrp.is_empty() {
            return Err(Empty);
        }
        if hrp.len() > MAX_HRP_LEN {
            return Err(TooLong(hrp.len()));
        }

        let mut new = Hrp { buf: [0_u8; MAX_HRP_LEN], size: 0 };

        let mut has_lower: bool = false;
        let mut has_upper: bool = false;
        for (i, c) in hrp.chars().enumerate() {
            if !c.is_ascii() {
                return Err(NonAsciiChar(c));
            }
            let b = c as u8; // cast OK as we just checked that c is an ASCII value

            // Valid subset of ASCII
            if !(33..=126).contains(&b) {
                return Err(InvalidAsciiByte(b));
            }

            if b.is_ascii_lowercase() {
                if has_upper {
                    return Err(MixedCase);
                }
                has_lower = true;
            } else if b.is_ascii_uppercase() {
                if has_lower {
                    return Err(MixedCase);
                }
                has_upper = true;
            };

            new.buf[i] = b;
            new.size += 1;
        }

        Ok(new)
    }

    /// Parses the human-readable part from an object which can be formatted.
    ///
    /// The formatted form of the object is subject to all the same rules as [`Self::parse`].
    /// This method is semantically equivalent to `Hrp::parse(&data.to_string())` but avoids
    /// allocating an intermediate string.
    pub fn parse_display<T: core::fmt::Display>(data: T) -> Result<Self, Error> {
        use Error::*;

        struct ByteFormatter {
            arr: [u8; MAX_HRP_LEN],
            index: usize,
            error: Option<Error>,
        }

        impl core::fmt::Write for ByteFormatter {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let mut has_lower: bool = false;
                let mut has_upper: bool = false;
                for ch in s.chars() {
                    let b = ch as u8; // cast ok, `b` unused until `ch` is checked to be ASCII

                    // Break after finding an error so that we report the first invalid
                    // character, not the last.
                    if !ch.is_ascii() {
                        self.error = Some(Error::NonAsciiChar(ch));
                        break;
                    } else if !(33..=126).contains(&b) {
                        self.error = Some(InvalidAsciiByte(b));
                        break;
                    }

                    if ch.is_ascii_lowercase() {
                        if has_upper {
                            self.error = Some(MixedCase);
                            break;
                        }
                        has_lower = true;
                    } else if ch.is_ascii_uppercase() {
                        if has_lower {
                            self.error = Some(MixedCase);
                            break;
                        }
                        has_upper = true;
                    };
                }

                // However, an invalid length error will take priority over an
                // invalid character error.
                if self.index + s.len() > self.arr.len() {
                    self.error = Some(Error::TooLong(self.index + s.len()));
                } else {
                    // Only do the actual copy if we passed the index check.
                    self.arr[self.index..self.index + s.len()].copy_from_slice(s.as_bytes());
                }

                // Unconditionally update self.index so that in the case of a too-long
                // string, our error return will reflect the full length.
                self.index += s.len();
                Ok(())
            }
        }

        let mut byte_formatter = ByteFormatter { arr: [0; MAX_HRP_LEN], index: 0, error: None };

        write!(byte_formatter, "{}", data).expect("custom Formatter cannot fail");
        if byte_formatter.index == 0 {
            Err(Empty)
        } else if let Some(err) = byte_formatter.error {
            Err(err)
        } else {
            Ok(Self { buf: byte_formatter.arr, size: byte_formatter.index })
        }
    }

    /// Parses the human-readable part (see [`Hrp::parse`] for full docs).
    ///
    /// Does not check that `hrp` is valid according to BIP-173 but does check for valid ASCII
    /// values, replacing any invalid characters with `X`.
    pub const fn parse_unchecked(hrp: &str) -> Self {
        let mut new = Hrp { buf: [0_u8; MAX_HRP_LEN], size: 0 };
        let hrp_bytes = hrp.as_bytes();

        let mut i = 0;
        // Funky code so we can be const.
        while i < hrp.len() {
            let mut b = hrp_bytes[i];
            // Valid subset of ASCII
            if b < 33 || b > 126 {
                b = b'X';
            }

            new.buf[i] = b;
            new.size += 1;
            i += 1;
        }
        new
    }

    /// Returns this human-readable part as a lowercase string.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_lowercase(&self) -> String { self.lowercase_char_iter().collect() }

    /// Returns this human-readable part as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] { &self.buf[..self.size] }

    /// Returns this human-readable part as str.
    #[inline]
    pub fn as_str(&self) -> &str {
        str::from_utf8(&self.buf[..self.size]).expect("we only store ASCII bytes")
    }

    /// Creates a byte iterator over the ASCII byte values (ASCII characters) of this HRP.
    ///
    /// If an uppercase HRP was parsed during object construction then this iterator will yield
    /// uppercase ASCII `char`s. For lowercase bytes see [`Self::lowercase_byte_iter`]
    #[inline]
    pub fn byte_iter(&self) -> ByteIter { ByteIter { iter: self.buf[..self.size].iter() } }

    /// Creates a character iterator over the ASCII characters of this HRP.
    ///
    /// If an uppercase HRP was parsed during object construction then this iterator will yield
    /// uppercase ASCII `char`s. For lowercase bytes see [`Self::lowercase_char_iter`].
    #[inline]
    pub fn char_iter(&self) -> CharIter { CharIter { iter: self.byte_iter() } }

    /// Creates a lowercase iterator over the byte values (ASCII characters) of this HRP.
    #[inline]
    pub fn lowercase_byte_iter(&self) -> LowercaseByteIter {
        LowercaseByteIter { iter: self.byte_iter() }
    }

    /// Creates a lowercase character iterator over the ASCII characters of this HRP.
    #[inline]
    pub fn lowercase_char_iter(&self) -> LowercaseCharIter {
        LowercaseCharIter { iter: self.lowercase_byte_iter() }
    }

    /// Returns the length (number of characters) of the human-readable part.
    ///
    /// Guaranteed to be between 1 and 83 inclusive.
    #[inline]
    #[allow(clippy::len_without_is_empty)] // HRP is never empty.
    pub fn len(&self) -> usize { self.size }

    /// Returns `true` if this HRP is valid according to the bips.
    ///
    /// [BIP-173] states that the HRP must be either "bc" or "tb".
    ///
    /// [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#user-content-Segwit_address_format>
    #[inline]
    pub fn is_valid_segwit(&self) -> bool {
        self.is_valid_on_mainnet() || self.is_valid_on_testnet()
    }

    /// Returns `true` if this HRP is valid on the Bitcoin network i.e., HRP is "bc".
    #[inline]
    pub fn is_valid_on_mainnet(&self) -> bool { *self == self::BC }

    /// Returns `true` if this HRP is valid on the Bitcoin testnet network i.e., HRP is "tb".
    #[inline]
    pub fn is_valid_on_testnet(&self) -> bool { *self == self::TB }

    /// Returns `true` if this HRP is valid on the Bitcoin signet network i.e., HRP is "tb".
    #[inline]
    pub fn is_valid_on_signet(&self) -> bool { *self == self::TB }

    /// Returns `true` if this HRP is valid on the Bitcoin regtest network i.e., HRP is "bcrt".
    #[inline]
    pub fn is_valid_on_regtest(&self) -> bool { *self == self::BCRT }
}

/// Displays the human-readable part.
///
/// If an uppercase HRP was parsed during object construction then the returned string will be
/// in uppercase also. For a lowercase string see `Self::to_lowercase`.
impl fmt::Display for Hrp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.char_iter() {
            f.write_char(c)?;
        }
        Ok(())
    }
}

/// Case insensitive comparison.
impl Ord for Hrp {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.lowercase_byte_iter().cmp(other.lowercase_byte_iter())
    }
}

/// Case insensitive comparison.
impl PartialOrd for Hrp {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

/// Case insensitive comparison.
impl PartialEq for Hrp {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.lowercase_byte_iter().eq(other.lowercase_byte_iter())
    }
}

impl Eq for Hrp {}

impl core::hash::Hash for Hrp {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) { self.buf.hash(h) }
}

/// Iterator over bytes (ASCII values) of the human-readable part.
///
/// ASCII byte values as they were initially parsed (i.e., in the original case).
pub struct ByteIter<'b> {
    iter: slice::Iter<'b, u8>,
}

impl Iterator for ByteIter<'_> {
    type Item = u8;
    #[inline]
    fn next(&mut self) -> Option<u8> { self.iter.next().copied() }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

impl ExactSizeIterator for ByteIter<'_> {
    #[inline]
    fn len(&self) -> usize { self.iter.len() }
}

impl DoubleEndedIterator for ByteIter<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> { self.iter.next_back().copied() }
}

impl FusedIterator for ByteIter<'_> {}

/// Iterator over ASCII characters of the human-readable part.
///
/// ASCII `char`s as they were initially parsed (i.e., in the original case).
pub struct CharIter<'b> {
    iter: ByteIter<'b>,
}

impl Iterator for CharIter<'_> {
    type Item = char;
    #[inline]
    fn next(&mut self) -> Option<char> { self.iter.next().map(Into::into) }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

impl ExactSizeIterator for CharIter<'_> {
    #[inline]
    fn len(&self) -> usize { self.iter.len() }
}

impl DoubleEndedIterator for CharIter<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> { self.iter.next_back().map(Into::into) }
}

impl FusedIterator for CharIter<'_> {}

/// Iterator over lowercase bytes (ASCII characters) of the human-readable part.
pub struct LowercaseByteIter<'b> {
    iter: ByteIter<'b>,
}

impl Iterator for LowercaseByteIter<'_> {
    type Item = u8;
    #[inline]
    fn next(&mut self) -> Option<u8> {
        self.iter.next().map(|b| if is_ascii_uppercase(b) { b | 32 } else { b })
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

impl ExactSizeIterator for LowercaseByteIter<'_> {
    #[inline]
    fn len(&self) -> usize { self.iter.len() }
}

impl DoubleEndedIterator for LowercaseByteIter<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(|b| if is_ascii_uppercase(b) { b | 32 } else { b })
    }
}

impl FusedIterator for LowercaseByteIter<'_> {}

/// Iterator over lowercase ASCII characters of the human-readable part.
pub struct LowercaseCharIter<'b> {
    iter: LowercaseByteIter<'b>,
}

impl Iterator for LowercaseCharIter<'_> {
    type Item = char;
    #[inline]
    fn next(&mut self) -> Option<char> { self.iter.next().map(Into::into) }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

impl ExactSizeIterator for LowercaseCharIter<'_> {
    #[inline]
    fn len(&self) -> usize { self.iter.len() }
}

impl DoubleEndedIterator for LowercaseCharIter<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> { self.iter.next_back().map(Into::into) }
}

impl FusedIterator for LowercaseCharIter<'_> {}

fn is_ascii_uppercase(b: u8) -> bool { (65..=90).contains(&b) }

/// Errors encountered while checking the human-readable part as defined by [BIP-173].
///
/// [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#user-content-Bech32>
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The human-readable part is too long.
    TooLong(usize),
    /// The human-readable part is empty.
    Empty,
    /// Found a non-ASCII character.
    NonAsciiChar(char),
    /// Byte value not within acceptable US-ASCII range.
    InvalidAsciiByte(u8),
    /// The human-readable part cannot mix upper and lower case.
    MixedCase,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            TooLong(len) =>
                write!(f, "hrp is too long, found {} characters, must be <= {}", len, MAX_HRP_LEN),
            Empty => write!(f, "hrp is empty, must have at least 1 character"),
            NonAsciiChar(c) => write!(f, "found non-ASCII character: {}", c),
            InvalidAsciiByte(b) => write!(f, "byte value is not valid US-ASCII: \'{:x}\'", b),
            MixedCase => write!(f, "hrp cannot mix upper and lower case"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            TooLong(_) | Empty | NonAsciiChar(_) | InvalidAsciiByte(_) | MixedCase => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! check_parse_ok {
        ($($test_name:ident, $hrp:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    assert!(Hrp::parse($hrp).is_ok());
                    assert!(Hrp::parse_display($hrp).is_ok());
                }
            )*
        }
    }
    check_parse_ok! {
        parse_ok_0, "a";
        parse_ok_1, "A";
        parse_ok_2, "abcdefg";
        parse_ok_3, "ABCDEFG";
        parse_ok_4, "abc123def";
        parse_ok_5, "ABC123DEF";
        parse_ok_6, "!\"#$%&'()*+,-./";
        parse_ok_7, "1234567890";
    }

    macro_rules! check_parse_err {
        ($($test_name:ident, $hrp:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    assert!(Hrp::parse($hrp).is_err());
                    assert!(Hrp::parse_display($hrp).is_err());
                }
            )*
        }
    }
    check_parse_err! {
        parse_err_0, "has-capitals-aAbB";
        parse_err_1, "has-value-out-of-range-∈∈∈∈∈∈∈∈";
        parse_err_2, "toolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolong";
        parse_err_3, "has spaces in it";
    }

    macro_rules! check_iter {
        ($($test_name:ident, $hrp:literal, $len:literal);* $(;)?) => {
            $(
                #[test]
                fn $test_name() {
                    let hrp = Hrp::parse($hrp).expect(&format!("failed to parse hrp {}", $hrp));

                    // Test ByteIter forwards.
                    for (got, want) in hrp.byte_iter().zip($hrp.bytes()) {
                        assert_eq!(got, want);
                    }

                    // Test ByteIter backwards.
                    for (got, want) in hrp.byte_iter().rev().zip($hrp.bytes().rev()) {
                        assert_eq!(got, want);
                    }

                    // Test exact sized works.
                    let mut iter = hrp.byte_iter();
                    for i in 0..$len {
                        assert_eq!(iter.len(), $len - i);
                        let _ = iter.next();
                    }
                    assert!(iter.next().is_none());

                    // Test CharIter forwards.
                    let iter = hrp.char_iter();
                    assert_eq!($hrp.to_string(), iter.collect::<String>());

                    for (got, want) in hrp.char_iter().zip($hrp.chars()) {
                        assert_eq!(got, want);
                    }

                    // Test CharIter backwards.
                    for (got, want) in hrp.char_iter().rev().zip($hrp.chars().rev()) {
                        assert_eq!(got, want);
                    }

                    // Test LowercaseCharIter forwards (implicitly tests LowercaseByteIter)
                    for (got, want) in hrp.lowercase_char_iter().zip($hrp.chars().map(|c| c.to_ascii_lowercase())) {
                        assert_eq!(got, want);
                    }

                    // Test LowercaseCharIter backwards (implicitly tests LowercaseByteIter)
                    for (got, want) in hrp.lowercase_char_iter().rev().zip($hrp.chars().rev().map(|c| c.to_ascii_lowercase())) {
                        assert_eq!(got, want);
                    }
                }
            )*
        }
    }
    check_iter! {
        char_0, "abc", 3;
        char_1, "ABC", 3;
        char_2, "abc123", 6;
        char_3, "ABC123", 6;
        char_4, "abc123def", 9;
        char_5, "ABC123DEF", 9;
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn hrp_consts() {
        use crate::primitives::hrp::{BC, BCRT, TB};
        assert_eq!(BC, Hrp::parse_unchecked("bc"));
        assert_eq!(TB, Hrp::parse_unchecked("tb"));
        assert_eq!(BCRT, Hrp::parse_unchecked("bcrt"));
    }

    #[test]
    fn as_str() {
        let s = "arbitraryhrp";
        let hrp = Hrp::parse_unchecked(s);
        assert_eq!(hrp.as_str(), s);
    }

    #[test]
    fn as_bytes() {
        let s = "arbitraryhrp";
        let hrp = Hrp::parse_unchecked(s);
        assert_eq!(hrp.as_bytes(), s.as_bytes());
    }

    #[test]
    fn parse_display() {
        let hrp = Hrp::parse_display(format_args!("{}_{}", 123, "abc")).unwrap();
        assert_eq!(hrp.as_str(), "123_abc");

        let hrp = Hrp::parse_display(format_args!("{:083}", 1)).unwrap();
        assert_eq!(
            hrp.as_str(),
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000001"
        );

        assert_eq!(Hrp::parse_display(format_args!("{:084}", 1)), Err(Error::TooLong(84)),);

        assert_eq!(
            Hrp::parse_display(format_args!("{:83}", 1)),
            Err(Error::InvalidAsciiByte(b' ')),
        );
    }

    #[test]
    fn parse_non_ascii() {
        assert_eq!(Hrp::parse("❤").unwrap_err(), Error::NonAsciiChar('❤'));
    }

    #[test]
    fn parse_display_non_ascii() {
        assert_eq!(Hrp::parse_display("❤").unwrap_err(), Error::NonAsciiChar('❤'));
    }

    #[test]
    fn parse_display_returns_first_error() {
        assert_eq!(Hrp::parse_display("❤ ").unwrap_err(), Error::NonAsciiChar('❤'));
    }

    // This test shows that the error does not contain heart.
    #[test]
    fn parse_display_iterates_chars() {
        assert_eq!(Hrp::parse_display(" ❤").unwrap_err(), Error::InvalidAsciiByte(b' '));
        assert_eq!(Hrp::parse_display("_❤").unwrap_err(), Error::NonAsciiChar('❤'));
    }
}
