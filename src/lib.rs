// Written by Clark Moody and the rust-bitcoin developers.
// SPDX-License-Identifier: MIT

//! Encoding and decoding of the Bech32 format.
//!
//! Bech32 is an encoding scheme that is easy to use for humans and efficient to encode in QR codes.
//!
//! A Bech32 string consists of a human-readable part (HRP), a separator (the character `'1'`), and
//! a data part. A checksum at the end of the string provides error detection to prevent mistakes
//! when the string is written off or read out loud.
//!
//! The original description in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
//! has more details. See also [BIP-0350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(bench, feature(test))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Coding conventions
#![deny(missing_docs)]

#[cfg(bench)]
extern crate test;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate core;

#[cfg(all(feature = "alloc", not(feature = "std"), not(test)))]
use alloc::{string::String, vec::Vec};
use core::convert::{Infallible, TryFrom};
use core::fmt;

pub use crate::primitives::checksum::Checksum;
use crate::primitives::hrp;
pub use crate::primitives::hrp::Hrp;
pub use crate::primitives::hrpstring::{self, Parsed};
pub use crate::primitives::{Bech32, Bech32m};

mod error;
pub mod primitives;

pub use primitives::gf32::Fe32 as u5;

/// Interface to write `u5`s into a sink.
pub trait WriteBase32 {
    /// Write error.
    type Error: fmt::Debug;

    /// Writes a `u5` slice to `self`.
    fn write(&mut self, data: &[u5]) -> Result<(), Self::Error> {
        for b in data {
            self.write_u5(*b)?;
        }
        Ok(())
    }

    /// Writes a single `u5`.
    fn write_u5(&mut self, data: u5) -> Result<(), Self::Error> { self.write(&[data]) }
}

/// Interface to write `u8`s into a sink
///
/// Like `std::io::Writer`, but because the associated type is no_std compatible.
pub trait WriteBase256 {
    /// Write error.
    type Error: fmt::Debug;

    /// Writes a `u8` slice.
    fn write(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        for b in data {
            self.write_u8(*b)?;
        }
        Ok(())
    }

    /// Writes a single `u8`.
    fn write_u8(&mut self, data: u8) -> Result<(), Self::Error> { self.write(&[data]) }
}

macro_rules! write_base_n {
    { $tr:ident, $ty:ident, $meth:ident } => {
        #[cfg(feature = "alloc")]
        impl $tr for Vec<$ty> {
            type Error = Infallible;

            fn write(&mut self, data: &[$ty]) -> Result<(), Self::Error> {
                self.extend_from_slice(data);
                Ok(())
            }

            fn $meth(&mut self, data: $ty) -> Result<(), Self::Error> {
                self.push(data);
                Ok(())
            }
        }
    }
}

write_base_n! { WriteBase32, u5, write_u5 }
write_base_n! { WriteBase256, u8, write_u8 }

/// A trait to convert between u8 arrays and u5 arrays without changing the content of the elements,
/// but checking that they are in range.
pub trait CheckBase32<T> {
    /// Error type if conversion fails
    type Error;

    /// Checks if all values are in range and return slice-like-type of `u5` values.
    fn check_base32(self) -> Result<T, Self::Error>;
}

impl<T, U: AsRef<[u8]>> CheckBase32<T> for U
where
    T: AsRef<[u5]>,
    T: core::iter::FromIterator<u5>,
{
    type Error = Error;

    fn check_base32(self) -> Result<T, Self::Error> {
        self.as_ref()
            .iter()
            .map(|x| u5::try_from(*x).map_err(Error::TryFrom))
            .collect::<Result<T, Error>>()
    }
}

impl<U: AsRef<[u8]>> CheckBase32<()> for U {
    type Error = Error;

    fn check_base32(self) -> Result<(), Error> {
        self.as_ref()
            .iter()
            .map(|x| u5::try_from(*x).map(|_| ()).map_err(Error::TryFrom))
            .find(|r| r.is_err())
            .unwrap_or(Ok(()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Upper,
    Lower,
    None,
}

/// Encodes a bech32 payload to a writer ([`fmt::Write`]) using lowercase.
///
/// This method is intended for implementing traits from [`std::fmt`].
///
/// # Deviations from standard.
///
/// * No length limits are enforced for the data part.
pub fn encode_to_fmt<T: AsRef<[u5]>>(
    fmt: &mut dyn fmt::Write,
    hrp: Hrp,
    data: T,
    variant: Variant,
) -> fmt::Result {
    use crate::primitives::iter::Fe32IterExt;

    match variant {
        Variant::Bech32 =>
            for c in data
                .as_ref()
                .iter()
                .copied()
                .checksum::<Bech32>()
                .with_checksummed_hrp(&hrp)
                .hrp_char(&hrp)
            {
                fmt.write_char(c)?;
            },
        Variant::Bech32m =>
            for c in data
                .as_ref()
                .iter()
                .copied()
                .checksum::<Bech32m>()
                .with_checksummed_hrp(&hrp)
                .hrp_char(&hrp)
            {
                fmt.write_char(c)?;
            },
    }
    Ok(())
}

/// Encodes a bech32 payload without a checksum to a writer ([`fmt::Write`]).
///
/// This method is intended for implementing traits from [`std::fmt`].
///
/// # Deviations from standard.
///
/// * No length limits are enforced for the data part.
pub fn encode_without_checksum_to_fmt<T: AsRef<[u5]>>(
    fmt: &mut dyn fmt::Write,
    hrp: Hrp,
    data: T,
) -> Result<fmt::Result, Error> {
    for c in hrp.lowercase_char_iter() {
        if let Err(e) = fmt.write_char(c) {
            return Ok(Err(e));
        }
    }
    if let Err(e) = fmt.write_char(SEP) {
        return Ok(Err(e));
    }
    for b in data.as_ref() {
        if let Err(e) = fmt.write_char(b.to_char()) {
            return Ok(Err(e));
        }
    }
    Ok(Ok(()))
}

/// Used for encode/decode operations for the two variants of Bech32.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Variant {
    /// The original Bech32 described in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
    Bech32,
    /// The improved Bech32m variant described in [BIP-0350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).
    Bech32m,
}

/// Encodes a bech32 payload to string.
///
/// # Deviations from standard.
///
/// * No length limits are enforced for the data part.
#[cfg(feature = "alloc")]
pub fn encode<T: AsRef<[u5]>>(hrp: Hrp, data: T, variant: Variant) -> String {
    use crate::primitives::iter::Fe32IterExt;

    match variant {
        Variant::Bech32 => data
            .as_ref()
            .iter()
            .copied()
            .checksum::<Bech32>()
            .with_checksummed_hrp(&hrp)
            .hrp_char(&hrp)
            .collect(),
        Variant::Bech32m => data
            .as_ref()
            .iter()
            .copied()
            .checksum::<Bech32m>()
            .with_checksummed_hrp(&hrp)
            .hrp_char(&hrp)
            .collect(),
    }
}

/// Encodes a bech32 payload to string without the checksum.
///
/// # Deviations from standard.
///
/// * No length limits are enforced for the data part.
#[cfg(feature = "alloc")]
pub fn encode_without_checksum<T: AsRef<[u5]>>(hrp: Hrp, data: T) -> Result<String, Error> {
    let mut buf = String::new();
    encode_without_checksum_to_fmt(&mut buf, hrp, data)?.unwrap();
    Ok(buf)
}

/// Decodes a bech32 string.
pub fn decode(s: &str) -> Result<(hrpstring::Parsed, Variant), Error> {
    let p = Parsed::new(s)?;
    if p.validate_checksum::<Bech32m>().is_ok() {
        return Ok((p, Variant::Bech32m));
    }
    if p.validate_checksum::<Bech32>().is_ok() {
        return Ok((p, Variant::Bech32));
    }

    Err(Error::InvalidChecksum)
}

/// Decodes a bech32 string, assuming no checksum.
pub fn decode_without_checksum(s: &str) -> Result<hrpstring::Parsed, Error> {
    let p = Parsed::new(s)?;
    Ok(p)
}

/// Human-readable part and data part separator.
const SEP: char = '1';

/// Error types for Bech32 encoding / decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// String does not contain the separator character.
    MissingSeparator,
    /// The checksum does not match the rest of the data.
    InvalidChecksum,
    /// The data or human-readable part is too long or too short.
    InvalidLength,
    /// Some part of the string contains an invalid character.
    InvalidChar(char),
    /// The bit conversion failed due to a padding issue.
    InvalidPadding,
    /// The whole string must be of one case.
    MixedCase,
    /// Attempted to convert a value which overflows a `u5`.
    Overflow,
    /// Conversion to u5 failed.
    TryFrom(primitives::gf32::Error),
    /// HRP parsing failed.
    Hrp(hrp::Error),
    /// hrpstring parsing failed.
    Hrpstring(hrpstring::Error),
}

impl From<Infallible> for Error {
    fn from(v: Infallible) -> Self { match v {} }
}

impl From<hrp::Error> for Error {
    fn from(e: hrp::Error) -> Self { Error::Hrp(e) }
}

impl From<hrpstring::Error> for Error {
    fn from(e: hrpstring::Error) -> Self { Error::Hrpstring(e) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            MissingSeparator => write!(f, "missing human-readable separator, \"{}\"", SEP),
            InvalidChecksum => write!(f, "invalid checksum"),
            InvalidLength => write!(f, "invalid length"),
            InvalidChar(n) => write!(f, "invalid character (code={})", n),
            InvalidPadding => write!(f, "invalid padding"),
            MixedCase => write!(f, "mixed-case strings not allowed"),
            TryFrom(ref e) => write_err!(f, "conversion to u5 failed"; e),
            Overflow => write!(f, "attempted to convert a value which overflows a u5"),
            Hrp(ref e) => write_err!(f, "HRP conversion failed"; e),
            Hrpstring(ref e) => write_err!(f, "hrpstring conversion failed"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            TryFrom(ref e) => Some(e),
            Hrp(ref e) => Some(e),
            Hrpstring(ref e) => Some(e),
            MissingSeparator | InvalidChecksum | InvalidLength | InvalidChar(_)
            | InvalidPadding | MixedCase | Overflow => None,
        }
    }
}

impl From<primitives::gf32::Error> for Error {
    fn from(e: primitives::gf32::Error) -> Self { Error::TryFrom(e) }
}

/// Error return when `TryFrom<T>` fails for T -> u5 conversion.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum TryFromIntError {
    /// Attempted to convert a negative value to a `u5`.
    NegOverflow,
    /// Attempted to convert a value which overflows a `u5`.
    PosOverflow,
}

impl fmt::Display for TryFromIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TryFromIntError::*;

        match *self {
            NegOverflow => write!(f, "attempted to convert a negative value to a u5"),
            PosOverflow => write!(f, "attempted to convert a value which overflows a u5"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TryFromIntError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TryFromIntError::*;

        match *self {
            NegOverflow | PosOverflow => None,
        }
    }
}

// impl From<convert::Error> for Error {
//     fn from(e: convert::Error) -> Self {
//         Error::InvalidData(e)
//     }
// }

/// Converts between bit sizes.
///
/// # Errors
///
/// * `Error::InvalidData` if any element of `data` is out of range.
/// * `Error::InvalidPadding` if `pad == false` and the padding bits are not `0`.
///
/// # Panics
///
/// Function will panic if attempting to convert `from` or `to` a bit size that
/// is 0 or larger than 8 bits i.e., `from` and `to` must within range `1..=8`.
///
/// # Examples
///
/// ```rust
/// use bech32::convert_bits;
/// let base5 = convert_bits(&[0xff], 8, 5, true);
/// assert_eq!(base5.unwrap(), vec![0x1f, 0x1c]);
/// ```
#[cfg(feature = "alloc")]
pub fn convert_bits<T>(data: &[T], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, Error>
where
    T: Into<u8> + Copy,
{
    let mut ret: Vec<u8> = Vec::new();
    convert_bits_in::<Error, _, _>(data, from, to, pad, &mut ret)?;
    Ok(ret)
}

/// Convert between bit sizes without allocating
///
/// Like [convert_bits].
pub fn convert_bits_in<E, T, R>(
    data: &[T],
    from: u32,
    to: u32,
    pad: bool,
    ret: &mut R,
) -> Result<(), E>
where
    T: Into<u8> + Copy,
    R: WriteBase256,
    E: From<Error>,
    E: From<R::Error>,
{
    if from > 8 || to > 8 || from == 0 || to == 0 {
        panic!("convert_bits `from` and `to` parameters 0 or greater than 8");
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv: u32 = (1 << to) - 1;
    for value in data {
        let v: u32 = u32::from(Into::<u8>::into(*value));
        if (v >> from) != 0 {
            // Input value exceeds `from` bit size
            Err(Error::Overflow)?;
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.write_u8(((acc >> bits) & maxv) as u8)?;
        }
    }
    if pad {
        if bits > 0 {
            ret.write_u8(((acc << (to - bits)) & maxv) as u8)?;
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        Err(Error::InvalidPadding)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::iter::{ByteIterExt, Fe32IterExt};
    use crate::primitives::NoChecksum;

    #[cfg(feature = "alloc")]
    fn hrp(s: &str) -> Hrp { Hrp::parse_unchecked(s) }

    trait TextExt {
        fn check_base32_vec(self) -> Result<Vec<u5>, Error>;
    }
    impl<U: AsRef<[u8]>> TextExt for U {
        fn check_base32_vec(self) -> Result<Vec<u5>, Error> { self.check_base32() }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn getters() {
        let (parsed, _variant) = decode("BC1SW50QA3JX3S").unwrap();
        let data = [16, 14, 20, 15, 0].check_base32_vec().unwrap();
        let want = data.iter().copied().fes_to_bytes();
        assert_eq!(parsed.hrp(), hrp("bc"));
        assert_eq!(parsed.hrp().to_string(), "BC");
        assert!(parsed.data_iter::<Bech32>().unwrap().eq(want));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn valid_checksum() {
        let strings: Vec<&str> = vec!(
            // Bech32
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            // Bech32m
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            // TODO: Fix this test case
            // "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        );
        for s in strings {
            match decode(s) {
                Ok((parsed, variant)) => {
                    let data =
                        parsed.data_iter::<Bech32>().unwrap().bytes_to_fes().collect::<Vec<u5>>();
                    let encoded = encode(parsed.hrp(), data, variant);
                    assert_eq!(s.to_lowercase(), encoded.to_lowercase());
                }
                Err(e) => panic!("Did not decode: {:?} Reason: {:?}", s, e),
            }
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn invalid_strings() {
        use crate::primitives::hrpstring;

        let pairs: Vec<(&str, Error)> = vec!(
            (" 1nwldj5",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::InvalidAsciiByte(b' ')))),
            ("abc1\u{2192}axkwrx",
                Error::Hrpstring(hrpstring::Error::InvalidChar('\u{2192}'))),
            ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::TooLong(84)))),
            ("pzry9x0s0muk",
                Error::Hrpstring(hrpstring::Error::MissingSeparator)),
            ("1pzry9x0s0muk",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::Empty))),
            ("x1b4n0q5v",
                Error::Hrpstring(hrpstring::Error::InvalidChar('b'))),
            ("ABC1DEFGOH",
                Error::Hrpstring(hrpstring::Error::InvalidChar('O'))),
            ("li1dgmt3",
                Error::InvalidChecksum),
            ("de1lg7wt\u{ff}",
                Error::Hrpstring(hrpstring::Error::InvalidChar('\u{ff}'))),
            ("\u{20}1xj0phk",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::InvalidAsciiByte(b' ')))), // u20 is space character
            ("\u{7F}1g6xzxy",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::InvalidAsciiByte(0x7f)))),
            ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::TooLong(84)))),
            ("qyrz8wqd2c9m",
                Error::Hrpstring(hrpstring::Error::MissingSeparator)),
            ("1qyrz8wqd2c9m",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::Empty))),
            ("y1b0jsk6g",
                Error::Hrpstring(hrpstring::Error::InvalidChar('b'))),
            ("lt1igcx5c0",
                Error::Hrpstring(hrpstring::Error::InvalidChar('i'))),
            ("in1muywd",
                Error::InvalidChecksum),
            ("mm1crxm3i",
                Error::Hrpstring(hrpstring::Error::InvalidChar('i'))),
            ("au1s5cgom",
                Error::Hrpstring(hrpstring::Error::InvalidChar('o'))),
            ("M1VUXWEZ",
                Error::InvalidChecksum),
            ("16plkw9",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::Empty))),
            ("1p2gdwpf",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::Empty))),
            ("bc1p2",
                Error::InvalidChecksum),
        );
        for p in pairs {
            let (s, expected_error) = p;
            match decode(s) {
                Ok(_) => panic!("Should be invalid: {:?}", s),
                Err(e) => assert_eq!(e, expected_error, "testing input '{}'", s),
            }
        }
    }

    #[test]
    #[allow(clippy::type_complexity)]
    #[cfg(feature = "alloc")]
    fn valid_conversion() {
        // Set of [data, from_bits, to_bits, pad, result]
        let tests: Vec<(Vec<u8>, u32, u32, bool, Vec<u8>)> = vec![
            (vec![0x01], 1, 1, true, vec![0x01]),
            (vec![0x01, 0x01], 1, 1, true, vec![0x01, 0x01]),
            (vec![0x01], 8, 8, true, vec![0x01]),
            (vec![0x01], 8, 4, true, vec![0x00, 0x01]),
            (vec![0x01], 8, 2, true, vec![0x00, 0x00, 0x00, 0x01]),
            (vec![0x01], 8, 1, true, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            (vec![0xff], 8, 5, true, vec![0x1f, 0x1c]),
            (vec![0x1f, 0x1c], 5, 8, false, vec![0xff]),
        ];
        for t in tests {
            let (data, from_bits, to_bits, pad, expected_result) = t;
            let result = convert_bits(&data, from_bits, to_bits, pad);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_result);
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn invalid_conversion() {
        // Set of [data, from_bits, to_bits, pad, expected error]
        let tests: Vec<(Vec<u8>, u32, u32, bool, Error)> = vec![
            (vec![0xff], 8, 5, false, Error::InvalidPadding),
            (vec![0x02], 1, 1, true, Error::Overflow),
        ];
        for t in tests {
            let (data, from_bits, to_bits, pad, expected_error) = t;
            let result = convert_bits(&data, from_bits, to_bits, pad);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), expected_error);
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn convert_bits_invalid_bit_size() {
        use std::panic::{catch_unwind, set_hook, take_hook};

        let invalid = &[(0, 8), (5, 0), (9, 5), (8, 10), (0, 16)];

        for &(from, to) in invalid {
            set_hook(Box::new(|_| {}));
            let result = catch_unwind(|| {
                let _ = convert_bits(&[0], from, to, true);
            });
            let _ = take_hook();
            assert!(result.is_err());
        }
    }

    #[test]
    fn check_base32() {
        assert!([0u8, 1, 2, 30, 31].check_base32_vec().is_ok());
        assert!([0u8, 1, 2, 30, 31, 32].check_base32_vec().is_err());
        assert!([0u8, 1, 2, 30, 31, 255].check_base32_vec().is_err());

        assert!([1u8, 2, 3, 4].check_base32_vec().is_ok());
        assert!(matches!(
            [30u8, 31, 35, 20].check_base32_vec(),
            Err(Error::TryFrom(primitives::gf32::Error::InvalidByte(35)))
        ));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_encode() {
        assert_eq!(Hrp::parse(""), Err(hrp::Error::Empty));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn roundtrip_without_checksum() {
        let hrp = hrp("lnbc");
        let data = "Hello World!".as_bytes().iter().copied().bytes_to_fes().collect::<Vec<u5>>();

        let encoded = encode_without_checksum(hrp, data.clone()).expect("failed to encode");
        let parsed = decode_without_checksum(&encoded).expect("failed to decode");

        let decoded_hrp = parsed.hrp();
        let decoded_data =
            parsed.data_iter::<NoChecksum>().unwrap().bytes_to_fes().collect::<Vec<u5>>();
        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, data);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_hrp_case() {
        let fes = [0x00, 0x00].iter().copied().bytes_to_fes().collect::<Vec<u5>>();
        // Tests for issue with HRP case checking being ignored for encoding
        let encoded_str = encode(hrp("HRP"), fes, Variant::Bech32);

        assert_eq!(encoded_str, "hrp1qqqq40atq3");
    }

    #[test]
    fn try_from_err() {
        assert!(u5::try_from(32_u8).is_err());
        assert!(u5::try_from(32_u16).is_err());
        assert!(u5::try_from(32_u32).is_err());
        assert!(u5::try_from(32_u64).is_err());
        assert!(u5::try_from(32_u128).is_err());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decode_bitcoin_bech32_address() {
        let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let (parsed, variant) = crate::decode(addr).expect("address is well formed");
        assert_eq!(parsed.hrp().to_string(), "bc");
        assert_eq!(variant, Variant::Bech32)
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decode_bitcoin_bech32m_address() {
        let addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        let (parsed, variant) = crate::decode(addr).expect("address is well formed");
        assert_eq!(parsed.hrp().to_string(), "bc");
        assert_eq!(variant, Variant::Bech32m)
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decode_all_digit_hrp_uppercase_data() {
        let addr = "BC1P5D7RJQ7G6RDK2YHZKS9SMLAQTEDR4DEKQ08GE8ZTWAC72SFR9RUSXG3297";
        let (parsed, variant) = crate::decode(addr).expect("address is well formed");
        let hrp = Hrp::parse("bc").expect("failed to parse hrp");
        assert_eq!(parsed.hrp(), hrp);
        let data = parsed
            .data_iter::<Bech32>()
            .expect("data_iter failed")
            .bytes_to_fes()
            .collect::<Vec<u5>>();
        let s = crate::encode(hrp, data, variant);
        assert_eq!(s.to_uppercase(), addr);
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    #[bench]
    fn bech32_parse_address(bh: &mut Bencher) {
        let addr = black_box("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");

        bh.iter(|| {
            let tuple = crate::decode(&addr).expect("address is well formed");
            black_box(&tuple);
        })
    }

    #[bench]
    fn bech32m_parse_address(bh: &mut Bencher) {
        let addr = black_box("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297");

        bh.iter(|| {
            let tuple = crate::decode(&addr).expect("address is well formed");
            black_box(&tuple);
        })
    }

    // Encode with allocation.
    #[bench]
    fn encode_bech32_address(bh: &mut Bencher) {
        let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let (hrp, data, variant) = crate::decode(&addr).expect("address is well formed");

        bh.iter(|| {
            let s = crate::encode(hrp, &data, variant);
            black_box(&s);
        });
    }

    // Encode without allocation.
    #[bench]
    fn encode_to_fmt_bech32_address(bh: &mut Bencher) {
        let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let (hrp, data, variant) = crate::decode(&addr).expect("address is well formed");
        let mut buf = String::with_capacity(64);

        bh.iter(|| {
            let res =
                crate::encode_to_fmt(&mut buf, hrp, &data, variant).expect("failed to encode");
            black_box(&res);
        });
    }

    // Encode with allocation.
    #[bench]
    fn encode_bech32m_address(bh: &mut Bencher) {
        let addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        let (hrp, data, variant) = crate::decode(&addr).expect("address is well formed");

        bh.iter(|| {
            let s = crate::encode(hrp, &data, variant);
            black_box(&s);
        });
    }

    // Encode without allocation.
    #[bench]
    fn encode_to_fmt_bech32m_address(bh: &mut Bencher) {
        let addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        let (hrp, data, variant) = crate::decode(&addr).expect("address is well formed");
        let mut buf = String::with_capacity(64);

        bh.iter(|| {
            let res =
                crate::encode_to_fmt(&mut buf, hrp, &data, variant).expect("failed to encode");
            black_box(&res);
        });
    }
}
