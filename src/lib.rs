// Copyright (c) 2017 Clark Moody
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Encoding and decoding Bech32 format
//!
//! Bech32 is a 5-bit (base-32) encoding scheme that produces strings that comprise
//! a human-readable part, a separator, a data part, and a checksum. The encoding
//! implements a BCH code that guarantees error detection of up to four characters
//! with less than 1 in 1 billion chance of failing to detect more errors.
//!
//! The Bech32 encoding was originally formulated in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
//!
//! # Examples
//!
//! ```rust
//! use bech32::Bech32;
//!
//! let b = Bech32::new_check_data("bech32".into(), vec![0x00, 0x01, 0x02]).unwrap();
//! let encoded = b.to_string();
//! assert_eq!(encoded, "bech321qpz4nc4pe".to_string());
//!
//! let c = encoded.parse::<Bech32>();
//! assert_eq!(b, c.unwrap());
//! ```
//!
//! If the data is already range-checked the `Bech32::new` function can be used which will never
//! return `Err(Error::InvalidData)`.
//!
//! ```rust
//! use bech32::{Bech32, u5, ToBase32};
//!
//! // converts base256 data to base32 and adds padding if needed
//! let checked_data: Vec<u5> = [0xb4, 0xff, 0xa5].to_base32();
//!
//! let b = Bech32::new("bech32".into(), checked_data).expect("hrp is not empty");
//! let encoded = b.to_string();
//!
//! assert_eq!(encoded, "bech321knl623tk6v7".to_string());
//! ```
//!

#![deny(missing_docs)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

#![cfg_attr(feature = "strict", deny(warnings))]

use std::{error, fmt};

// AsciiExt is needed for Rust 1.14 but not for newer versions
#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Integer in the range `0..32`
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub struct u5(u8);

/// Parse/convert base32 slice to `Self`. It is the reciprocal of
/// `ToBase32`.
pub trait FromBase32: Sized {
    /// The associated error which can be returned from parsing (e.g. because of bad padding).
    type Err;

    /// Convert a base32 slice to `Self`.
    fn from_base32(b32: &[u5]) -> Result<Self, Self::Err>;
}

/// A trait for converting a value to a type `T` that represents a `u5` slice.
pub trait ToBase32 {
    /// Convert `Self` to base32 slice
    fn to_base32(&self) -> Vec<u5> {
        let mut buff = Vec::new();
        self.write_base32(&mut buff);
        buff
    }

    /// Convert `Self` to bech32 and append the result to a supplied, mutable buffer
    fn write_base32(&self, buffer: &mut Vec<u5>);
}

/// A trait to convert between u8 arrays and u5 arrays without changing the content of the elements,
/// but checking that they are in range.
pub trait CheckBase32<T: AsRef<[u5]>> {
    /// Error type if conversion fails
    type Err;

    /// Check if all values are in range and return array-like struct of `u5` values
    fn check_base32(self) -> Result<T, Self::Err>;
}

/// Grouping structure for the human-readable part and the data part
/// of decoded Bech32 string.
#[derive(PartialEq, Eq, Debug, Clone, PartialOrd, Ord, Hash)]
pub struct Bech32 {
    /// Human-readable part
    hrp: String,
    /// Data payload
    data: Vec<u5>
}

impl u5 {
    /// Convert a `u8` to `u5` if in range, return `Error` otherwise
    pub fn try_from_u8(value: u8) -> Result<u5, Error> {
        if value > 31 {
            Err(Error::InvalidData(value))
        } else {
            Ok(u5(value))
        }
    }

    /// Returns a copy of the underlying `u8` value
    pub fn to_u8(&self) -> u8 {
        self.0
    }
}

impl Into<u8> for u5 {
    fn into(self) -> u8 {
        self.0
    }
}

impl AsRef<u8> for u5 {
    fn as_ref(&self) -> &u8 {
        &self.0
    }
}

impl<'f, T: AsRef<[u8]>> CheckBase32<Vec<u5>> for T {
    type Err = Error;

    fn check_base32(self) -> Result<Vec<u5>, Self::Err> {
        self.as_ref().iter().map(|x| u5::try_from_u8(*x)).collect::<Result<Vec<u5>, Error>>()
    }
}

impl FromBase32 for Vec<u8> {
    type Err = Error;

    /// Convert base32 to base256, removes null-padding if present, returns
    /// `Err(Error::InvalidPadding)` if padding bits are unequal `0`
    fn from_base32(b32: &[u5]) -> Result<Self, Self::Err> {
        convert_bits(b32, 5, 8, false)
    }
}

impl<T: AsRef<[u8]>> ToBase32 for T {
    fn write_base32(&self, buffer: &mut Vec<u5>) {
        buffer.extend_from_slice(&convert_bits(self.as_ref(), 8, 5, true).expect(
            "both error conditions are impossible (InvalidPadding, InvalidData)"
        ).check_base32().expect(
            "after conversion all elements are in range"
        ))
    }
}

impl Bech32 {
    /// Constructs a `Bech32` struct if the result can be encoded as a bech32 string.
    pub fn new(hrp: String, data: Vec<u5>) -> Result<Bech32, Error> {
        if hrp.is_empty() {
            return Err(Error::InvalidLength)
        }

        Ok(Bech32 {hrp: hrp, data: data})
    }

    /// Constructs a `Bech32` struct if the result can be encoded as a bech32 string. It uses
    /// `data` that is not range checked yet and as a result may return `Err(Error::InvalidData)`.
    ///
    /// This function currently allocates memory for the checked data part.
    /// See [issue #19](https://github.com/rust-bitcoin/rust-bech32/issues/19).
    pub fn new_check_data(hrp: String, data: Vec<u8>) -> Result<Bech32, Error> {
        Self::new(hrp, data.check_base32()?)
    }

    /// Returns the human readable part
    pub fn hrp(&self) -> &str {
        &self.hrp
    }

    /// Returns the data part as `[u8]` but only using 5 bits per byte
    pub fn data(&self) -> &[u5] {
        &self.data
    }

    /// Destructures the `Bech32` struct into its parts
    pub fn into_parts(self) -> (String, Vec<u5>) {
        (self.hrp, self.data)
    }

    /// Parses a Bech32 string but without enforcing the 90 character limit (for lightning BOLT 11).
    pub fn from_str_lenient(s: &str) -> Result<Bech32, Error> {
        // Ensure overall length is within bounds
        let len: usize = s.len();
        if len < 8 {
            return Err(Error::InvalidLength)
        }

        // Check for missing separator
        if s.find(SEP).is_none() {
            return Err(Error::MissingSeparator)
        }

        // Split at separator and check for two pieces
        let parts: Vec<&str> = s.rsplitn(2, SEP).collect();
        let raw_hrp = parts[1];
        let raw_data = parts[0];
        if raw_hrp.len() < 1 || raw_data.len() < 6 {
            return Err(Error::InvalidLength)
        }

        let mut has_lower: bool = false;
        let mut has_upper: bool = false;
        let mut hrp_bytes: Vec<u8> = Vec::new();
        for b in raw_hrp.bytes() {
            // Valid subset of ASCII
            if b < 33 || b > 126 {
                return Err(Error::InvalidChar(b as char))
            }
            let mut c = b;
            // Lowercase
            if b >= b'a' && b <= b'z' {
                has_lower = true;
            }
            // Uppercase
            if b >= b'A' && b <= b'Z' {
                has_upper = true;
                // Convert to lowercase
                c = b + (b'a'-b'A');
            }
            hrp_bytes.push(c);
        }

        // Check data payload
        let mut data_bytes = raw_data.chars().map(|c| {
            // Only check if c is in the ASCII range, all invalid ASCII characters have the value -1
            // in CHARSET_REV (which covers the whole ASCII range) and will be filtered out later.
            if !c.is_ascii() {
                return Err(Error::InvalidChar(c))
            }

            if c.is_lowercase() {
                has_lower = true;
            } else if c.is_uppercase() {
                has_upper = true;
            }

            // c should be <128 since it is in the ASCII range, CHARSET_REV.len() == 128
            let num_value = CHARSET_REV[c as usize];

            if num_value > 31 || num_value < 0 {
                return Err(Error::InvalidChar(c));
            }

            Ok(u5::try_from_u8(num_value as u8).expect("range checked above, num_value <= 31"))
        }).collect::<Result<Vec<u5>, Error>>()?;

        // Ensure no mixed case
        if has_lower && has_upper {
            return Err(Error::MixedCase)
        }

        // Ensure checksum
        if !verify_checksum(&hrp_bytes, &data_bytes) {
            return Err(Error::InvalidChecksum)
        }

        // Remove checksum from data payload
        let dbl: usize = data_bytes.len();
        data_bytes.truncate(dbl - 6);

        Ok(Bech32 {
            hrp: String::from_utf8(hrp_bytes).unwrap(),
            data: data_bytes
        })
    }
}

impl Display for Bech32 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let hrp_bytes: &[u8] = self.hrp.as_bytes();
        let checksum = create_checksum(hrp_bytes, &self.data);
        let data_part = self.data.iter().chain(checksum.iter());

        write!(
            f,
            "{}{}{}",
            self.hrp,
            SEP,
            data_part.map(|p| CHARSET[*p.as_ref() as usize]).collect::<String>()
        )
    }
}

impl FromStr for Bech32 {
    type Err = Error;

    /// Decode from a string
    fn from_str(s: &str) -> Result<Bech32, Error> {
        if s.len() > 90 {
            return Err(Error::InvalidLength)
        }
        Self::from_str_lenient(s)
    }
}

fn create_checksum(hrp: &[u8], data: &[u5]) -> Vec<u5> {
    let mut values: Vec<u5> = hrp_expand(hrp);
    values.extend_from_slice(data);
    // Pad with 6 zeros
    values.extend_from_slice(&[u5::try_from_u8(0).unwrap(); 6]);
    let plm: u32 = polymod(&values) ^ 1;
    let mut checksum: Vec<u5> = Vec::new();
    for p in 0..6 {
        checksum.push(u5::try_from_u8(((plm >> (5 * (5 - p))) & 0x1f) as u8).unwrap());
    }
    checksum
}

fn verify_checksum(hrp: &[u8], data: &[u5]) -> bool {
    let mut exp = hrp_expand(hrp);
    exp.extend_from_slice(data);
    polymod(&exp) == 1u32
}

fn hrp_expand(hrp: &[u8]) -> Vec<u5> {
    let mut v: Vec<u5> = Vec::new();
    for b in hrp {
        v.push(u5::try_from_u8(*b >> 5).expect("can't be out of range, max. 7"));
    }
    v.push(u5::try_from_u8(0).unwrap());
    for b in hrp {
        v.push(u5::try_from_u8(*b & 0x1f).expect("can't be out of range, max. 31"));
    }
    v
}

fn polymod(values: &[u5]) -> u32 {
    let mut chk: u32 = 1;
    let mut b: u8;
    for v in values {
        b = (chk >> 25) as u8;
        chk = (chk & 0x1ffffff) << 5 ^ (u32::from(*v.as_ref()));
        for i in 0..5 {
            if (b >> i) & 1 == 1 {
                chk ^= GEN[i]
            }
        }
    }
    chk
}

/// Human-readable part and data part separator
const SEP: char = '1';

/// Encoding character set. Maps data value -> char
const CHARSET: [char; 32] = [
    'q','p','z','r','y','9','x','8',
    'g','f','2','t','v','d','w','0',
    's','3','j','n','5','4','k','h',
    'c','e','6','m','u','a','7','l'
];

// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
const CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
];

/// Generator coefficients
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/// Error types for Bech32 encoding / decoding
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Error {
    /// String does not contain the separator character
    MissingSeparator,
    /// The checksum does not match the rest of the data
    InvalidChecksum,
    /// The data or human-readable part is too long or too short
    InvalidLength,
    /// Some part of the string contains an invalid character
    InvalidChar(char),
    /// Some part of the data has an invalid value
    InvalidData(u8),
    /// The bit conversion failed due to a padding issue
    InvalidPadding,
    /// The whole string must be of one case
    MixedCase,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::MissingSeparator => write!(f, "missing human-readable separator, \"{}\"", SEP),
            Error::InvalidChecksum => write!(f, "invalid checksum"),
            Error::InvalidLength => write!(f, "invalid length"),
            Error::InvalidChar(n) => write!(f, "invalid character (code={})", n),
            Error::InvalidData(n) => write!(f, "invalid data point ({})", n),
            Error::InvalidPadding => write!(f, "invalid padding"),
            Error::MixedCase => write!(f, "mixed-case strings not allowed"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::MissingSeparator => "missing human-readable separator",
            Error::InvalidChecksum => "invalid checksum",
            Error::InvalidLength => "invalid length",
            Error::InvalidChar(_) => "invalid character",
            Error::InvalidData(_) => "invalid data point",
            Error::InvalidPadding => "invalid padding",
            Error::MixedCase => "mixed-case strings not allowed",
        }
    }
}

/// Convert between bit sizes
///
/// # Errors
/// * `Error::InvalidData` if any element of `data` is out of range
/// * `Error::InvalidPadding` if `pad == false` and the padding bits are not `0`
///
/// # Panics
/// Function will panic if attempting to convert `from` or `to` a bit size that
/// is 0 or larger than 8 bits.
///
/// # Examples
///
/// ```rust
/// use bech32::convert_bits;
/// let base5 = convert_bits(&[0xff], 8, 5, true);
/// assert_eq!(base5.unwrap(), vec![0x1f, 0x1c]);
/// ```
///
// TODO: use mut buffer
pub fn convert_bits<T>(data: &[T], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, Error>
    where T: Into<u8> + Copy
{
    if from > 8 || to > 8 || from == 0 || to == 0 {
        panic!("convert_bits `from` and `to` parameters 0 or greater than 8");
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret: Vec<u8> = Vec::new();
    let maxv: u32 = (1<<to) - 1;
    for value in data {
        let v: u32 = u32::from(Into::<u8>::into(*value));
        if (v >> from) != 0 {
            // Input value exceeds `from` bit size
            return Err(Error::InvalidData(v as u8))
        }
        acc = (acc << from) | v;
        bits += from;
        while bits >= to {
            bits -= to;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err(Error::InvalidPadding)
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use Bech32;
    use Error;
    use convert_bits;
    use CheckBase32;

    #[test]
    fn new_checks() {
        assert!(Bech32::new_check_data("test".into(), vec![1, 2, 3, 4]).is_ok());
        assert_eq!(Bech32::new_check_data("".into(), vec![1, 2, 3, 4]), Err(Error::InvalidLength));
        assert_eq!(Bech32::new_check_data("test".into(), vec![30, 31, 35, 20]), Err(Error::InvalidData(35)));

        let both = Bech32::new_check_data("".into(), vec![30, 31, 35, 20]);
        assert!(both == Err(Error::InvalidLength) || both == Err(Error::InvalidData(35)));

        assert!(Bech32::new("test".into(), [1u8, 2, 3, 4].check_base32().unwrap()).is_ok());
        assert_eq!(Bech32::new("".into(), [1u8, 2, 3, 4].check_base32().unwrap()), Err(Error::InvalidLength));
    }

    #[test]
    fn getters() {
        let bech: Bech32 = "BC1SW50QA3JX3S".parse().unwrap();
        let data = [16, 14, 20, 15, 0].check_base32().unwrap();
        assert_eq!(bech.hrp(), "bc");
        assert_eq!(
            bech.data(),
            data.as_slice()
        );
        assert_eq!(bech.into_parts(), ("bc".to_owned(), data));
    }

    #[test]
    fn valid_checksum() {
        let strings: Vec<&str> = vec!(
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        );
        for s in strings {
            let decode_result = s.parse::<Bech32>();
            if !decode_result.is_ok() {
                panic!("Did not decode: {:?} Reason: {:?}", s, decode_result.unwrap_err());
            }
            assert!(decode_result.is_ok());
            let encode_result = decode_result.unwrap().to_string();
            assert_eq!(s.to_lowercase(), encode_result.to_lowercase());
        }
    }

    #[test]
    fn invalid_strings() {
        let pairs: Vec<(&str, Error)> = vec!(
            (" 1nwldj5",
                Error::InvalidChar(' ')),
            ("abc1\u{2192}axkwrx",
                Error::InvalidChar('\u{2192}')),
            ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
                Error::InvalidLength),
            ("pzry9x0s0muk",
                Error::MissingSeparator),
            ("1pzry9x0s0muk",
                Error::InvalidLength),
            ("x1b4n0q5v",
                Error::InvalidChar('b')),
            ("ABC1DEFGOH",
                Error::InvalidChar('O')),
            ("li1dgmt3",
                Error::InvalidLength),
            ("de1lg7wt\u{ff}",
                Error::InvalidChar('\u{ff}')),
        );
        for p in pairs {
            let (s, expected_error) = p;
            let dec_result = s.parse::<Bech32>();
            if dec_result.is_ok() {
                println!("{:?}", dec_result.unwrap());
                panic!("Should be invalid: {:?}", s);
            }
            assert_eq!(dec_result.unwrap_err(), expected_error, "testing input '{}'", s);
        }
    }

    #[test]
    fn valid_conversion() {
        // Set of [data, from_bits, to_bits, pad, result]
        let tests: Vec<(Vec<u8>, u32, u32, bool, Vec<u8>)> = vec!(
            (vec![0x01], 1, 1, true, vec![0x01]),
            (vec![0x01, 0x01], 1, 1, true, vec![0x01, 0x01]),
            (vec![0x01], 8, 8, true, vec![0x01]),
            (vec![0x01], 8, 4, true, vec![0x00, 0x01]),
            (vec![0x01], 8, 2, true, vec![0x00, 0x00, 0x00, 0x01]),
            (vec![0x01], 8, 1, true, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            (vec![0xff], 8, 5, true, vec![0x1f, 0x1c]),
            (vec![0x1f, 0x1c], 5, 8, false, vec![0xff]),
        );
        for t in tests {
            let (data, from_bits, to_bits, pad, expected_result) = t;
            let result = convert_bits(&data, from_bits, to_bits, pad);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected_result);
        }
    }

    #[test]
    fn invalid_conversion() {
        // Set of [data, from_bits, to_bits, pad, expected error]
        let tests: Vec<(Vec<u8>, u32, u32, bool, Error)> = vec!(
            (vec![0xff], 8, 5, false, Error::InvalidPadding),
            (vec![0x02], 1, 1, true, Error::InvalidData(0x02)),
        );
        for t in tests {
            let (data, from_bits, to_bits, pad, expected_error) = t;
            let result = convert_bits(&data, from_bits, to_bits, pad);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), expected_error);
        }
    }

    #[test]
    fn convert_bits_invalid_bit_size() {
        use std::panic::{catch_unwind, set_hook, take_hook};

        let invalid = &[(0, 8), (5, 0), (9, 5), (8, 10), (0, 16)];

        for &(from, to) in invalid {
            set_hook(Box::new(|_| {}));
            let result = catch_unwind(|| {
                let _ = convert_bits(&[0], from, to, true);
            });
            take_hook();
            assert!(result.is_err());
        }
    }

    #[test]
    fn lenient_parsing() {
        assert_ne!(
            Bech32::from_str_lenient("an84characterslonghumanreadablepartthatcontainsthenumber1a\
            ndtheexcludedcharactersbio1569pvx"),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn check_base32() {
        assert!([0u8, 1, 2, 30, 31].check_base32().is_ok());
        assert!([0u8, 1, 2, 30, 31, 32].check_base32().is_err());
        assert!([0u8, 1, 2, 30, 31, 255].check_base32().is_err());
    }

    #[test]
    fn from_base32() {
        use FromBase32;
        assert_eq!(Vec::from_base32(&[0x1f, 0x1c].check_base32().unwrap()), Ok(vec![0xff]));
        assert_eq!(
            Vec::from_base32(&[0x1f, 0x1f].check_base32().unwrap()),
            Err(Error::InvalidPadding)
        );
    }

    #[test]
    fn to_base32() {
        use ToBase32;
        assert_eq!([0xffu8].to_base32(), [0x1f, 0x1c].check_base32().unwrap());
    }

    #[test]
    fn reverse_charset() {
        // AsciiExt is needed for Rust 1.14 but not for newer versions
        #[allow(unused_imports, deprecated)]
        use std::ascii::AsciiExt;
        use ::CHARSET_REV;

        fn get_char_value(c: char) -> i8 {
            let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
            match charset.find(c.to_ascii_lowercase()) {
                Some(x) => x as i8,
                None => -1,
            }
        }

        let expected_rev_charset = (0u8..128).map(|i| {
            get_char_value(i as char)
        }).collect::<Vec<_>>();

        assert_eq!(&(CHARSET_REV[..]), expected_rev_charset.as_slice());
    }
}
