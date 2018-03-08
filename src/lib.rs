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
//! let b = Bech32::new("bech32".into(), vec![0x00, 0x01, 0x02]).unwrap();
//! let encoded = b.to_string();
//! assert_eq!(encoded, "bech321qpz4nc4pe".to_string());
//!
//! let c = encoded.parse::<Bech32>();
//! assert_eq!(b, c.unwrap());
//! ```

#![deny(missing_docs)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

use std::{error, fmt};
use std::str::FromStr;
use std::fmt::{Display, Formatter};

/// Grouping structure for the human-readable part and the data part
/// of decoded Bech32 string.
#[derive(PartialEq, Debug, Clone)]
pub struct Bech32 {
    /// Human-readable part
    hrp: String,
    /// Data payload
    data: Vec<u8>
}

type DecodeResult = Result<Bech32, Error>;

impl Bech32 {

    /// Constructs a `Bech32` struct if the result can be encoded as a bech32 string.
    pub fn new(hrp: String, data: Vec<u8>) -> Result<Bech32, Error> {
        if hrp.is_empty() {
            return Err(Error::InvalidLength)
        }
        if let Some(bad_byte) = data.iter().find(|&&x| x >= 32) {
            return Err(Error::InvalidData(*bad_byte));
        }

        Ok(Bech32 {hrp, data})
    }

    /// Returns the human readable part
    pub fn hrp(&self) -> &str {
        &self.hrp
    }

    /// Returns the data part as `[u8]` but only using 5 bits per byte
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Destructures the `Bech32` struct into its parts
    pub fn into_parts(self) -> (String, Vec<u8>) {
        (self.hrp, self.data)
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
            data_part.map(|p| CHARSET[*p as usize]).collect::<String>()
        )
    }
}

impl FromStr for Bech32 {
    type Err = Error;

    /// Decode from a string
    fn from_str(s: &str) -> DecodeResult {
        // Ensure overall length is within bounds
        let len: usize = s.len();
        if len < 8 || len > 90 {
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
                return Err(Error::InvalidChar(b))
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
        let mut data_bytes: Vec<u8> = Vec::new();
        for b in raw_data.bytes() {
            // Aphanumeric only
            if !((b >= b'0' && b <= b'9') || (b >= b'A' && b <= b'Z') || (b >= b'a' && b <= b'z')) {
                return Err(Error::InvalidChar(b))
            }
            // Excludes these characters: [1,b,i,o]
            if b == b'1' || b == b'b' || b == b'i' || b == b'o' {
                return Err(Error::InvalidChar(b))
            }
            // Lowercase
            if b >= b'a' && b <= b'z' {
                has_lower = true;
            }

            // Uppercase
            let c = if b >= b'A' && b <= b'Z' {
                has_upper = true;
                // Convert to lowercase
                b + (b'a'-b'A')
            } else {
                b
            };

            data_bytes.push(CHARSET_REV[c as usize] as u8);
        }

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

fn create_checksum(hrp: &[u8], data: &[u8]) -> Vec<u8> {
    let mut values: Vec<u8> = hrp_expand(hrp);
    values.extend_from_slice(data);
    // Pad with 6 zeros
    values.extend_from_slice(&[0u8; 6]);
    let plm: u32 = polymod(&values) ^ 1;
    let mut checksum: Vec<u8> = Vec::new();
    for p in 0..6 {
        checksum.push(((plm >> (5 * (5 - p))) & 0x1f) as u8);
    }
    checksum
}

fn verify_checksum(hrp: &[u8], data: &[u8]) -> bool {
    let mut exp = hrp_expand(hrp);
    exp.extend_from_slice(data);
    polymod(&exp) == 1u32
}

fn hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for b in hrp {
        v.push(*b >> 5);
    }
    v.push(0);
    for b in hrp {
        v.push(*b & 0x1f);
    }
    v
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    let mut b: u8;
    for v in values {
        b = (chk >> 25) as u8;
        chk = (chk & 0x1ffffff) << 5 ^ (u32::from(*v));
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
#[derive(PartialEq, Debug)]
pub enum Error {
    /// String does not contain the separator character
    MissingSeparator,
    /// The checksum does not match the rest of the data
    InvalidChecksum,
    /// The data or human-readable part is too long or too short
    InvalidLength,
    /// Some part of the string contains an invalid character
    InvalidChar(u8),
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

type ConvertResult = Result<Vec<u8>, Error>;

/// Convert between bit sizes
///
/// # Panics
/// Function will panic if attempting to convert `from` or `to` a bit size that
/// is larger than 8 bits.
///
/// # Examples
///
/// ```rust
/// use bech32::convert_bits;
/// let base5 = convert_bits(vec![0xff], 8, 5, true);
/// assert_eq!(base5.unwrap(), vec![0x1f, 0x1c]);
/// ```
pub fn convert_bits(data: Vec<u8>, from: u32, to: u32, pad: bool) -> ConvertResult {
    if from > 8 || to > 8 {
        panic!("convert_bits `from` and `to` parameters greater than 8");
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret: Vec<u8> = Vec::new();
    let maxv: u32 = (1<<to) - 1;
    for value in data {
        let v: u32 = value as u32;
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

    #[test]
    fn new_checks() {
        assert!(Bech32::new("test".into(), vec![1, 2, 3, 4]).is_ok());
        assert_eq!(Bech32::new("".into(), vec![1, 2, 3, 4]), Err(Error::InvalidLength));
        assert_eq!(Bech32::new("test".into(), vec![30, 31, 35, 20]), Err(Error::InvalidData(35)));

        let both = Bech32::new("".into(), vec![30, 31, 35, 20]);
        assert!(both == Err(Error::InvalidLength) || both == Err(Error::InvalidData(35)));
    }

    #[test]
    fn getters() {
        let bech: Bech32 = "BC1SW50QA3JX3S".parse().unwrap();
        let data: Vec<u8> = vec![16, 14, 20, 15, 0];
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
                Error::InvalidChar(b' ')),
            ("\x7f1axkwrx",
                Error::InvalidChar(0x7f)),
            ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
                Error::InvalidLength),
            ("pzry9x0s0muk",
                Error::MissingSeparator),
            ("1pzry9x0s0muk",
                Error::InvalidLength),
            ("x1b4n0q5v",
                Error::InvalidChar(b'b')),
            ("li1dgmt3",
                Error::InvalidLength),
            ("de1lg7wt\u{ff}",
                Error::InvalidChar(0xc3)), // ASCII 0xff -> \uC3BF in UTF-8
        );
        for p in pairs {
            let (s, expected_error) = p;
            let dec_result = s.parse::<Bech32>();
            println!("{:?}", s.to_string());
            if dec_result.is_ok() {
                println!("{:?}", dec_result.unwrap());
                panic!("Should be invalid: {:?}", s);
            }
            assert_eq!(dec_result.unwrap_err(), expected_error);
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
            let result = convert_bits(data, from_bits, to_bits, pad);
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
            let result = convert_bits(data, from_bits, to_bits, pad);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), expected_error);
        }
    }
}
