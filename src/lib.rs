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
use core::fmt;

// Re-export all types from `primitives` modules that appear in the public API.
pub use crate::primitives::gf32::Fe32;
pub use crate::primitives::hrp::Hrp;
pub use crate::primitives::hrpstring::Parsed;
// Also re-export the iter extensions because the conversion methods are core functionality.
pub use crate::primitives::iter::{ByteIterExt, Fe32IterExt};
pub use crate::primitives::{Bech32, Bech32m, NoChecksum};

mod error;
pub mod primitives;

pub use primitives::gf32::Fe32 as u5;

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
    let iter = data.as_ref().iter().copied();
    match variant {
        Variant::Bech32 =>
            for c in iter.checksummed::<Bech32>().hrp_checksummed(&hrp).hrpstring_chars() {
                fmt.write_char(c)?;
            },
        Variant::Bech32m =>
            for c in iter.checksummed::<Bech32m>().hrp_checksummed(&hrp).hrpstring_chars() {
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
pub fn encode<T: AsRef<[u5]>>(hrp: Hrp, data: T, variant: Variant) -> Result<String, fmt::Error> {
    let mut buf = String::new();
    crate::encode_to_fmt(&mut buf, hrp, data, variant)?;
    Ok(buf)
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
pub fn decode(s: &str) -> Result<(Parsed, Variant), Error> {
    if let Ok(p) = Parsed::new::<Bech32m>(s) {
        return Ok((p, Variant::Bech32m));
    }
    match Parsed::new::<Bech32>(s) {
        Ok(p) => Ok((p, Variant::Bech32)),
        Err(e) => Err(Error::Hrpstring(e)),
    }
}

/// Decodes a bech32 string, assuming no checksum.
pub fn decode_without_checksum(s: &str) -> Result<Parsed, Error> {
    let p = Parsed::new::<NoChecksum>(s)?;
    Ok(p)
}

/// Human-readable part and data part separator.
const SEP: char = '1';

/// Error types for Bech32 encoding / decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Conversion to u5 failed.
    TryFrom(primitives::gf32::Error),
    /// HRP parsing failed.
    Hrp(primitives::hrp::Error),
    /// hrpstring parsing failed.
    Hrpstring(primitives::hrpstring::Error),
}

impl From<primitives::hrp::Error> for Error {
    fn from(e: primitives::hrp::Error) -> Self { Error::Hrp(e) }
}

impl From<primitives::hrpstring::Error> for Error {
    fn from(e: primitives::hrpstring::Error) -> Self { Error::Hrpstring(e) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            TryFrom(ref e) => write_err!(f, "conversion to u5 failed"; e),
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
        }
    }
}

impl From<primitives::gf32::Error> for Error {
    fn from(e: primitives::gf32::Error) -> Self { Error::TryFrom(e) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    fn hrp(s: &str) -> Hrp { Hrp::parse_unchecked(s) }

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
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        );
        for s in strings {
            match decode(s) {
                Ok((parsed, variant)) => {
                    let hrp = parsed.hrp();
                    let data = parsed.fe32_iter().collect::<Vec<u5>>();
                    let encoded =
                        encode(hrp, data, variant).expect("failed to encode decoded parts");
                    assert_eq!(s.to_lowercase(), encoded.to_lowercase());
                }
                Err(e) => panic!("Did not decode: {:?} Reason: {:?}", s, e),
            }
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn invalid_strings() {
        use crate::primitives::{hrp, hrpstring};

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
                Error::Hrpstring(hrpstring::Error::InvalidChecksumLength)),
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
                Error::Hrpstring(hrpstring::Error::InvalidChecksumLength)),
            ("mm1crxm3i",
                Error::Hrpstring(hrpstring::Error::InvalidChar('i'))),
            ("au1s5cgom",
                Error::Hrpstring(hrpstring::Error::InvalidChar('o'))),
            ("M1VUXWEZ",
                Error::Hrpstring(hrpstring::Error::InvalidChecksum)),
            ("16plkw9",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::Empty))),
            ("1p2gdwpf",
                Error::Hrpstring(hrpstring::Error::InvalidHrp(hrp::Error::Empty))),
            ("bc1p2",
                Error::Hrpstring(hrpstring::Error::InvalidChecksumLength)),
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
    #[cfg(feature = "alloc")]
    fn test_encode() {
        assert_eq!(Hrp::parse(""), Err(primitives::hrp::Error::Empty));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn roundtrip_without_checksum() {
        let hrp = hrp("lnbc");
        let data = "Hello World!".bytes().bytes_to_fes().collect::<Vec<u5>>();

        let encoded = encode_without_checksum(hrp, data.clone()).expect("failed to encode");
        let parsed = decode_without_checksum(&encoded).expect("failed to decode");

        let decoded_hrp = parsed.hrp();
        let decoded_data = parsed.byte_iter().bytes_to_fes().collect::<Vec<u5>>();
        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, data);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_hrp_case() {
        let fes = [0x00, 0x00].iter().copied().bytes_to_fes().collect::<Vec<u5>>();
        // Tests for issue with HRP case checking being ignored for encoding
        let encoded_str = encode(hrp("HRP"), fes, Variant::Bech32).expect("failed to encode");

        assert_eq!(encoded_str, "hrp1qqqq40atq3");
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
        let addr = "23451QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZLKULZK";
        let (parsed, variant) = crate::decode(addr).expect("address is well formed");

        let got_hrp = parsed.hrp();
        let want_hrp = Hrp::parse("2345").unwrap();
        assert_eq!(got_hrp, want_hrp);

        let data = parsed.fe32_iter().collect::<Vec<u5>>();
        let encoded = encode(got_hrp, data, variant).expect("failed to encode decoded parts");
        assert_eq!(encoded.to_uppercase(), addr);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn roundtrip_bitcoin_bech32_address() {
        let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let (parsed, variant) = crate::decode(addr).expect("address is well formed");

        let hrp = parsed.hrp();
        let data = parsed.fe32_iter().collect::<Vec<u5>>();
        let encoded = crate::encode(hrp, data, variant).expect("failed to encode");
        assert_eq!(encoded, addr);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn roundtrip_bitcoin_bech32m_address() {
        let addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        let (parsed, variant) = crate::decode(addr).expect("address is well formed");

        let hrp = parsed.hrp();
        let data = parsed.fe32_iter().collect::<Vec<u5>>();
        let encoded = crate::encode(hrp, data, variant).expect("failed to encode");
        assert_eq!(encoded, addr);
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::*;

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
        let (parsed, variant) = crate::decode(&addr).expect("address is well formed");

        let hrp = parsed.hrp();
        let data = parsed.fe32_iter().collect::<Vec<u5>>();

        bh.iter(|| {
            let s = crate::encode(hrp, &data, variant);
            black_box(&s);
        });
    }

    // Encode without allocation.
    #[bench]
    fn encode_to_fmt_bech32_address(bh: &mut Bencher) {
        let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let (parsed, variant) = crate::decode(&addr).expect("address is well formed");

        let mut buf = String::with_capacity(64);
        let hrp = parsed.hrp();
        let data = parsed.fe32_iter().collect::<Vec<u5>>();

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
        let (parsed, variant) = crate::decode(&addr).expect("address is well formed");

        let hrp = parsed.hrp();
        let data = parsed.fe32_iter().collect::<Vec<u5>>();

        bh.iter(|| {
            let s = crate::encode(hrp, &data, variant);
            black_box(&s);
        });
    }

    // Encode without allocation.
    #[bench]
    fn encode_to_fmt_bech32m_address(bh: &mut Bencher) {
        let addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        let (parsed, variant) = crate::decode(&addr).expect("address is well formed");

        let mut buf = String::with_capacity(64);
        let hrp = parsed.hrp();
        let data = parsed.fe32_iter().collect::<Vec<u5>>();

        bh.iter(|| {
            let res =
                crate::encode_to_fmt(&mut buf, hrp, &data, variant).expect("failed to encode");
            black_box(&res);
        });
    }
}
