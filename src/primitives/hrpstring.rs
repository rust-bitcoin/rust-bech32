// SPDX-License-Identifier: MIT

//! String encoding/decoding of HRP strings as specified by [BIP-173] (bech32) and [BIP-350] (bech32m).
//!
//! HRP string format: `<hrp> 1 <witness_version> <payload> <checksum>`
//!
//! * **hrp**: Human Readable Part.
//! * **witness_version**: 0 ('q) for bech32 1 ('p') for bech32m.
//! * **payload**: GF(32) bech32 encoded characters.
//! * **checksum**: BCH code checksum.
//!
//! [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
//! [BIP-350]: <https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki>

use core::convert::TryFrom;
use core::{fmt, iter, slice, str};

use crate::primitives::checksum::{self, Checksum};
use crate::primitives::gf32::{self, Fe32};
use crate::primitives::hrp::{self, Hrp};
use crate::primitives::iter::{Fe32IterExt, FesToBytes};
use crate::write_err;

/// Separator between the hrp and payload (as defined by BIP-173).
const SEP: char = '1';

/// An HRP string that has been parsed and had the checksum validated.
///
/// Pre-parsing an HRP string only checks validity of the characters, it does not validate the checksum in any way - to validate convert to [`Parsed`].
#[derive(Debug)]
pub struct Parsed<'s> {
    /// The human-readable part, guaranteed to be lowercase ASCII characters.
    hrp: Hrp,
    /// The witness version, if one exists.
    witness_version: Option<u8>,
    /// This is ASCII byte values of the parsed string, guaranteed to be valid bech32 characters, with the checksum removed.
    data: &'s [u8],
}

impl<'s> Parsed<'s> {
    /// Parses an HRP string, without treating the first data character specially.
    ///
    /// Cuidado, if you are doing segwit-y stuff you almost certainly want to use
    /// [`Parsed::new_with_witness_version`].
    pub fn new<Ck: Checksum>(s: &'s str) -> Result<Self, Error> {
        let unvalidated = Parsed::parse_unvalidated(s)?;

        if unvalidated.data.is_empty() {
            return Err(Error::NothingAfterSeparator);
        }

        let ret = unvalidated.validate_checksum::<Ck>()?;

        Ok(ret)
    }

    /// Parses an HRP string, treating the first data character as a witness version.
    ///
    /// This version byte does not appear in the extracted binary data, but is covered
    /// by the checksum. It can be accessed with [`Self::witness_version`] and is also
    /// returned from this constructor as a convenience.
    pub fn new_with_witness_version<Ck: Checksum>(s: &'s str) -> Result<(Self, u8), Error> {
        let mut unvalidated = Parsed::parse_unvalidated(s)?;

        if unvalidated.data.is_empty() {
            return Err(Error::NothingAfterSeparator);
        }

        // Unwrap ok since check_characters (in `Self::new`) checked the bech32-ness of this char.
        let witver = Fe32::from_char(unvalidated.data[0].into()).unwrap().to_u8();

        unvalidated.witness_version = Some(witver);
        unvalidated.data = &unvalidated.data[1..]; // checksum removed by validation below.

        let ret = unvalidated.validate_checksum::<Ck>()?;

        // From BIP-173:
        // > Re-arrange those bits into groups of 8 bits. Any incomplete group at the
        // > end MUST be 4 bits or less, MUST be all zeroes, and is discarded.
        if ret.data.len() * 5 % 8 > 4 {
            return Err(Error::InvalidDataLength);
        }

        Ok((ret, witver))
    }

    /// Returns the witness version if present.
    pub fn witness_version(&self) -> Option<u8> { self.witness_version }

    /// Returns the human-readable part.
    pub fn hrp(&self) -> Hrp { self.hrp }

    /// Returns an iterator over the byte data encoded by the HRP string (excluding the HRP, witness
    /// version byte if any, and checksum).
    pub fn byte_iter(&self) -> ByteIter {
        ByteIter { iter: AsciiToFe32Iter { iter: self.data.iter().copied() }.fes_to_bytes() }
    }

    /// Returns an iterate over field elements of the data encoded by the HRP string (excluding the
    /// HRP, witness version byte if any, and checksum).
    pub fn fe32_iter(&self) -> Fe32Iter {
        Fe32Iter { iter: AsciiToFe32Iter { iter: self.data.iter().copied() } }
    }

    /// Parses an bech32 encode string and constructs a [`Parsed`] object that must have
    /// `validate_checksum` called (if it contains a checksum).
    ///
    /// Checks for valid ASCII values, does not validate the checksum.
    fn parse_unvalidated(s: &'s str) -> Result<Self, Error> {
        let sep_pos = check_characters(s)?;
        let (hrp, data) = s.split_at(sep_pos);

        let ret = Parsed {
            hrp: Hrp::parse(hrp)?,
            witness_version: None,
            data: data[1..].as_bytes(), // Skip the separator.
        };

        Ok(ret)
    }

    /// Validates that a [`Parsed`] returned by `parse_unvalidated` has a valid checksum.
    ///
    /// # Returns
    ///
    /// Returns `self` with the checksum removed from the inner data slice.
    fn validate_checksum<Ck: Checksum>(mut self) -> Result<Self, Error> {
        if Ck::CHECKSUM_LENGTH == 0 {
            return Ok(self); // Called with NoChecksum.
        }

        if self.data.len() < Ck::CHECKSUM_LENGTH {
            return Err(Error::InvalidChecksumLength);
        }

        let mut checksum_eng = checksum::Engine::<Ck>::new();
        checksum_eng.input_hrp(&self.hrp());
        if let Some(witver) = self.witness_version {
            checksum_eng.input_fe(Fe32::try_from(witver).map_err(Error::InvalidWitnessVersion)?);
        }
        // Unwrap ok since we checked all characters in our constructor.
        for fe in self.data.iter().map(|&b| Fe32::from_char_unchecked(b)) {
            checksum_eng.input_fe(fe);
        }

        if checksum_eng.residue() != &Ck::TARGET_RESIDUE {
            return Err(Error::InvalidChecksum);
        }

        let data_len = self.data.len() - Ck::CHECKSUM_LENGTH;
        self.data = &self.data[..data_len];

        Ok(self)
    }
}

/// A iterator over a parsed HRP string data as bytes.
pub struct ByteIter<'s> {
    iter: FesToBytes<AsciiToFe32Iter<iter::Copied<slice::Iter<'s, u8>>>>,
}

impl<'s> Iterator for ByteIter<'s> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> { self.iter.next() }
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

/// A iterator over a parsed HRP string data as field elements.
pub struct Fe32Iter<'s> {
    iter: AsciiToFe32Iter<iter::Copied<slice::Iter<'s, u8>>>,
}

impl<'s> Iterator for Fe32Iter<'s> {
    type Item = Fe32;
    fn next(&mut self) -> Option<Fe32> { self.iter.next() }
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

/// Helper iterator adaptor that maps an iterator of valid bech32 character ASCII bytes to an
/// iterator of field elements.
///
/// This iterator is a performance optimization. Equivalent, but significantly faster than, using
/// `hrp_string.data_chk.iter().copied().map(|c| Fe32::from_char_unchecked(c).to_u8())`.
///
/// # Panics
///
/// If any `u8` in the input iterator is out of range for an [`Fe32`]. Should only be used on data
/// that has already been checked for validity (eg, by using `check_characters`).
struct AsciiToFe32Iter<I: Iterator<Item = u8>> {
    iter: I,
}

impl<I> Iterator for AsciiToFe32Iter<I>
where
    I: Iterator<Item = u8>,
{
    type Item = Fe32;
    fn next(&mut self) -> Option<Fe32> { self.iter.next().map(Fe32::from_char_unchecked) }
    fn size_hint(&self) -> (usize, Option<usize>) {
        // Each ASCII character is an fe32 so iterators are the same size.
        self.iter.size_hint()
    }
}

/// Checks whether a given HRP string has data characters in the bech32 alphabet (incl. checksum
/// characters), and that the whole string has consistent casing (hrp, data, and checksum).
///
/// # Returns
///
/// The byte-index into the string where the '1' separator occurs, or an error if it does not.
fn check_characters(s: &str) -> Result<usize, Error> {
    let mut has_upper = false;
    let mut has_lower = false;
    let mut req_bech32 = true;
    let mut sep_pos = None;
    for (n, ch) in s.char_indices().rev() {
        if ch == SEP && sep_pos.is_none() {
            req_bech32 = false;
            sep_pos = Some(n);
        }
        if req_bech32 {
            Fe32::from_char(ch).map_err(|_| Error::InvalidChar(ch))?;
        }
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        }
    }
    if has_upper && has_lower {
        Err(Error::MixedCase)
    } else if let Some(pos) = sep_pos {
        Ok(pos)
    } else {
        Err(Error::MissingSeparator)
    }
}

/// Errors types for Bech32 (hrpstring) encoding / decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Human-readable part is invalid.
    InvalidHrp(hrp::Error),
    /// String does not contain the separator character.
    MissingSeparator,
    /// No characters after the separator.
    NothingAfterSeparator,
    /// Attempt conversion of an invalid witness version string/number.
    InvalidWitnessVersion(gf32::Error),
    /// The data payload is not a valid length.
    InvalidDataLength,
    /// The checksum does not match the rest of the data.
    InvalidChecksum,
    /// The checksum is not a valid length.
    InvalidChecksumLength,
    /// Some part of the string contains an invalid character.
    InvalidChar(char),
    /// The whole string must be of one case.
    MixedCase,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            InvalidHrp(ref e) => write_err!(f, "invalid human-readable part"; e),
            MissingSeparator => write!(f, "missing human-readable separator, \"{}\"", SEP),
            NothingAfterSeparator => write!(f, "invalid data - no characters after the separator"),
            InvalidWitnessVersion(ref e) => write_err!(f, "witness version error"; e),
            InvalidDataLength => write!(f, "invalid data - payload is not a valid length"),
            InvalidChecksum => write!(f, "invalid checksum"),
            InvalidChecksumLength => write!(f, "the checksum is not a valid length"),
            InvalidChar(n) => write!(f, "invalid character (code={})", n),
            MixedCase => write!(f, "mixed-case strings not allowed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            InvalidHrp(ref e) => Some(e),
            InvalidWitnessVersion(ref e) => Some(e),
            MissingSeparator
            | NothingAfterSeparator
            | InvalidDataLength
            | InvalidChecksum
            | InvalidChecksumLength
            | InvalidChar(_)
            | MixedCase => None,
        }
    }
}

impl From<hrp::Error> for Error {
    fn from(e: hrp::Error) -> Self { Error::InvalidHrp(e) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bech32, Bech32m};

    #[test]
    #[allow(unused_variables)] // Triggered by matches macro.
    fn bip_173_invalid_hrpstring_parsing_fails() {
        let invalid: Vec<(&str, Error)> = vec!(
            ("\u{20}1nwldj5",
             Error::InvalidChar('\u{20}')),
            ("\u{7F}1axkwrx",
             Error::InvalidChar('\u{7F}')),
            ("\u{80}1eym55h",
             Error::InvalidChar('\u{80}')),
            ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
             Error::InvalidHrp(hrp::Error::TooLong(84))),
            ("pzry9x0s0muk",
             Error::MissingSeparator),
            ("1pzry9x0s0muk",
             Error::InvalidHrp(hrp::Error::Empty)),
            ("x1b4n0q5v",
             Error::InvalidChar('b')),
            ("de1lg7wt\u{ff}",
             Error::InvalidChar('\u{ff}')),
            ("10a06t8",
             Error::InvalidHrp(hrp::Error::Empty)),
            ("1qzzfhee",
             Error::InvalidHrp(hrp::Error::Empty)),
        );

        for (s, expected_error) in invalid {
            assert!(matches!(Parsed::new_with_witness_version::<Bech32>(s), Err(expected_error)));
            assert!(matches!(Parsed::new::<Bech32>(s), Err(expected_error)));
        }
    }

    #[test]
    #[allow(unused_variables)] // Triggered by matches macro.
    fn bip_173_invalid_hrpstring_because_of_invalid_checksum() {
        assert!(matches!(Parsed::new::<Bech32>("li1dgmt3"), Err(Error::InvalidChecksumLength)))
    }

    #[test]
    #[allow(unused_variables)] // Triggered by matches macro.
    fn bip_350_invalid_hrpstring_parsing_fails() {
        let invalid: Vec<(&str, Error)> = vec!(
            ("\u{20}1xj0phk",
             Error::InvalidChar('\u{20}')),
            ("\u{7F}1g6xzxy",
             Error::InvalidChar('\u{7F}')),
            ("\u{80}1g6xzxy",
             Error::InvalidChar('\u{7F}')),
            ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
             Error::InvalidHrp(hrp::Error::TooLong(84))),
            ("qyrz8wqd2c9m",
             Error::MissingSeparator),
            ("1qyrz8wqd2c9m",
             Error::InvalidHrp(hrp::Error::Empty)),
            ("y1b0jsk6g",
             Error::InvalidChar('b')),
            ("lt1igcx5c0",
             Error::InvalidChar('i')),
            ("mm1crxm3i",
             Error::InvalidChar('i')),
            ("au1s5cgom",
             Error::InvalidChar('o')),
            ("16plkw9",
             Error::InvalidHrp(hrp::Error::Empty)),
            ("1p2gdwpf",
             Error::InvalidHrp(hrp::Error::Empty)),

        );

        for (s, expected_error) in invalid {
            assert!(matches!(Parsed::new_with_witness_version::<Bech32m>(s), Err(expected_error)));
            assert!(matches!(Parsed::new::<Bech32m>(s), Err(expected_error)));
        }
    }

    #[test]
    #[allow(unused_variables)] // Triggered by matches macro.
    fn bip_350_invalid_hrpstring_because_of_invalid_checksum() {
        // Note the "bc1p2" test case is not from the bip test vectors.
        let invalid: Vec<&str> = vec!["in1muywd", "bc1p2"];

        for s in invalid {
            assert!(matches!(Parsed::new::<Bech32m>(s), Err(Error::InvalidChecksumLength)))
        }
    }

    #[test]
    fn check_hrp_lowercase() {
        let addr = "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj";
        let (parsed, _) =
            Parsed::new_with_witness_version::<Bech32>(addr).expect("failed to parse address");
        assert_eq!(parsed.hrp(), Hrp::parse_unchecked("bc"));
    }

    #[test]
    fn check_hrp_uppercase_returns_lower() {
        let addr = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        let parsed = Parsed::new::<Bech32>(addr).expect("failed to parse address");
        assert_eq!(parsed.hrp(), Hrp::parse_unchecked("bc"));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn check_hrp_max_length() {
        let hrps =
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio";

        let hrp = Hrp::parse_unchecked(hrps);
        let s =
            crate::encode(hrp, [], crate::Variant::Bech32).expect("failed to encode empty buffer");

        let parsed = Parsed::new::<Bech32>(&s).expect("failed to parse address");
        assert_eq!(parsed.hrp(), hrp);
    }

    #[test]
    fn exclude_strings_that_are_not_valid_bech32_length_0() {
        let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        assert!(Parsed::new::<Bech32>(addr).is_ok())
    }

    #[test]
    fn exclude_strings_that_are_not_valid_bech32_length_1() {
        let addr = "23451QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZLKULZK";
        assert!(Parsed::new::<Bech32>(addr).is_ok())
    }
}
