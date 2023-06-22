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

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::borrow::Cow;
use core::convert::{Infallible, TryFrom};
use core::marker::PhantomData;
use core::{fmt, iter, slice, str};

use crate::primitives::checksum::{self, Checksum};
use crate::primitives::gf32::{self, Fe32};
use crate::primitives::hrp::{self, Hrp};
use crate::primitives::iter::{Fe32IterExt, FeToByteIter};
use crate::write_err;

/// Separator between the hrp and payload (as defined by BIP-173).
const SEP: char = '1';

/// An HRP string that has been parsed from an ordinary checksummed string.
///
/// Parsing as an HRP string does not validate the checksum in any way.
pub struct Parsed<'s> {
    /// The human-readable part, guaranteed to be lowercase ASCII characters.
    hrp: Hrp,
    /// The witness version, if one exists.
    witness_version: Option<u8>,
    /// The data part (including checksum, if any).
    ///
    /// This is ASCII byte values of the parsed string, guaranteed to be valid bech32 characters.
    data_chk: &'s [u8],
}

impl<'s> Parsed<'s> {
    /// Parses an HRP string, without treating the first data character specially.
    pub fn new(s: &'s str) -> Result<Self, Error> {
        let sep_pos = check_characters(s)?;
        let (hrp, data) = s.split_at(sep_pos);

        let p = Parsed {
            hrp: Hrp::parse(hrp)?,
            witness_version: None,
            data_chk: data[1..].as_bytes(),
        };
        Ok(p)
    }

    /// Parses an HRP string, treating the first data character as a witness version.
    ///
    /// This version byte does not appear in the extracted binary data, but is covered
    /// by the checksum. It can be accessed with [`Self::witness_version`] and is also
    /// returned from this constructor as a convenience.
    pub fn new_with_witness_version(s: &'s str) -> Result<(Self, u8), Error> {
        let mut ret = Self::new(s)?;
        if ret.data_chk.is_empty() {
            return Err(Error::InvalidDataEmpty);
        }

        // Unwrap ok since check_characters (in `Self::new`) checked the bech32-ness of this char.
        let witver = Fe32::from_char(ret.data_chk[0].into()).unwrap().to_u8();

        ret.witness_version = Some(witver);
        ret.data_chk = &ret.data_chk[1..];

        Ok((ret, witver))
    }

    /// Helper function that sanity checks the length of an HRP string for a given checksum algorithm.
    ///
    /// Specifically, check that
    ///     * the data is at least long enough to contain a checksum
    ///     * that the length doesn't imply any "useless characters" where no bits are used
    fn checksum_length_checks<Ck: Checksum>(&self) -> Result<(), Error> {
        if self.data_chk.len() < Ck::CHECKSUM_LENGTH
            || (self.data_chk.len() - Ck::CHECKSUM_LENGTH) * 5 % 8 > 4
        {
            return Err(Error::InvalidChecksumLength);
        }
        Ok(())
    }

    /// Validates that the parsed string has a correct checksum.
    pub fn validate_checksum<Ck: Checksum>(&self) -> Result<(), Error>
    where
        <Ck as Checksum>::MidstateRepr: core::fmt::Display,
    {
        self.checksum_length_checks::<Ck>()?;
        let mut checksum_eng = checksum::Engine::<Ck>::new();
        checksum_eng.input_hrp(&self.hrp());
        if let Some(witver) = self.witness_version {
            checksum_eng.input_fe(Fe32::try_from(witver).map_err(Error::InvalidWitnessVersion)?);
        }
        // Unwrap ok since we checked all characters in our constructor.
        for fe in self.data_chk.iter().map(|&b| Fe32::from_char_unchecked(b)) {
            checksum_eng.input_fe(fe);
        }
        if checksum_eng.residue() == &Ck::TARGET_RESIDUE {
            Ok(())
        } else {
            Err(Error::InvalidChecksum)
        }
    }

    /// Iterate over the data encoded by the HRP string (excluding the HRP, witness
    /// version byte if any, and checksum).
    ///
    /// When constructing the iterator we do some preliminary checks on the length
    /// of the checksummed data, hence the `Result` return type. But **this function
    /// does not validate the checksum**. Before using it, you should first call
    /// [`Self::validate_checksum`].
    ///
    /// This function is generic over the checksum algorithm, but only uses it to
    /// determine the length of the checksum. So for Bitcoin addresses, it is okay
    /// to be sloppy and specify bech32 when bech32m is intended, or vice-versa.
    /// (For [`Self::validate_checksum`], of course, you do need to use the correct
    /// checksum algorithm for the string you're validating.)
    pub fn data_iter<Ck: Checksum>(&self) -> Result<ParsedDataIter<Ck>, Error> {
        self.checksum_length_checks::<Ck>()?;
        Ok(ParsedDataIter {
            iter: FeIter { iter: self.data_chk.iter().copied() }
                .take(self.data_chk.len() - Ck::CHECKSUM_LENGTH)
                .fes_to_bytes(),
            ck: PhantomData,
        })
    }

    /// Returns for the witness version.
    pub fn witness_version(&self) -> Option<u8> { self.witness_version }

    /// Returns the human-readable part (in lowercase without allocation).
    pub fn hrp(&self) -> Hrp {
        self.hrp
    }
}

/// A character iterator over a parsed HRP string.
#[allow(clippy::type_complexity)]
pub struct ParsedDataIter<'s, Ck: Checksum> {
    // We need `Copied` because non of our adaptor iterators use referenced items.
    iter: FeToByteIter<iter::Take<FeIter<iter::Copied<slice::Iter<'s, u8>>>>>,
    ck: PhantomData<Ck>,
}

impl<'s, Ck: Checksum> Iterator for ParsedDataIter<'s, Ck> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> { self.iter.next() }
    fn size_hint(&self) -> (usize, Option<usize>) { self.iter.size_hint() }
}

/// Helper iterator adaptor that maps an iterator of valid bech32 character ASCII bytes to an
/// iterator of field elements.
///
/// This iterator is a performance optimization. Equivalent, but significantly faster than, using
/// `hrp_string.data_chk.iter().copied().map(Fe32::from_char_unchecked)`.
///
/// # Panics
///
/// If any `u8` in the input iterator is out of range for an [`Fe32`]. Should only be used on data
/// that has already been checked for validity (eg, by using `check_characters`).
struct FeIter<I: Iterator<Item = u8>> {
    iter: I,
}

impl<I> Iterator for FeIter<I>
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
    /// The checksum does not match the rest of the data.
    InvalidChecksum,
    /// Attempt conversion of an invalid witness version string/number.
    InvalidWitnessVersion(gf32::Error),
    /// The data payload is empty.
    InvalidDataEmpty,
    /// The checksum is not a valid length.
    InvalidChecksumLength,
    /// Some part of the string contains an invalid character.
    InvalidChar(char),
    /// The bit conversion failed due to a padding issue.
    InvalidPadding,
    /// The whole string must be of one case.
    MixedCase,
}

impl From<hrp::Error> for Error {
    fn from(e: hrp::Error) -> Self { Error::InvalidHrp(e) }
}

impl From<Infallible> for Error {
    fn from(v: Infallible) -> Self { match v {} }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            InvalidHrp(ref e) => write_err!(f, "invalid human-readable part"; e),
            MissingSeparator => write!(f, "missing human-readable separator, \"{}\"", SEP),
            InvalidChecksum => write!(f, "invalid checksum"),
            InvalidWitnessVersion(ref e) => write_err!(f, "witness version error"; e),
            InvalidDataEmpty => write!(f, "invalid data - payload is empty"),
            InvalidChecksumLength => write!(f, "the checksum is not a valid length"),
            InvalidChar(n) => write!(f, "invalid character (code={})", n),
            InvalidPadding => write!(f, "invalid padding"),
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
            | MixedCase
            | InvalidChecksum
            | InvalidDataEmpty
            | InvalidChecksumLength
            | InvalidChar(_)
            | InvalidPadding => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert!(matches!(Parsed::new_with_witness_version(s), Err(expected_error)));
            assert!(matches!(Parsed::new(s), Err(expected_error)));
        }
    }

    #[test]
    #[allow(unused_variables)] // Triggered by matches macro.
    fn bip_173_invalid_hrpstring_because_of_invalid_checksum() {
        let p = Parsed::new("li1dgmt3").expect("invalid checksum still parses");
        assert!(matches!(p.validate_checksum::<crate::Bech32>(), Err(Error::InvalidChecksumLength)))
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
            assert!(matches!(Parsed::new_with_witness_version(s), Err(expected_error)));
            assert!(matches!(Parsed::new(s), Err(expected_error)));
        }
    }

    #[test]
    #[allow(unused_variables)] // Triggered by matches macro.
    fn bip_350_invalid_hrpstring_because_of_invalid_checksum() {
        // Note the "bc1p2" test case is not from the bip test vectors.
        let invalid: Vec<&str> = vec!["in1muywd", "bc1p2"];

        for s in invalid {
            let p = Parsed::new(s).expect("invalid checksum still parses");
            assert!(matches!(
                p.validate_checksum::<crate::Bech32m>(),
                Err(Error::InvalidChecksumLength)
            ))
        }
    }

    #[test]
    fn check_hrp_lowercase() {
        let addr = "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj";
        let parsed = Parsed::new(addr).expect("failed to parse address");
        assert_eq!(parsed.hrp(), Hrp::parse_unchecked("bc"));
    }

    #[test]
    fn check_hrp_uppercase_returns_lower() {
        let addr = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        let parsed = Parsed::new(addr).expect("failed to parse address");
        assert_eq!(parsed.hrp(), Hrp::parse_unchecked("bc"));
    }

    #[test]
    fn check_hrp_max_length() {
        let s = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx";
        let parsed = Parsed::new(s).expect("failed to parse address");
        assert_eq!(
            parsed.hrp(),
            Hrp::parse_unchecked("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio")
        );
    }
}
