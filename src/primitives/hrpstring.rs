// Written by the Andrew Poelstra and the rust-bitcoin developers.
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

use core::convert::Infallible;
use core::iter::FusedIterator;
use core::marker::PhantomData;
use core::str::FromStr;
use core::{fmt, iter, slice, str};

use internals::write_err;
use primitives::witness_version::{self, WitnessVersion};

use crate::primitives::checksum::{self, Checksum};
use crate::primitives::gf32::Fe32;
use crate::primitives::hrp::{self, Hrp, KnownHrp, UnknownHrpError};
use crate::primitives::iter::{Fe32IterExt, FeToByteIter};

/// An HRP string that has been parsed from an ordinary checksummed string.
///
/// Parsing as an HRP string does not validate the checksum in any way.
#[derive(Debug)]
pub struct Parsed<'s> {
    /// The human-readable part.
    hrp: Hrp<'s>,
    /// The witness version, if one exists.
    witness_version: Option<WitnessVersion>,
    /// The data part (including checksum, if any).
    ///
    /// This is ASCII byte values of the parsed string, guaranteed to be valid bech32 characters.
    data_chk: &'s [u8],
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
struct FeIter<I: ExactSizeIterator + FusedIterator + Iterator<Item = u8>> {
    iter: I,
}

impl<I> Iterator for FeIter<I>
where
    I: ExactSizeIterator + FusedIterator + Iterator<Item = u8>,
{
    type Item = Fe32;
    fn next(&mut self) -> Option<Fe32> { self.iter.next().map(Fe32::from_char_unchecked) }
    fn size_hint(&self) -> (usize, Option<usize>) { (self.len(), Some(self.len())) }
}

impl<I> ExactSizeIterator for FeIter<I>
where
    I: ExactSizeIterator + FusedIterator + Iterator<Item = u8>,
{
    fn len(&self) -> usize {
        // Each ASCII byte is a bech32 character i.e., one `Fe32`.
        self.iter.len()
    }
}

impl<I> FusedIterator for FeIter<I> where I: ExactSizeIterator + FusedIterator + Iterator<Item = u8> {}

impl<'s> Parsed<'s> {
    /// Parses an HRP string, without treating the first data character specially.
    pub fn new(s: &'s str) -> Result<Self, Error> {
        let sep_pos = check_characters(s)?;
        let (hrp, data) = s.split_at(sep_pos);
        let hrp = Hrp::parse(hrp)?;

        Ok(Parsed { hrp, witness_version: None, data_chk: data[1..].as_bytes() })
    }

    /// Parses an HRP string, treating the first data character as a witness version.
    ///
    /// This version byte does not appear in the extracted binary data, but is covered
    /// by the checksum. It can be accessed with [`Self::witness_version`] and is also
    /// returned from this constructor as a convenience.
    pub fn new_with_witness_version(s: &'s str) -> Result<(Self, WitnessVersion), Error> {
        let mut ret = Self::new(s)?;
        if ret.data_chk.is_empty() {
            return Err(Error::InvalidDataEmpty);
        }

        // Unwrap ok since check_characters (in `Self::new`) checked the bech32-ness of this char.
        let witver = Fe32::from_char(ret.data_chk[0].into()).unwrap().to_witness_version()?;

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
        checksum_eng.input_hrp(self.hrp());
        if let Some(witver) = self.witness_version {
            checksum_eng.input_fe(Fe32::from_witness_version(witver));
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

    /// Returns the witness version.
    pub fn witness_version(&self) -> Option<WitnessVersion> { self.witness_version }

    /// Returns the human-readable part.
    pub fn hrp(&'s self) -> Hrp<'s> { self.hrp }

    /// Attempts to create a [`KnownHrp`] from the inner HRP string.
    ///
    /// # Errors
    ///
    /// If this is not a known segwit HRP e.g., "bc".
    pub fn segwit_known_hrp(&self) -> Result<KnownHrp, UnknownHrpError> {
        KnownHrp::from_str(self.hrp.as_str())
    }
}

/// A character iterator over a parsed HRP string.
#[allow(clippy::type_complexity)] // FIXME: Should we remove this and use type aliases?
pub struct ParsedDataIter<'s, Ck: Checksum> {
    iter: FeToByteIter<iter::Take<FeIter<iter::Copied<slice::Iter<'s, u8>>>>>,
    ck: PhantomData<Ck>,
}

impl<'s, Ck: Checksum> Iterator for ParsedDataIter<'s, Ck> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> { self.iter.next() }

    fn size_hint(&self) -> (usize, Option<usize>) { (self.len(), Some(self.len())) }
}

impl<'s, Ck: Checksum> ExactSizeIterator for ParsedDataIter<'s, Ck> {
    fn len(&self) -> usize { self.iter.len() }
}

impl<'s, Ck: Checksum> FusedIterator for ParsedDataIter<'s, Ck> {}

/// Separator between the hrp and payload (as defined by BIP-173).
const SEP: char = '1';

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
            Fe32::from_char(ch).map_err(|_| Error::InvalidBech32Char(ch))?;
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
    /// The data payload is empty.
    InvalidDataEmpty,
    /// The checksum is not a valid length.
    InvalidChecksumLength,
    /// Attempt conversion of an invalid witness version string/number.
    InvalidWitnessVersion(witness_version::ConversionError),
    /// Some part of the string contains a character that is not a valid bech32 character.
    InvalidBech32Char(char),
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

impl From<witness_version::ConversionError> for Error {
    fn from(e: witness_version::ConversionError) -> Self { Error::InvalidWitnessVersion(e) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            InvalidHrp(ref e) => write_err!(f, "invalid human-readable part"; e),
            MissingSeparator => write!(f, "missing human-readable separator, \"{}\"", SEP),
            InvalidChecksum => write!(f, "invalid checksum"),
            InvalidDataEmpty => write!(f, "invalid data - payload is empty"),
            InvalidChecksumLength => write!(f, "the checksum is not a valid length"),
            InvalidBech32Char(n) => write!(f, "invalid bech32 character (code={})", n),
            InvalidPadding => write!(f, "invalid padding"),
            InvalidWitnessVersion(ref e) => write_err!(f, "witness version error"; e),
            MixedCase => write!(f, "mixed-case strings not allowed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            InvalidWitnessVersion(ref e) => Some(e),
            InvalidHrp(ref e) => Some(e),
            MissingSeparator
            | MixedCase
            | InvalidChecksum
            | InvalidDataEmpty
            | InvalidChecksumLength
            | InvalidBech32Char(_)
            | InvalidPadding => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;
    use crate::primitives::hrp::KnownHrp;

    #[test]
    fn try_from_err() {
        assert!(Fe32::try_from(32_u8).is_err());
        assert!(Fe32::try_from(32_u16).is_err());
        assert!(Fe32::try_from(32_u32).is_err());
        assert!(Fe32::try_from(32_u64).is_err());
        assert!(Fe32::try_from(32_u128).is_err());
    }

    #[test]
    fn check_hrp_lowercase() {
        let addr = "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj";
        let parsed = Parsed::new(addr).expect("failed to parse address");
        assert_eq!(parsed.hrp(), KnownHrp::Bitcoin.into());
    }

    #[test]
    fn check_hrp_uppercase_returns_lower() {
        let addr = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        let parsed = Parsed::new(addr).expect("failed to parse address");
        assert_eq!(parsed.hrp(), Hrp::parse("BC").expect("BC is valid"));
    }

    #[test]
    fn check_hrp_max_length() {
        let s = "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx";
        let parsed = Parsed::new(s).expect("failed to parse address");
        assert_eq!(
            parsed.hrp(),
            Hrp::parse("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio").expect("valid hrp"),
        );
    }
}
