// Written by Clark Moody and the rust-bitcoin developers.
// SPDX-License-Identifier: MIT

//! Provides an `Hrp` type that represents the human-readable part of a bech32 encoded string.
//!
//! > The human-readable part, which is intended to convey the type of data, or anything else that
//! > is relevant to the reader. This part MUST contain 1 to 83 US-ASCII characters, with each
//! > character having a value in the range [33-126]. HRP validity may be further restricted by
//! > specific applications.
//!
//! ref: [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#user-content-Bech32)

#[cfg(feature = "alloc")]
use alloc::borrow::Cow;
#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
use core::fmt;
use core::iter::FusedIterator;
use core::str::FromStr;

/// Maximum length of the human-readable part, as defined by BIP-173.
const MAX_HRP_LEN: usize = 83;

/// The human-readable part (human readable prefix before the '1' separator).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hrp<'a> {
    /// Lowercase human-readable part.
    Lower(&'a str),
    /// Uppercase human-readable part.
    Upper(&'a str),
    /// All digit human-readable part.
    Digit(&'a str),
}

impl<'s> Hrp<'s> {
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
    /// # Returns
    ///
    /// A copy-on-write string of the lowercase HRP if `hrp` is valid, `None` otherwise.
    ///
    /// [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
    pub fn parse(hrp: &'s str) -> Result<Self, Error> {
        use Error::*;

        if hrp.is_empty() {
            return Err(Empty);
        }
        if hrp.len() > MAX_HRP_LEN {
            return Err(TooLong(hrp.len()));
        }

        let mut has_lower: bool = false;
        let mut has_upper: bool = false;
        for b in hrp.bytes() {
            // Valid subset of ASCII
            if !(33..=126).contains(&b) {
                return Err(InvalidAsciiByte(b));
            }

            if b.is_ascii_lowercase() {
                has_lower = true;
            } else if b.is_ascii_uppercase() {
                has_upper = true;
            };

            if has_lower && has_upper {
                return Err(MixedCase);
            }
        }

        if has_lower {
            return Ok(Hrp::Lower(hrp));
        }

        if has_upper {
            return Ok(Hrp::Upper(hrp));
        }

        Ok(Hrp::Digit(hrp))
    }

    /// Returns the human-readable part as a lowercase string.
    #[cfg(feature = "alloc")]
    pub fn to_lower(&self) -> Cow<str> {
        match self {
            Self::Upper(upper) => Cow::Owned(upper.to_lowercase()),
            Self::Lower(lower) => Cow::Borrowed(lower),
            Self::Digit(digits) => Cow::Borrowed(digits),
        }
    }

    /// Creates a lowercase iterator over the bytes (ASCII characters) of this HRP.
    pub fn iter(&self) -> LowercaseIter<'s> {
        let s = match self {
            Self::Upper(s) => s,
            Self::Lower(s) => s,
            Self::Digit(s) => s,
        };
        let iter = s.bytes();
        LowercaseIter { iter }
    }

    /// Returns a reference to the inner human-readable part.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Upper(s) => s,
            Self::Lower(s) => s,
            Self::Digit(s) => s,
        }
    }

    /// Returns the length (number of characters) of the human-readable part.
    ///
    /// Guaranteed to be between 1 and 83 inclusive.
    pub fn len(&self) -> usize {
        let s = match self {
            Self::Upper(s) => s,
            Self::Lower(s) => s,
            Self::Digit(s) => s,
        };
        s.len()
    }

    /// The human-readable part is guaranteed to be between 1-83 characters.
    pub fn is_empty(&self) -> bool { false }
}

/// Iterator over the human-readable part, as lowercase ASCII values.
pub struct LowercaseIter<'s> {
    iter: core::str::Bytes<'s>,
}

impl<'s> Iterator for LowercaseIter<'s> {
    type Item = u8;
    fn next(&mut self) -> Option<u8> { self.iter.next().map(|c| c | 32) }

    fn size_hint(&self) -> (usize, Option<usize>) { (self.len(), Some(self.len())) }
}

impl<'s> ExactSizeIterator for LowercaseIter<'s> {
    fn len(&self) -> usize { self.iter.len() }
}

impl<'s> FusedIterator for LowercaseIter<'s> {}

/// A type used to get the current know HRPs as specified in [BIP-173].
///
/// Please note this does not include signet because testnet and signet use the same HRP ("tb").
///
/// [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
#[derive(Copy, PartialEq, Eq, Clone, Hash, Debug)]
#[non_exhaustive]
pub enum KnownHrp {
    /// Mainnet Bitcoin - "bc".
    Bitcoin,
    /// Bitcoin's testnet network - "tb".
    Testnet,
    /// Bitcoin's regtest network - "bcrt".
    Regtest,
}

/// Parses a [`KnownHrp`] from a string.
///
/// Bitcoin currently uses "bc", "tb", and "bcrt" as HRP for mainnet, testnet/signet, and
/// regtest respectively.
///
/// # Examples
///
/// ```
/// # use core::str::FromStr;
/// # use bech32::primitives::hrp::KnownHrp;
/// assert!(KnownHrp::from_str("randomvalidhrp").is_err());
/// assert_eq!(KnownHrp::from_str("bc").expect("bc is valid"), KnownHrp::Bitcoin);
/// assert_eq!(KnownHrp::from_str("TB").expect("uppercase is valid also"), KnownHrp::Testnet);
/// ```
impl FromStr for KnownHrp {
    type Err = UnknownHrpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use KnownHrp::*;

        match s {
            "bc" | "BC" => Ok(Bitcoin),
            "tb" | "TB" => Ok(Testnet),
            "bcrt" | "BCRT" => Ok(Regtest),
            #[cfg(feature = "alloc")]
            _ => Err(UnknownHrpError { not_segwit: s.to_string() }),
            #[cfg(not(feature = "alloc"))]
            _ => Err(UnknownHrpError {}),
        }
    }
}

/// Error if string is not a known segwit HRP.
#[derive(Debug)]
pub struct UnknownHrpError {
    #[cfg(feature = "alloc")]
    not_segwit: String,
}

impl fmt::Display for UnknownHrpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "alloc")]
        return write!(f, "{} is not a known segwit HRP", self.not_segwit);
        #[cfg(not(feature = "alloc"))]
        return write!(f, "encountered an unknown segwit HRP");
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnknownHrpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Creates an [`Hrp`] from a [`KnownHrp`]
///
/// # Examples
///
/// ```
/// # use bech32::primitives::hrp::{Hrp, KnownHrp};
/// assert_eq!(Hrp::parse("bc").expect("bc is valid"), Hrp::from(KnownHrp::Bitcoin))
/// ```
///
/// [segwit address format]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#user-content-Segwit_address_format>
impl From<KnownHrp> for Hrp<'static> {
    fn from(hrp: KnownHrp) -> Self {
        use KnownHrp::*;

        match hrp {
            Bitcoin => Self::Lower("bc"),
            Testnet => Self::Lower("tb"),
            Regtest => Self::Lower("bcrt"),
        }
    }
}

/// Errors encountered while checking the human-readable part as defined by [BIP-173].
/// [BIP-173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#user-content-Bech32>
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The human-readable part is too long.
    TooLong(usize),
    /// The human-readable part is empty.
    Empty,
    /// Invalid byte (not within acceptable US-ASCII range).
    InvalidAsciiByte(u8),
    /// The human-readable part cannot mix upper and lower case.
    MixedCase,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            TooLong(len) => write!(f, "hrp is too long, found {} characters, must be <= 126", len),
            Empty => write!(f, "hrp is empty, must have at least 1 character"),
            InvalidAsciiByte(b) => write!(f, "character is not valid US-ASCII: \'{:x}\'", b),
            MixedCase => write!(f, "hrp cannot mix upper and lower case"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            TooLong(_) | Empty | InvalidAsciiByte(_) | MixedCase => None,
        }
    }
}
