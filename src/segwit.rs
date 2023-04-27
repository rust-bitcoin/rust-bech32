// Written by the rust-bitcoin developers.
// SPDX-License-Identifier: MIT

//! Encoding and decoding of addresses for segregated witness outputs.
//!
//! A segwit address is a restricted form of bech32 defined in [BIP-173] and [BIP-350].
//!
//! The API supports both the original [BIP-173] segwit address format (using the bech32 checksum
//! algorithm) as well as the more recent [BIP-350] segwit address format (using the bech32m
//! checksum algorithm). As such, encoding/decoding witness version 0 defaults to using the bech32
//! checksum algorithm while encoding/decoding witness version 1 or greater defaults to using the
//! bech32m checksum algorithm. We also provide the ability to encode witness version 1 and greater
//! using bech32 if for some reason you need it (see [`encode_force_bech32`]).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "alloc")] {
//! use bech32::segwit::{KnownHrp, WitnessVersion};
//!
//! // Works for segwit version 0 addresses.
//! let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
//! let (hrp, witness_version, data) = bech32::segwit::decode(addr).expect("valid address");
//! assert_eq!(hrp, KnownHrp::Bitcoin);
//! assert_eq!(witness_version, WitnessVersion::V0);
//! assert_eq!(bech32::segwit::encode(hrp, witness_version, &data), addr);
//!
//! // Works for taproot (segwit version 1) addresses.
//! let addr = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y";
//! let (hrp, witness_version, data) = bech32::segwit::decode(addr).expect("valid address");
//! assert_eq!(hrp, KnownHrp::Bitcoin);
//! assert_eq!(witness_version, WitnessVersion::V1);
//! assert_eq!(bech32::segwit::encode(hrp, witness_version, &data), addr);
//! # }
//! ```
//!
//! [BIP-0173]: <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki>
//! [BIP-0350]: <https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki>

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{string::String, vec::Vec};
use core::convert::Infallible;
use core::fmt;

use internals::write_err;
pub use primitives::witness_version::WitnessVersion;

use crate::primitives::checksum::{Checksum, PackedNull};
#[cfg(feature = "alloc")]
use crate::primitives::hrp::Hrp;
pub use crate::primitives::hrp::KnownHrp;
#[cfg(feature = "alloc")]
use crate::primitives::hrpstring::Parsed;
use crate::primitives::{hrp, hrpstring};

/// Verifies a Bitcoin address.
///
/// Checking that the input string:
/// * Has a valid checksum implied by the witness version (see below)
/// * Has a valid human-readable part.
/// * Has a valid witness program length.
///
/// # Errors
///
/// Returns an error if the input string cannot be parsed or the checksum is invalid.
///
/// # Examples
///
/// ```
/// // Works for segwit version 0 addresses.
/// let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
/// assert!(bech32::segwit::verify(addr).is_ok());
///
/// // Works for segwit version 1 (taproot) addresses.
/// let addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
/// assert!(bech32::segwit::verify(addr).is_ok());
/// ```
pub fn verify(s: &str) -> Result<(), Error> {
    let (hrp_string, witver) = hrpstring::Parsed::new_with_witness_version(s)?;

    let _ = hrp_string.segwit_known_hrp()?;

    match witver {
        WitnessVersion::V0 => hrp_string.validate_checksum::<Bech32>()?,
        _ => {
            // Check bech32m first because its the most likely case.
            match hrp_string.validate_checksum::<Bech32m>() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // Higher witver are still allowed to be checksummed with bech32 though.
                    match hrp_string.validate_checksum::<Bech32>() {
                        Ok(()) => return Ok(()),
                        Err(_) => return Err(e.into()), // Return the error from parsing bech32m.
                    }
                }
            }
        }
    };

    Ok(())
}

/// Verifies a Bitcoin address has a valid bech32 checksum.
///
/// BIP-173: "implementations MUST allow the use of any version".
///
/// # Errors
///
/// Returns an error if the input string cannot be parsed or the checksum is invalid.
///
/// # Examples
///
/// ```
/// // Note this valid address uses witness version 1.
/// let addr = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx";
/// assert!(bech32::segwit::verify_bech32(addr).is_ok());
/// ```
pub fn verify_bech32(s: &str) -> Result<(), Error> {
    let (hrp_string, _) = hrpstring::Parsed::new_with_witness_version(s)?;
    hrp_string.validate_checksum::<Bech32>()?;

    Ok(())
}

/// Verifies a Bitcoin address has a valid bech32m checksum.
///
/// # Errors
///
/// If input string has a witness version of 0, as specified by BIP-350.
///
/// # Examples
///
/// ```
/// let addr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
/// assert!(bech32::segwit::verify(addr).is_ok());
/// ```
pub fn verify_bech32m(s: &str) -> Result<(), Error> {
    let (hrp_string, witver) = hrpstring::Parsed::new_with_witness_version(s)?;
    hrp_string.validate_checksum::<Bech32m>()?;

    if witver == WitnessVersion::V0 {
        return Err(Error::InvalidWitnessVersion);
    }

    Ok(())
}

/// Decodes a Bitcoin address using the witness version byte to imply the checksum algorithm.
///
/// This is the inverse function of [`encode`].
///
/// From [BIP-350]:
///
/// > To decode an address, client software should either decode with both a Bech32 and a Bech32m
/// > decoder, or use a decoder that supports both simultaneously. In both cases, the address
/// > decoder has to verify that the encoding matches what is expected for the decoded witness
/// > version (Bech32 for version 0, Bech32m for others).
///
/// # Returns
///
/// The HRP, the witness version number, and the decoded payload data. Note that the witness version
/// number is _not_ present in the data vector.
///
/// # Examples
///
/// ```
/// use bech32::segwit::{KnownHrp, WitnessVersion};
///
/// // Works for segwit version 0 addresses.
/// let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
/// let (hrp, witness_version, data) = bech32::segwit::decode(addr).expect("valid address");
///
/// assert_eq!(hrp, KnownHrp::Bitcoin);
/// assert_eq!(witness_version, WitnessVersion::V0);
/// assert_eq!(bech32::segwit::encode(hrp, witness_version, &data), addr);
///
/// // Works for segwit version 1 (taproot) addresses.
/// let addr = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y";
/// let (hrp, witness_version, data) = bech32::segwit::decode(addr).expect("valid address");
///
/// assert_eq!(hrp, KnownHrp::Bitcoin);
/// assert_eq!(witness_version, WitnessVersion::V1);
/// assert_eq!(bech32::segwit::encode(hrp, witness_version, &data), addr);
/// ```
///
/// [BIP-0350]: <https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#user-content-Bech32m>
#[cfg(feature = "alloc")]
pub fn decode(addr: &str) -> Result<(KnownHrp, WitnessVersion, Vec<u8>), Error> {
    let (hrp_string, witver) = hrpstring::Parsed::new_with_witness_version(addr)?;

    match witver {
        WitnessVersion::V0 => _decode_bech32(&hrp_string),
        _ => _decode_bech32m(&hrp_string),
    }
}

/// Decodes a Bitcoin address that contains a bech32 checksum.
///
/// This is the inverse function of [`encode_force_bech32`].
///
/// # Returns
///
/// The HRP, the witness version number, and the decoded payload data. Note that the witness version
/// number is _not_ present in the data vector.
///
/// # Examples
///
/// ```
/// use bech32::segwit::{WitnessVersion, KnownHrp};
///
/// let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
/// let (hrp, witness_version, data) = bech32::segwit::decode_bech32(addr).expect("valid address");
///
/// assert_eq!(hrp, KnownHrp::Bitcoin);
/// assert_eq!(witness_version, WitnessVersion::V0);
/// assert_eq!(bech32::segwit::encode_force_bech32(hrp, witness_version, &data), addr);
/// ```
#[cfg(feature = "alloc")]
pub fn decode_bech32(addr: &str) -> Result<(KnownHrp, WitnessVersion, Vec<u8>), Error> {
    let (hrp_string, _witver) = hrpstring::Parsed::new_with_witness_version(addr)?;
    _decode_bech32(&hrp_string)
}

/// `hrp_string` expected to have been created by call to `Parsed::new_with_witness_version`.
#[cfg(feature = "alloc")]
fn _decode_bech32(hrp_string: &Parsed) -> Result<(KnownHrp, WitnessVersion, Vec<u8>), Error> {
    // Note we do not check the witness version number here explicitly, it is checked implicitly by
    // the type system. Also, in accord with BIP-173, decoding bech32 allows use of any witness
    // version number 0..=16
    let witver =
        hrp_string.witness_version().expect("new_with_witness_version always includes witver");

    let hrp = hrp_string.segwit_known_hrp()?;

    hrp_string.validate_checksum::<Bech32>()?;
    let data = hrp_string.data_iter::<Bech32>()?.collect::<Vec<u8>>();

    if !is_valid_witness_program_length(witver, data.len()) {
        return Err(Error::InvalidProgramLength);
    }

    Ok((hrp, witver, data))
}

/// Decodes a Bitcoin address that contains a bech32 checksum.
///
/// This is the inverse function of [`encode_force_bech32m`].
///
/// BIP-350: "Addresses for segregated witness outputs version 1 through 16 use Bech32m."
///
/// # Returns
///
/// The HRP, the witness version number, and the decoded payload data. Note that the witness version
/// number is _not_ present in the data vector.
///
/// # Errors
///
/// If input string has a witness version of 0, this is in accord with the BIP-350 test vectors.
///
/// # Examples
///
/// ```
/// use bech32::segwit::{KnownHrp, WitnessVersion};
///
/// let addr = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y";
/// let (hrp, witness_version, data) = bech32::segwit::decode_bech32m(addr).expect("valid address");
///
/// assert_eq!(hrp, KnownHrp::Bitcoin);
/// assert_eq!(witness_version, WitnessVersion::V1);
/// assert_eq!(bech32::segwit::encode_force_bech32m(hrp, witness_version, &data), addr);
/// ```
#[cfg(feature = "alloc")]
pub fn decode_bech32m(addr: &str) -> Result<(KnownHrp, WitnessVersion, Vec<u8>), Error> {
    let (hrp_string, _witver) = hrpstring::Parsed::new_with_witness_version(addr)?;
    _decode_bech32m(&hrp_string)
}

/// `hrp_string` expected to have been created by call to `Parsed::new_with_witness_version`.
#[cfg(feature = "alloc")]
fn _decode_bech32m(hrp_string: &Parsed) -> Result<(KnownHrp, WitnessVersion, Vec<u8>), Error> {
    let witver =
        hrp_string.witness_version().expect("new_with_witness_version always includes witver");

    let hrp = hrp_string.segwit_known_hrp()?;

    hrp_string.validate_checksum::<Bech32m>()?;
    let data = hrp_string.data_iter::<Bech32m>()?.collect::<Vec<u8>>();

    if witver == WitnessVersion::V0 {
        return Err(Error::InvalidWitnessVersion);
    }

    if !is_valid_witness_program_length(witver, data.len()) {
        return Err(Error::InvalidProgramLength);
    }

    Ok((hrp, witver, data))
}

/// Encodes a bitcoin address using the witness version to imply the checksum algorithm.
///
/// This is the inverse function of [`decode`]. Uses lowercase characters as specified in BIP-173.
///
/// From [BIP-350]:
///
/// > To generate an address for a segregated witness output:
/// >
/// > * If its witness version is 0, encode it using Bech32.
/// > * If its witness version is 1 or higher, encode it using Bech32m.
///
/// If you want to encode an address with witness version 0 using the bech32m checksum algorithm use
/// [`encode_force_bech32m`].
///
/// # Examples
///
/// ```
/// # use bech32::segwit::{KnownHrp, WitnessVersion};
/// # let addr = "bc1qadx88l6juc3lhuz3dvw7frmxujxzv0ralj2y20yq6gurguqyyxxsfq5jv3";
/// # let (_hrp, _witness_version, data) = bech32::segwit::decode_bech32(addr).expect("valid address");
///
/// let hrp = KnownHrp::Bitcoin;
/// let witness_version = WitnessVersion::V0;
/// // let data = <the address data to be encoded>;
/// let addr = bech32::segwit::encode(hrp, witness_version, &data);
/// assert!(matches!(bech32::segwit::decode(&addr), Ok((hrp, witness_version, data))));
/// ```
///
/// [BIP-0350]: <https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#user-content-Bech32m>
#[cfg(feature = "alloc")]
pub fn encode(hrp: KnownHrp, witness_version: WitnessVersion, data: &[u8]) -> String {
    if witness_version == WitnessVersion::V0 {
        encode_force_bech32(hrp, witness_version, data)
    } else {
        encode_force_bech32m(hrp, witness_version, data)
    }
}

/// Encodes a bitcoin address using the bech32 checksum algorithm _irrespective_ of the witness
/// version.
///
/// Encodes using lowercase characters as specified in BIP-173.
///
/// Please note, according to BIP-350:
///
/// > Addresses for segregated witness outputs version 1 through 16 use Bech32m
///
/// While encoding higher witness versions using bech32 is valid you probably want to use
/// [`encode`] which uses the correct checksum algorithm based on `witness_version`.
///
/// **Only use this function if you know what you are doing.**
#[cfg(feature = "alloc")]
pub fn encode_force_bech32(hrp: KnownHrp, witness_version: WitnessVersion, data: &[u8]) -> String {
    use crate::primitives::iter::{ByteIterExt, Fe32IterExt};

    let hrp = Hrp::from(hrp);

    data.iter()
        .copied() // iterate over bytes
        .bytes_to_fes() // convert bytes to field elements in-line
        .with_witness_version(witness_version)
        .checksum::<Bech32>()
        .with_checksummed_hrp(hrp)
        .hrp_char(hrp)
        .collect()
}

/// Encodes a bitcoin address using the bech32m checksum algorithm.
///
/// Encodes using lowercase characters as specified in BIP-173.
///
/// Please note, according to BIP-350:
///
/// > Version 0 outputs (specifically, P2WPKH and P2WSH addresses) continue to use Bech32 as
/// > specified in BIP173. Addresses for segregated witness outputs version 1 through 16 use Bech32m.
///
/// While encoding witness version 0 using bech32m is valid you probably want to use
/// [`encode`] which uses the correct checksum algorithm based on `witness_version`.
///
/// **Only use this function if you know what you are doing.**
#[cfg(feature = "alloc")]
pub fn encode_force_bech32m(hrp: KnownHrp, witness_version: WitnessVersion, data: &[u8]) -> String {
    use crate::primitives::iter::{ByteIterExt, Fe32IterExt};

    let hrp = Hrp::from(hrp);

    data.iter()
        .copied() // iterate over bytes
        .bytes_to_fes() // convert bytes to field elements in-line
        .with_witness_version(witness_version)
        .checksum::<Bech32m>()
        .with_checksummed_hrp(hrp)
        .hrp_char(hrp)
        .collect()
}

/// True if program length is either 20 bytes (p2wpkh) or 32 bytes (p2wsh).
/// ref: [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#user-content-Witness_program)
#[cfg(feature = "alloc")]
fn is_valid_witness_program_length(version: WitnessVersion, len: usize) -> bool {
    match version {
        WitnessVersion::V0 => len == 20 || len == 32,
        _ => (2..=40).contains(&len),
    }
}

/// The "null checksum" used on bech32 strings for which we want to do no checksum checking
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NoChecksum {}

/// The bech32 checksum algorithm, defined in BIP-173.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bech32 {}

/// The bech32m checksum algorithm, defined in BIP-350.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bech32m {}

impl Checksum for NoChecksum {
    type MidstateRepr = PackedNull;
    const CHECKSUM_LENGTH: usize = 0;
    const GENERATOR_SH: [PackedNull; 5] = [PackedNull; 5];
    const TARGET_RESIDUE: PackedNull = PackedNull;
}

// Bech32[m] generator coefficients, copied from Bitcoin Core src/bech32.cpp
const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];

impl Checksum for Bech32 {
    type MidstateRepr = u32;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = GEN;
    const TARGET_RESIDUE: u32 = 1;
}
// Same as Bech32 except TARGET_RESIDUE is different
impl Checksum for Bech32m {
    type MidstateRepr = u32;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = GEN;
    const TARGET_RESIDUE: u32 = 0x2bc830a3;
}

/// Error types for Bech32 encoding / decoding.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Encountered an invalid hrpstring.
    InvalidHrpstring(hrpstring::Error),
    /// Unknown HRP for a segwit address.
    UnknownHrp(hrp::UnknownHrpError),
    /// Encountered an invalid human-readable part (as per BIP-173).
    #[cfg(feature = "alloc")]
    InvalidSegwitHrp(String),
    /// Encountered an invalid human-readable part (as per BIP-173).
    #[cfg(not(feature = "alloc"))]
    InvalidSegwitHrp,
    /// Witness version is out of the range [0, 16] inclusive
    InvalidWitnessVersion,
    /// Invalid witness program length.
    InvalidProgramLength,
}

impl From<Infallible> for Error {
    fn from(v: Infallible) -> Self { match v {} }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            UnknownHrp(ref e) => write_err!(f, "unknown segwit hrp"; e),
            InvalidHrpstring(ref e) => write_err!(f, "invalid hrpstring"; e),
            #[cfg(feature = "alloc")]
            InvalidSegwitHrp(ref s) =>
                write!(f, "human-readable part is not a valid segwit hrp: {}", s),
            #[cfg(not(feature = "alloc"))]
            InvalidSegwitHrp => write!(f, "human-readable part is not a valid segwit hrp"),
            InvalidWitnessVersion => write!(f, "invalid witness version"),
            InvalidProgramLength => write!(f, "invalid witness program length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            UnknownHrp(ref e) => Some(e),
            InvalidHrpstring(ref e) => Some(e),
            InvalidWitnessVersion | InvalidSegwitHrp(_) | InvalidProgramLength => None,
        }
    }
}

impl From<hrpstring::Error> for Error {
    fn from(e: hrpstring::Error) -> Self { Error::InvalidHrpstring(e) }
}

impl From<hrp::UnknownHrpError> for Error {
    fn from(e: hrp::UnknownHrpError) -> Self { Error::UnknownHrp(e) }
}

/// Error return when `TryFrom<T>` fails for `T` -> `Fe32` conversion.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum TryFromIntError {
    /// Attempted to convert a negative value to a `Fe32`.
    NegOverflow,
    /// Attempted to convert a value which overflows a `Fe32`.
    PosOverflow,
}

impl fmt::Display for TryFromIntError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TryFromIntError::*;

        match *self {
            NegOverflow => write!(f, "attempted to convert a negative value to a Fe32"),
            PosOverflow => write!(f, "attempted to convert a value which overflows a Fe32"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::checksum::Checksum;
    #[cfg(feature = "alloc")]
    use crate::segwit::NoChecksum;

    #[cfg(feature = "alloc")]
    fn roundtrip_checksum<Ck: Checksum>() {
        use crate::primitives::iter::{ByteIterExt, Fe32IterExt};

        let hrp = Hrp::from(KnownHrp::Testnet);
        let data = b"Hello World!";

        let ckstring = data
            .iter()
            .copied() // iterate over bytes
            .bytes_to_fes() // convert bytes to field elements in-line
            .checksum::<Ck>()
            .with_checksummed_hrp(hrp)
            .hrp_char(hrp)
            .collect::<String>();

        let decoded = hrpstring::Parsed::new(&ckstring).expect("failed to parse hrp string");
        let mut dec_iter = decoded.data_iter::<Ck>().expect("failed to create data iterator");
        let dec_data = dec_iter.by_ref().collect::<Vec<_>>();

        assert_eq!(decoded.hrp(), hrp);
        assert_eq!(dec_data, data);
        for _ in 0..100 {
            assert!(dec_iter.next().is_none());
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn roundtrip() {
        roundtrip_checksum::<NoChecksum>();
        roundtrip_checksum::<Bech32>();
        roundtrip_checksum::<Bech32m>();
    }

    #[test]
    fn bech32_sanity() { Bech32::sanity_check(); }

    #[test]
    fn bech32m_sanity() { Bech32m::sanity_check(); }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    #[bench]
    fn bech32_parse_address(bh: &mut Bencher) {
        let addr = black_box("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");

        bh.iter(|| {
            let tuple = crate::bitcoin_decode(&addr).expect("address is well formed");
            black_box(&tuple);
        })
    }

    #[bench]
    fn bech32_validate(bh: &mut Bencher) {
        let addr = black_box("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");

        bh.iter(|| {
            let tuple = crate::verify(&addr).expect("address is well formed");
            black_box(&tuple);
        })
    }

    #[bench]
    fn bech32m_parse_address(bh: &mut Bencher) {
        let addr = black_box("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297");

        bh.iter(|| {
            let tuple = crate::bitcoin_decode(&addr).expect("address is well formed");
            black_box(&tuple);
        })
    }

    // Encode with allocation.
    #[bench]
    fn encode_bech32_address(bh: &mut Bencher) {
        let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let (hrp, witver, data) = crate::bitcoin_decode(&addr).expect("address is well formed");

        bh.iter(|| {
            let s = crate::bitcoin_encode(&hrp, witver, &data).expect("failed to encode");
            black_box(&s);
        });
    }

    // Encode with allocation.
    #[bench]
    fn encode_bech32m_address(bh: &mut Bencher) {
        let addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        let (hrp, witver, data) = crate::bitcoin_decode(&addr).expect("address is well formed");

        bh.iter(|| {
            let s = crate::bitcoin_encode(&hrp, witver, &data).expect("failed to encode");
            black_box(&s);
        });
    }
}
