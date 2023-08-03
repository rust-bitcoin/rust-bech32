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
use core::{fmt, mem};

pub use crate::primitives::checksum::Checksum;
use crate::primitives::checksum::{self, PackedFe32};
pub use crate::primitives::gf32::Fe32;
use crate::primitives::hrp;
pub use crate::primitives::hrp::Hrp;
pub use crate::primitives::iter::{ByteIterExt, Fe32IterExt};
pub use crate::primitives::{Bech32, Bech32m};

mod error;
pub mod primitives;
pub mod segwit;

#[cfg(feature = "arrayvec")]
use arrayvec::{ArrayVec, CapacityError};
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

const CHECKSUM_LENGTH: usize = 6;

/// Allocationless Bech32 writer that accumulates the checksum data internally and writes them out
/// in the end.
pub struct Bech32Writer<'a, Ck: Checksum> {
    formatter: &'a mut dyn fmt::Write,
    engine: checksum::Engine<Ck>,
}

impl<'a, Ck: Checksum> Bech32Writer<'a, Ck> {
    /// Creates a new writer that can write a bech32 string without allocating itself.
    ///
    /// This is a rather low-level API and doesn't check the HRP or data length for standard
    /// compliance.
    fn new(hrp: Hrp, fmt: &'a mut dyn fmt::Write) -> Result<Bech32Writer<'a, Ck>, fmt::Error> {
        let mut engine = checksum::Engine::new();
        engine.input_hrp(&hrp);

        for c in hrp.lowercase_char_iter() {
            fmt.write_char(c)?;
        }
        fmt.write_char(SEP)?;

        Ok(Bech32Writer { formatter: fmt, engine })
    }

    /// Writes out the checksum at the end.
    ///
    /// If this method isn't explicitly called this will happen on drop.
    pub fn finalize(mut self) -> fmt::Result {
        self.write_checksum()?;
        mem::forget(self);
        Ok(())
    }

    /// Calculates and writes a checksum to `self`.
    fn write_checksum(&mut self) -> fmt::Result {
        self.engine.input_target_residue();

        let mut checksum_remaining = self::CHECKSUM_LENGTH;
        while checksum_remaining > 0 {
            checksum_remaining -= 1;

            let fe = u5::try_from(self.engine.residue().unpack(checksum_remaining))
                .expect("unpack returns valid field element");
            self.formatter.write_char(fe.to_char())?;
        }

        Ok(())
    }
}

impl<'a, Ck: Checksum> WriteBase32 for Bech32Writer<'a, Ck> {
    type Error = fmt::Error;

    fn write_u5(&mut self, data: u5) -> fmt::Result {
        self.engine.input_fe(data);
        self.formatter.write_char(data.to_char())
    }
}

impl<'a, Ck: Checksum> Drop for Bech32Writer<'a, Ck> {
    fn drop(&mut self) {
        self.write_checksum().expect("Unhandled error writing the checksum on drop.")
    }
}

/// Parses/converts base32 slice to `Self`.
///
/// This trait is the reciprocal of `ToBase32`.
pub trait FromBase32: Sized {
    /// The associated error which can be returned from parsing (e.g. because of bad padding).
    type Error;

    /// Converts a base32 slice to `Self`.
    fn from_base32(b32: &[u5]) -> Result<Self, Self::Error>;
}

macro_rules! write_base_n {
    { $tr:ident, $ty:ident, $meth:ident } => {
        #[cfg(feature = "arrayvec")]
        impl<const L: usize> $tr for ArrayVec<$ty, L> {
            type Error = CapacityError;

            fn write(&mut self, data: &[$ty]) -> Result<(), Self::Error> {
                self.try_extend_from_slice(data)?;
                Ok(())
            }

            fn $meth(&mut self, data: $ty) -> Result<(), Self::Error> {
                self.push(data);
                Ok(())
            }
        }

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

#[cfg(feature = "arrayvec")]
#[derive(Clone, Debug, PartialEq, Eq)]
/// Combination of Errors for use with array vec
pub enum ComboError {
    /// Error from this crate
    Bech32Error(Error),
    /// Error from `arrayvec`.
    WriteError(CapacityError),
}
#[cfg(feature = "arrayvec")]
impl From<Error> for ComboError {
    fn from(e: Error) -> ComboError { ComboError::Bech32Error(e) }
}
#[cfg(feature = "arrayvec")]
impl From<CapacityError> for ComboError {
    fn from(e: CapacityError) -> ComboError { ComboError::WriteError(e) }
}
#[cfg(feature = "arrayvec")]
impl From<hrp::Error> for ComboError {
    fn from(e: hrp::Error) -> ComboError { ComboError::Bech32Error(Error::Hrp(e)) }
}

#[cfg(feature = "arrayvec")]
impl<const L: usize> FromBase32 for ArrayVec<u8, L> {
    type Error = ComboError;

    /// Convert base32 to base256, removes null-padding if present, returns
    /// `Err(Error::InvalidPadding)` if padding bits are unequal `0`
    fn from_base32(b32: &[u5]) -> Result<Self, Self::Error> {
        let mut ret: ArrayVec<u8, L> = ArrayVec::new();
        convert_bits_in::<ComboError, _, _>(b32, 5, 8, false, &mut ret)?;
        Ok(ret)
    }
}

#[cfg(feature = "alloc")]
impl FromBase32 for Vec<u8> {
    type Error = Error;

    /// Converts base32 (slice of u5s) to base256 (vector of u8s).
    ///
    /// Removes null-padding if present.
    ///
    /// # Errors
    ///
    /// Uses [`convert_bits`] to convert 5 bit values to 8 bit values, see that function for errors.
    fn from_base32(b32: &[u5]) -> Result<Self, Self::Error> { convert_bits(b32, 5, 8, false) }
}

/// A trait for converting a value to a type `T` that represents a `u5` slice.
///
/// This trait is the reciprocal of `FromBase32`.
pub trait ToBase32 {
    /// Converts `Self` to a base32 vector.
    #[cfg(feature = "alloc")]
    fn to_base32(&self) -> Vec<u5> {
        let mut vec = Vec::new();
        self.write_base32(&mut vec).unwrap();
        vec
    }

    /// Encodes `Self` as base32 and writes it to the supplied writer.
    ///
    /// Implementations should not allocate.
    fn write_base32<W: WriteBase32>(&self, writer: &mut W)
        -> Result<(), <W as WriteBase32>::Error>;
}

/// Interface to calculate the length of the base32 representation before actually serializing.
pub trait Base32Len: ToBase32 {
    /// Calculates the base32 serialized length.
    fn base32_len(&self) -> usize;
}

impl<T: AsRef<[u8]> + ?Sized> ToBase32 for T {
    fn write_base32<W: WriteBase32>(
        &self,
        writer: &mut W,
    ) -> Result<(), <W as WriteBase32>::Error> {
        // Amount of bits left over from last round, stored in buffer.
        let mut buffer_bits = 0u32;
        // Holds all unwritten bits left over from last round. The bits are stored beginning from
        // the most significant bit. E.g. if buffer_bits=3, then the byte with bits a, b and c will
        // look as follows: [a, b, c, 0, 0, 0, 0, 0]
        let mut buffer: u8 = 0;

        for &b in self.as_ref() {
            // Write first u5 if we have to write two u5s this round. That only happens if the
            // buffer holds too many bits, so we don't have to combine buffer bits with new bits
            // from this rounds byte.
            if buffer_bits >= 5 {
                writer.write_u5(u5((buffer & 0b1111_1000) >> 3))?;
                buffer <<= 5;
                buffer_bits -= 5;
            }

            // Combine all bits from buffer with enough bits from this rounds byte so that they fill
            // a u5. Save reamining bits from byte to buffer.
            let from_buffer = buffer >> 3;
            let from_byte = b >> (3 + buffer_bits); // buffer_bits <= 4

            writer.write_u5(u5(from_buffer | from_byte))?;
            buffer = b << (5 - buffer_bits);
            buffer_bits += 3;
        }

        // There can be at most two u5s left in the buffer after processing all bytes, write them.
        if buffer_bits >= 5 {
            writer.write_u5(u5((buffer & 0b1111_1000) >> 3))?;
            buffer <<= 5;
            buffer_bits -= 5;
        }

        if buffer_bits != 0 {
            writer.write_u5(u5(buffer >> 3))?;
        }

        Ok(())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Base32Len for T {
    fn base32_len(&self) -> usize {
        let bits = self.as_ref().len() * 8;
        if bits % 5 == 0 {
            bits / 5
        } else {
            bits / 5 + 1
        }
    }
}

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
/// # Errors
///
/// * Deviations from standard.
/// * No length limits are enforced for the data part.
pub fn encode_to_fmt<T: AsRef<[u5]>>(
    fmt: &mut dyn fmt::Write,
    hrp: Hrp,
    data: T,
    variant: Variant,
) -> Result<fmt::Result, Error> {
    let mut hrp = hrp;
    hrp.lowercase();
    encode_to_fmt_anycase(fmt, hrp, data, variant)
}

/// Encode a bech32 payload to an [fmt::Write], but with any case.
/// This method is intended for implementing traits from [core::fmt] without [std].
///
/// See `encode_to_fmt` for meaning of errors.
pub fn encode_to_fmt_anycase<T: AsRef<[u5]>>(
    fmt: &mut dyn fmt::Write,
    hrp: Hrp,
    data: T,
    variant: Variant,
) -> Result<fmt::Result, Error> {
    match variant {
        Variant::Bech32 => {
            let res = Bech32Writer::<Bech32>::new(hrp, fmt);
            match res {
                Ok(mut writer) => {
                    Ok(writer.write(data.as_ref()).and_then(|_| {
                        // Finalize manually to avoid panic on drop if write fails
                        writer.finalize()
                    }))
                }
                Err(e) => Ok(Err(e)),
            }
        }
        Variant::Bech32m => {
            let res = Bech32Writer::<Bech32m>::new(hrp, fmt);
            match res {
                Ok(mut writer) => {
                    Ok(writer.write(data.as_ref()).and_then(|_| {
                        // Finalize manually to avoid panic on drop if write fails
                        writer.finalize()
                    }))
                }
                Err(e) => Ok(Err(e)),
            }
        }
    }
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

const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

impl Variant {
    /// Produces the variant based on the remainder of the polymod operation.
    fn from_remainder(c: u32) -> Option<Self> {
        match c {
            BECH32_CONST => Some(Variant::Bech32),
            BECH32M_CONST => Some(Variant::Bech32m),
            _ => None,
        }
    }
}

/// Encodes a bech32 payload to string.
///
/// # Deviations from standard.
///
/// * No length limits are enforced for the data part.
#[cfg(feature = "alloc")]
pub fn encode<T: AsRef<[u5]>>(hrp: Hrp, data: T, variant: Variant) -> Result<String, Error> {
    let mut buf = String::new();
    encode_to_fmt(&mut buf, hrp, data, variant)?.unwrap();
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

/// Decodes a bech32 string into the raw HRP and the data bytes.
///
/// # Returns
///
/// The human-readable part in lowercase, the data with the checksum removed, and the encoding.
#[cfg(feature = "alloc")]
pub fn decode(s: &str) -> Result<(Hrp, Vec<u5>, Variant), Error> {
    let (hrp_lower, mut data) = split_and_decode(s)?;
    if data.len() < CHECKSUM_LENGTH {
        return Err(Error::InvalidLength);
    }

    // Ensure checksum
    match verify_checksum(hrp_lower, &data) {
        Some(variant) => {
            // Remove checksum from data payload
            data.truncate(data.len() - CHECKSUM_LENGTH);

            Ok((hrp_lower, data, variant))
        }
        None => Err(Error::InvalidChecksum),
    }
}

/// Decodes a bech32 string into the raw HRP and the data bytes, assuming no checksum.
///
/// # Returns
///
/// The human-readable part in lowercase and the data.
#[cfg(feature = "alloc")]
pub fn decode_without_checksum(s: &str) -> Result<(Hrp, Vec<u5>), Error> { split_and_decode(s) }

/// Decodes a bech32 string into the raw HRP and the `u5` data.
#[cfg(feature = "alloc")]
fn split_and_decode(s: &str) -> Result<(Hrp, Vec<u5>), Error> {
    // Split at separator and check for two pieces
    let (raw_hrp, raw_data) = match s.rfind(SEP) {
        None => return Err(Error::MissingSeparator),
        Some(sep) => {
            let (hrp, data) = s.split_at(sep);
            (hrp, &data[1..])
        }
    };

    let (hrp, mut case) = Hrp::parse_and_case(raw_hrp)?;

    // Check data payload
    let data = raw_data
        .chars()
        .map(|c| {
            if c.is_lowercase() {
                match case {
                    Case::Upper => return Err(Error::MixedCase),
                    Case::None => case = Case::Lower,
                    Case::Lower => {}
                }
            } else if c.is_uppercase() {
                match case {
                    Case::Lower => return Err(Error::MixedCase),
                    Case::None => case = Case::Upper,
                    Case::Upper => {}
                }
            }
            u5::from_char(c).map_err(Error::TryFrom)
        })
        .collect::<Result<Vec<u5>, Error>>()?;

    Ok((hrp, data))
}

// TODO deduplicate some
/// Decode a lowercase bech32 string into the raw HRP and the data bytes.
///
/// Less flexible than [decode], but don't allocate.
pub fn decode_lowercase<'b, E, R, S>(
    s: &str,
    data: &'b mut R,
    scratch: &mut S,
) -> Result<(Hrp, &'b [u5], Variant), E>
where
    R: WriteBase32 + AsRef<[u5]>,
    S: WriteBase32 + AsRef<[u5]>,
    E: From<R::Error>,
    E: From<S::Error>,
    E: From<Error>,
    E: core::convert::From<primitives::hrp::Error>,
{
    // Ensure overall length is within bounds
    if s.len() < 8 {
        Err(Error::InvalidLength)?;
    }

    // Split at separator and check for two pieces
    let (raw_hrp, raw_data) = match s.rfind(SEP) {
        None => Err(Error::MissingSeparator)?,
        Some(sep) => {
            let (hrp, data) = s.split_at(sep);
            (hrp, &data[1..])
        }
    };
    if raw_data.len() < 6 {
        Err(Error::InvalidLength)?;
    }

    let (hrp, case) = Hrp::parse_and_case(raw_hrp)?;

    // Check data payload
    for c in raw_data.chars() {
        match case {
            Case::Upper => Err(Error::MixedCase)?,
            Case::None | Case::Lower => {}
        }
        data.write_u5(u5::from_char(c).map_err(Error::TryFrom)?)?;
    }

    // Ensure checksum
    let variant =
        verify_checksum_in(hrp, data.as_ref(), scratch)?.ok_or(Error::MissingSeparator)?;

    let dbl: usize = data.as_ref().len();
    Ok((hrp, &(*data).as_ref()[..dbl.saturating_sub(6)], variant))
}

#[cfg(feature = "alloc")]
fn verify_checksum(hrp: Hrp, data: &[u5]) -> Option<Variant> {
    let mut v: Vec<u5> = Vec::new();
    match verify_checksum_in(hrp, data, &mut v) {
        Ok(v) => v,
        Err(e) => match e {},
    }
}

fn verify_checksum_in<T>(hrp: Hrp, data: &[u5], v: &mut T) -> Result<Option<Variant>, T::Error>
where
    T: WriteBase32 + AsRef<[u5]>,
{
    hrp_expand_in(hrp, v)?;
    v.write(data)?;
    Ok(Variant::from_remainder(polymod(v.as_ref())))
}

fn hrp_expand_in<T: WriteBase32>(hrp: Hrp, v: &mut T) -> Result<(), T::Error> {
    for b in hrp.lowercase_byte_iter() {
        v.write_u5(u5::try_from(b >> 5).expect("can't be out of range, max. 7"))?;
    }
    v.write_u5(u5::try_from(0).unwrap())?;
    for b in hrp.lowercase_byte_iter() {
        v.write_u5(u5::try_from(b & 0x1f).expect("can't be out of range, max. 31"))?;
    }
    Ok(())
}

fn polymod(values: &[u5]) -> u32 {
    let mut chk: u32 = 1;
    let mut b: u8;
    for v in values {
        b = (chk >> 25) as u8;
        chk = (chk & 0x01ff_ffff) << 5 ^ (u32::from(*v.as_ref()));

        for (i, item) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= item;
            }
        }
    }
    chk
}

/// Human-readable part and data part separator.
const SEP: char = '1';

/// Generator coefficients
const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];

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
}

impl From<Infallible> for Error {
    fn from(v: Infallible) -> Self { match v {} }
}

impl From<hrp::Error> for Error {
    fn from(e: hrp::Error) -> Self { Error::Hrp(e) }
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
    #[cfg(feature = "arrayvec")]
    use arrayvec::ArrayString;

    use super::*;

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
    fn getters_in() {
        let mut data_scratch = Vec::new();
        let mut scratch = Vec::new();
        let decoded =
            decode_lowercase::<Error, _, _>("bc1sw50qa3jx3s", &mut data_scratch, &mut scratch)
                .unwrap();
        let data = [16, 14, 20, 15, 0].check_base32_vec().unwrap();
        assert_eq!(decoded.0.to_string(), "bc");
        assert_eq!(decoded.1, data.as_slice());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn getters() {
        let decoded = decode("BC1SW50QA3JX3S").unwrap();
        let data = [16, 14, 20, 15, 0].check_base32_vec().unwrap();
        assert_eq!(decoded.0, hrp("bc"));
        assert_eq!(decoded.0.to_string(), "BC");
        assert_eq!(decoded.1, data.as_slice());
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
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        );
        for s in strings {
            match decode(s) {
                Ok((hrp, payload, variant)) => {
                    let encoded = encode(hrp, payload, variant).unwrap();
                    assert_eq!(s.to_lowercase(), encoded.to_lowercase());
                }
                Err(e) => panic!("Did not decode: {:?} Reason: {:?}", s, e),
            }
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn invalid_strings() {
        let pairs: Vec<(&str, Error)> = vec!(
            (" 1nwldj5",
                Error::Hrp(hrp::Error::InvalidAsciiByte(b' '))),
            ("abc1\u{2192}axkwrx",
                Error::TryFrom(primitives::gf32::Error::InvalidChar('\u{2192}'))),
            ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
                Error::Hrp(hrp::Error::TooLong(84))),
            ("pzry9x0s0muk",
                Error::MissingSeparator),
            ("1pzry9x0s0muk",
                Error::Hrp(hrp::Error::Empty)),
            ("x1b4n0q5v",
                Error::TryFrom(primitives::gf32::Error::InvalidChar('b'))),
            ("ABC1DEFGOH",
                Error::TryFrom(primitives::gf32::Error::InvalidChar('O'))),
            ("li1dgmt3",
                Error::InvalidLength),
            ("de1lg7wt\u{ff}",
                Error::TryFrom(primitives::gf32::Error::InvalidChar('\u{ff}'))),
            ("\u{20}1xj0phk",
                Error::Hrp(hrp::Error::InvalidAsciiByte(b' '))), // u20 is space character
            ("\u{7F}1g6xzxy",
                Error::Hrp(hrp::Error::InvalidAsciiByte(0x7f))),
            ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
                Error::Hrp(hrp::Error::TooLong(84))),
            ("qyrz8wqd2c9m",
                Error::MissingSeparator),
            ("1qyrz8wqd2c9m",
                Error::Hrp(hrp::Error::Empty)),
            ("y1b0jsk6g",
                Error::TryFrom(primitives::gf32::Error::InvalidChar('b'))),
            ("lt1igcx5c0",
                Error::TryFrom(primitives::gf32::Error::InvalidChar('i'))),
            ("in1muywd",
                Error::InvalidLength),
            ("mm1crxm3i",
                Error::TryFrom(primitives::gf32::Error::InvalidChar('i'))),
            ("au1s5cgom",
                Error::TryFrom(primitives::gf32::Error::InvalidChar('o'))),
            ("M1VUXWEZ",
                Error::InvalidChecksum),
            ("16plkw9",
                Error::Hrp(hrp::Error::Empty)),
            ("1p2gdwpf",
                Error::Hrp(hrp::Error::Empty)),
            ("bc1p2",
                Error::InvalidLength),
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
    fn from_base32() {
        assert_eq!(Vec::from_base32(&[0x1f, 0x1c].check_base32_vec().unwrap()), Ok(vec![0xff]));
        assert_eq!(
            Vec::from_base32(&[0x1f, 0x1f].check_base32_vec().unwrap()),
            Err(Error::InvalidPadding)
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn to_base32() {
        assert_eq!([0xffu8].to_base32(), [0x1f, 0x1c].check_base32_vec().unwrap());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn write_with_checksum() {
        let hrp = hrp("lnbc");
        let data = "Hello World!".as_bytes().to_base32();

        let mut written_str = String::new();
        {
            let mut writer = Bech32Writer::<Bech32>::new(hrp, &mut written_str).unwrap();
            writer.write(&data).unwrap();
            writer.finalize().unwrap();
        }

        let encoded_str = encode(hrp, data, Variant::Bech32).unwrap();

        assert_eq!(encoded_str, written_str);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn write_without_checksum() {
        let hrp = hrp("lnbc");
        let data = "Hello World!".as_bytes().to_base32();

        let mut written_str = String::new();
        {
            let mut writer = Bech32Writer::<Bech32>::new(hrp, &mut written_str).unwrap();
            writer.write(&data).unwrap();
        }

        let encoded_str = encode_without_checksum(hrp, data).unwrap();

        assert_eq!(encoded_str, written_str[..written_str.len() - CHECKSUM_LENGTH]);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn write_with_checksum_on_drop() {
        let hrp = hrp("lntb");
        let data = "Hello World!".as_bytes().to_base32();

        let mut written_str = String::new();
        {
            let mut writer = Bech32Writer::<Bech32>::new(hrp, &mut written_str).unwrap();
            writer.write(&data).unwrap();
        }

        let encoded_str = encode(hrp, data, Variant::Bech32).unwrap();

        assert_eq!(encoded_str, written_str);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn roundtrip_without_checksum() {
        let hrp = hrp("lnbc");
        let data = "Hello World!".as_bytes().to_base32();

        let encoded = encode_without_checksum(hrp, data.clone()).expect("failed to encode");
        let (decoded_hrp, decoded_data) =
            decode_without_checksum(&encoded).expect("failed to decode");

        assert_eq!(decoded_hrp, hrp);
        assert_eq!(decoded_data, data);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_hrp_case() {
        // Tests for issue with HRP case checking being ignored for encoding
        let encoded_str = encode(hrp("HRP"), [0x00, 0x00].to_base32(), Variant::Bech32).unwrap();

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
    #[cfg(feature = "arrayvec")]
    fn test_arrayvec() {
        let mut encoded = ArrayString::<30>::new();

        let mut base32 = ArrayVec::<u5, 30>::new();

        [0x00u8, 0x01, 0x02].write_base32(&mut base32).unwrap();

        let bech32_hrp = Hrp::parse("bech32").expect("bech32 is valid");
        encode_to_fmt_anycase(&mut encoded, bech32_hrp, &base32, Variant::Bech32).unwrap().unwrap();
        assert_eq!(&*encoded, "bech321qqqsyrhqy2a");

        println!("{}", encoded);

        let mut decoded = ArrayVec::<u5, 30>::new();

        let mut scratch = ArrayVec::<u5, 30>::new();

        let (hrp, data, variant) =
            decode_lowercase::<ComboError, _, _>(&encoded, &mut decoded, &mut scratch).unwrap();
        assert_eq!(hrp.to_string(), "bech32");
        let res = ArrayVec::<u8, 30>::from_base32(data).unwrap();
        assert_eq!(&res, [0x00, 0x01, 0x02].as_ref());
        assert_eq!(variant, Variant::Bech32);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decode_bitcoin_bech32_address() {
        let addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let (hrp, _data, variant) = crate::decode(addr).expect("address is well formed");
        assert_eq!(hrp.to_string(), "bc");
        assert_eq!(variant, Variant::Bech32)
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decode_bitcoin_bech32m_address() {
        let addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        let (hrp, _data, variant) = crate::decode(addr).expect("address is well formed");
        assert_eq!(hrp.to_string(), "bc");
        assert_eq!(variant, Variant::Bech32m)
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn decode_all_digit_hrp_uppercase_data() {
        let addr = "23451QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZLKULZK";
        let (hrp, data, variant) = crate::decode(addr).expect("address is well formed");
        assert_eq!(hrp, Hrp::parse("2345").unwrap());
        let hrp = Hrp::parse("2345").unwrap();
        let s = crate::encode(hrp, data, variant).expect("failed to encode");
        assert_eq!(s.to_uppercase(), addr);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn writer_lowercases_hrp_when_adding_to_checksum() {
        let addr = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        let (_hrp, data, _variant) = crate::decode(addr).expect("failed to decode");
        let data: Vec<u8> = FromBase32::from_base32(&data[1..]).expect("failed to convert u5s");

        let mut writer = String::new();
        let mut bech32_writer = Bech32Writer::<Bech32>::new(Hrp::parse("BC").unwrap(), &mut writer)
            .expect("failed to write hrp");
        let version = u5::try_from(0).unwrap();

        WriteBase32::write_u5(&mut bech32_writer, version).expect("failed to write version");
        ToBase32::write_base32(&data, &mut bech32_writer).expect("failed to write data");

        drop(bech32_writer);

        assert_eq!(writer, addr.to_lowercase());
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
            let s = crate::encode(hrp, &data, variant).expect("failed to encode");
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
            let s = crate::encode(hrp, &data, variant).expect("failed to encode");
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
