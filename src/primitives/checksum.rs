// Written by the Andrew Poelstra and the rust-bitcoin developers.
// SPDX-License-Identifier: MIT

//! Degree-2 [BCH] code checksum.
//!
//! [BCH]: <https://en.wikipedia.org/wiki/BCH_code>

use core::{mem, ops};

use crate::primitives::gf32::Fe32;
use crate::primitives::hrp::Hrp;

/// Trait describing an integer type which can be used as a "packed" sequence of Fe32s.
///
/// This is implemented for u32, u64 and u128, as a way to treat these primitive types as
/// packed coefficients of polynomials over GF32 (up to some maximal degree, of course).
///
/// This is useful because then multiplication by x reduces to simply left-shifting by 5,
/// and addition of entire polynomials can be done by xor.
pub trait PackedFe32: Copy + PartialEq + Eq + ops::BitXor<Self, Output = Self> {
    /// The one constant, for which stdlib provides no existing trait.
    const ONE: Self;

    /// The number of fe32s that can fit into the type; computed as floor(bitwidth / 5).
    const WIDTH: usize = mem::size_of::<Self>() * 8 / 5;

    /// Extracts the coefficient of the x^n from the packed polynomial.
    fn unpack(&self, n: usize) -> u8;

    /// Multiply the polynomial by x, drop its highest coefficient (and return it), and
    /// add a new field element to the now-0 constant coefficient.
    ///
    /// Takes the degree of the polynomial as an input; for checksum applications
    /// this shoud basically always be `Checksum::CHECKSUM_WIDTH`.
    fn mul_by_x_then_add(&mut self, degree: usize, add: u8) -> u8;
}

/// A placeholder type used as part of the [`crate::segwit::NoChecksum`] "checksum".
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PackedNull;

impl ops::BitXor<PackedNull> for PackedNull {
    type Output = PackedNull;
    fn bitxor(self, _: PackedNull) -> PackedNull { PackedNull }
}

impl PackedFe32 for PackedNull {
    const ONE: Self = PackedNull;
    fn unpack(&self, _: usize) -> u8 { 0 }
    fn mul_by_x_then_add(&mut self, _: usize, _: u8) -> u8 { 0 }
}

macro_rules! impl_packed_fe32 {
    ($ty:ident) => {
        impl PackedFe32 for $ty {
            const ONE: Self = 1;

            fn unpack(&self, n: usize) -> u8 {
                debug_assert!(n < Self::WIDTH);
                (*self >> (n * 5)) as u8 & 0x1f
            }

            fn mul_by_x_then_add(&mut self, degree: usize, add: u8) -> u8 {
                debug_assert!(degree > 0);
                debug_assert!(degree <= Self::WIDTH);
                debug_assert!(add < 32);
                let ret = self.unpack(degree - 1);
                *self &= !(0x1f << ((degree - 1) * 5));
                *self <<= 5;
                *self |= Self::from(add);
                ret
            }
        }
    };
}
impl_packed_fe32!(u32);
impl_packed_fe32!(u64);
impl_packed_fe32!(u128);

/// Trait defining a particular checksum.
///
/// For users, this can be treated as a marker trait; none of the associated data
/// are end-user relevant.
pub trait Checksum {
    /// An unsigned integer type capable of holding a packed version of the generator
    /// polynomial (without its leading 1) and target residue (which will have the
    /// same width).
    ///
    /// Generally, this is the number of characters in the checksum times 5. So e.g.
    /// for bech32, which has a 6-character checksum, we need 30 bits, so we can use
    /// u32 here.
    ///
    /// The smallest type possible should be used, for efficiency reasons, but the
    /// only operations we do on these types are bitwise xor and shifts, so it should
    /// be pretty efficient no matter what.
    type MidstateRepr: PackedFe32;

    /// The number of characters in the checksum.
    ///
    /// Alternately, the degree of the generator polynomial. This is **not** the same
    /// as the "length of the code", which is the maximum number of characters that
    /// the checksum can usefully cover.
    const CHECKSUM_LENGTH: usize;

    /// The coefficients of the generator polynomial, except the leading monic term,
    /// in "big-endian" (highest-degree coefficients get leftmost bits) order, along
    /// with the 4 shifts of the generator.
    ///
    /// The shifts are literally the generator polynomial left-shifted (i.e. multiplied
    /// by the appropriate power of 2) in the field. That is, the 5 entries in this
    /// array are the generator times { P, Z, Y, G, S } in that order.
    ///
    /// These cannot be usefully pre-computed because of Rust's limited constfn support
    /// as of 1.67, so they must be specified manually for each checksum. To check the
    /// values for consistency, run `Self::sanity_check()`.
    const GENERATOR_SH: [Self::MidstateRepr; 5];

    /// The residue, modulo the generator polynomial, that a valid codeword will have.
    const TARGET_RESIDUE: Self::MidstateRepr;

    /// Sanity check that the various constants of the trait are set in a way that are
    /// consistent with each other.
    ///
    /// This function never needs to be called by users, but anyone defining a checksum
    /// should add a unit test to their codebase which calls this.
    fn sanity_check() {
        // Check that the declared midstate type can actually hold the whole checksum.
        assert!(Self::CHECKSUM_LENGTH <= Self::MidstateRepr::WIDTH);

        // Check that the provided generator polynomials are, indeed, the same polynomial just shifted.
        for i in 1..5 {
            for j in 0..Self::MidstateRepr::WIDTH {
                let last = Self::GENERATOR_SH[i - 1].unpack(j);
                let curr = Self::GENERATOR_SH[i].unpack(j);
                // GF32 is defined by extending GF2 with a root of x^5 + x^3 + 1 = 0
                // which when written as bit coefficients is 41 = 0. Hence xoring
                // (adding, in GF32) by 41 is the way to reduce x^5.
                assert_eq!(
                    curr,
                    (last << 1) ^ if last & 0x10 == 0x10 { 41 } else { 0 },
                    "Element {} of generator << 2^{} was incorrectly computed. (Should have been {} << 1)",
                    j, i, last,
                );
            }
        }
    }
}

/// A checksum engine, which can be used to compute or verify a checksum.
///
/// Use this to verify a checksum, feed it the data to be checksummed using
/// the `Self::input_*` methods.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Engine<Ck: Checksum> {
    residue: Ck::MidstateRepr,
}

impl<Ck: Checksum> Default for Engine<Ck> {
    fn default() -> Self { Self::new() }
}

impl<Ck: Checksum> Engine<Ck> {
    /// Construct a new checksum engine with no data input.
    pub fn new() -> Self { Engine { residue: Ck::MidstateRepr::ONE } }

    /// Expands an HRP and feeds it into the checksum engine.
    ///
    /// This function is infallible, but if you feed it non-ASCII input or
    /// use it after the checksum engine has already had other data input,
    /// it probably will cause your engine to produce useless results.
    pub fn input_hrp(&mut self, hrp: Hrp) {
        for ch in hrp.iter() {
            self.input_fe(Fe32(ch >> 5));
        }
        self.input_fe(Fe32::Q);
        for ch in hrp.iter() {
            self.input_fe(Fe32(ch & 0x1f));
        }
    }

    /// Adds a single gf32 element to the checksum engine.
    ///
    /// This is where the actual checksum computation magic happens.
    pub fn input_fe(&mut self, e: Fe32) {
        let xn = self.residue.mul_by_x_then_add(Ck::CHECKSUM_LENGTH, e.into());
        for i in 0..5 {
            if xn & (1 << i) != 0 {
                self.residue = self.residue ^ Ck::GENERATOR_SH[i];
            }
        }
    }

    /// Inputs the target residue of the checksum.
    ///
    /// Checksums are generated by appending the target residue to the input
    /// string, then computing the actual residue, and then replacing the
    /// target with the actual. This method lets us compute the actual residue
    /// without doing any string concatenations.
    pub fn input_target_residue(&mut self) {
        for i in 0..Ck::CHECKSUM_LENGTH {
            self.input_fe(Fe32(Ck::TARGET_RESIDUE.unpack(Ck::CHECKSUM_LENGTH - i - 1)));
        }
    }

    /// Returns for the current checksum residue.
    pub fn residue(&self) -> &Ck::MidstateRepr { &self.residue }
}
