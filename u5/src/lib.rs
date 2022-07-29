// Written by Clark Moody and the rust-bitcoin developers.
// SPDX-License-Identifier: MIT
//
// A lot of the code and docs in this file is adapted from the Rust stdlib.

//! A 5 bit unsigned integer.
//!
//! An integer in the range 0..32
//!

#![deny(missing_docs)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![cfg_attr(feature = "strict", deny(warnings))]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

use core::convert::TryFrom;
use core::{fmt, num};
use core::ops::{Add, Div, Mul, Rem, Sub};

/// Integer in the range `0..32` i.e., a 5 bit integer.
/// # Examples
/// ```
/// use core::convert::TryFrom;
/// use u5::u5;
///
/// // Construct a u5 from an integer of unknown size.
/// # let v = 1;
/// let x = u5::try_from(v).expect("fails if v > 31");
///
/// // Construct a u5 from an integer masking off the high bits.
/// let x = u5::from_low_5_bits(129);
/// assert_eq!(x, u5::try_from(1).unwrap());
/// ```
// Maintains the invariant that inner is never greater that 31.
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub struct u5(u8);

impl u5 {
    /// The smallest value that can be represented by this integer type.
    ///
    /// # Examples
    /// ```
    /// # use u5::u5;
    /// assert_eq!(u5::MIN, u5::ZERO)
    /// ```
    pub const MIN: Self = Self::ZERO;

    /// The largest value that can be represented by this integer type.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// assert_eq!(u5::MAX, u5::try_from(31).unwrap());
    /// ```
    pub const MAX: Self = u5(31);

    /// The size of this integer type in bits.
    ///
    /// # Examples
    /// ```
    /// # use u5::u5;
    /// assert_eq!(u5::BITS, 5);
    /// ```
    pub const BITS: u32 = 5;

    /// The zero value.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// assert_eq!(u5::ZERO, u5::try_from(0).unwrap())
    /// ```
    pub const ZERO: Self = u5(0);

    /// Converts a string slice in a given base to an integer.
    ///
    /// The string is expected to be an optional `+` sign followed by digits. Leading and trailing
    /// whitespace represent an error. Digits are a subset of these characters, depending on
    /// `radix`:
    ///
    /// * `0-9`
    /// * `a-z`
    /// * `A-Z`
    ///
    /// # Panics
    ///
    /// This function panics if `radix` is not in the range from 2 to 36.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// assert_eq!(u5::from_str_radix("12", 10).unwrap(), u5::try_from(12).unwrap())
    /// ```
    pub fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError> {
        let x = u8::from_str_radix(src, radix)?;
        if x > Self::MAX.0 {
            return Err(ParseIntError::Overflow(x));
        }
        Ok(u5(x))
    }

    /// Constructs a `u5` from the low 5 bits of `value`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// assert_eq!(u5::from_low_5_bits(5), u5::try_from(5).unwrap());
    /// assert_eq!(u5::from_low_5_bits(32), u5::ZERO);
    /// ```
    #[inline]
    pub const fn from_low_5_bits(value: u8) -> Self { u5(value & 0x1f) }

    /// New code should prefer to use u5::MIN instead.
    ///
    /// Returns the smallest value that can be represented by this integer type.
    #[inline]
    pub const fn min_value() -> Self {
        Self::MIN
    }

    /// New code should prefer to use u5::MAX instead.
    ///
    /// Returns the largest value that can be represented by this integer type.
    #[inline]
    pub const fn max_value() -> Self {
        Self::MAX
    }

    /// Returns a copy of the underlying `u8` value.
    ///
    /// # Examples
    /// ```
    /// # use u5::u5;
    /// assert_eq!(u5::from_low_5_bits(20).to_u8(), 20);
    /// ```
    #[inline]
    pub const fn to_u8(self) -> u8 { self.0 }

    /// Returns the number of ones in the binary representation of `self`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0000_1100;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// assert_eq!(x.count_ones(), 2);
    /// ```
    #[inline]
    pub fn count_ones(self) -> u32 { self.0.count_ones() }

    /// Returns the number of zeros in the binary representation of `self`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0001_0100;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// assert_eq!(x.count_zeros(), 3);
    /// ```
    #[inline]
    pub fn count_zeros(self) -> u32 { Self::BITS - self.count_ones() }

    /// Returns the number of leading zeros in the binary representation of `self`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0000_0100;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// assert_eq!(x.leading_zeros(), 2);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn leading_zeros(self) -> u32 { self.0.leading_zeros() - 3 }

    /// Returns the number of trailing zeros in the binary representation of `self`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0001_0100;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// assert_eq!(x.trailing_zeros(), 2);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn trailing_zeros(self) -> u32 {
        let count = self.0.trailing_zeros();
        if count >= 5 {
            5
        } else {
            count
        }
    }
    
    /// Returns the number of leading zeros in the binary representation of `self`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0001_1100;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// assert_eq!(x.leading_ones(), 3);
    /// ```
    #[cfg(feature = "rust_1_46_0")]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn leading_ones(self) -> u32 {
        let x = self.0 ^ 0xe0;
        let count = x.leading_ones();
        count - 3
    }

    /// Returns the number of trailing zeros in the binary representation of `self`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0001_0101;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// assert_eq!(x.trailing_ones(), 1);
    /// ```
    #[cfg(feature = "rust_1_46_0")]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn trailing_ones(self) -> u32 {
        let count = self.0.trailing_ones();
        if count >= 5 {
            5
        } else {
            count
        }
    }

    /// Shifts the bits to the left by a specified amount, `n`, wrapping the truncated bits to the
    /// end of the resulting integer.
    ///
    /// Please note this isn't the same operation as the `<<` shifting operator!
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0001_0010;
    /// let m = 0b0000_1010;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// let y = u5::try_from(m).expect("m is less than 32");
    /// assert_eq!(x.rotate_left(2), y);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn rotate_left(self, n: u32) -> Self {
        let mut res = u5(0);
        for i in 0..5 {
            if self.is_bit_set(i) {
                let j = (i + n) % 5;
                res.set_bit(j);
            }
        }
        res
    }

    /// Shifts the bits to the right by a specified amount, `n`, wrapping the truncated bits to the
    /// beginning of the resulting integer.
    ///
    /// Please note this isn't the same operation as the `>>` shifting operator!
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0001_0010;
    /// let m = 0b0001_0100;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// let y = u5::try_from(m).expect("m is less than 32");
    /// assert_eq!(x.rotate_right(2), y);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn rotate_right(self, n: u32) -> Self {
        let mut res = u5(0);
        for i in 0..5 {
            if self.is_bit_set(i) {
                let mut j = i as i32 - n as i32;
                while j < 0 {
                    j += 5;
                }
                res.set_bit(j as u32);
            }
        }
        res
    }

    /// Reverses the byte order of the integer.
    ///
    /// For `u5` this is a no-op, provided for uniformity with other stdlib integer types.
    #[must_use]
    #[inline]
    pub const fn swap_bytes(self) -> Self {
        self
    }

    fn is_bit_set(self, i: u32) -> bool { self.0 & (1 << i) > 0 }

    fn set_bit(&mut self, i: u32) { self.0 |= 1 << i }

    /// Reverses the order of bits in the integer. The least significant bit becomes the most
    /// significant bit, second least-significant bit becomes second most-significant bit, etc.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0001_0010;
    /// let m = 0b000_1001;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// let y = u5::try_from(m).expect("m is less than 32");
    /// assert_eq!(x.reverse_bits(), y);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn reverse_bits(self) -> Self {
        let x = self.0.reverse_bits();
        u5(x >> 3)
    }

    /// Converts an integer from big endian to the target's endianness.
    ///
    /// For `u5` this is a no-op, provided for uniformity with other stdlib integer types.
    #[must_use]
    #[inline]
    pub fn from_be(self) -> Self {
        self
    }

    /// Converts an integer from little endian to the target's endianness.
    ///
    /// For `u5` this is a no-op, provided for uniformity with other stdlib integer types.
    #[must_use]
    #[inline]
    pub fn from_le(self) -> Self {
        self
    }

    /// Converts `self` to big endian from the target's endianness.
    ///
    /// For `u5` this is a no-op, provided for uniformity with other stdlib integer types.
    #[must_use]
    #[inline]
    pub fn to_be(self) -> Self {
        self
    }

    /// Converts `self` to little endian from the target's endianness.
    ///
    /// For `u5` this is a no-op, provided for uniformity with other stdlib integer types.
    #[must_use]
    #[inline]
    pub fn to_le(self) -> Self {
        self
    }

    /// Checked integer addition. Computes `self + rhs`, returning `None`
    /// if overflow occurred.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// assert_eq!(one.checked_add(two), Some(three));
    /// assert_eq!(two.checked_add(u5::MAX), None);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let (a, b) = self.overflowing_add(rhs);
        if b {
            None
        } else {
            Some(a)
        }
    }

    /// Checked integer subtraction. Computes `self - rhs`, returning `None` if overflow occurred.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// assert_eq!(two.checked_sub(one), Some(one));
    /// assert_eq!(one.checked_sub(two), None);
    /// ```
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        let (a, b) = self.overflowing_sub(rhs);
        if b {
            None
        } else {
            Some(a)
        }
    }

    /// Checked integer multiplication. Computes `self * rhs`, returning `None` if overflow
    /// occurred.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let three = u5::try_from(3).unwrap();
    /// let seven = u5::try_from(7).unwrap();
    /// let twenty_one = u5::try_from(21).unwrap();
    /// assert_eq!(three.checked_mul(seven), Some(twenty_one));
    /// assert_eq!(u5::MAX.checked_mul(three), None);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        let (a, b) = self.overflowing_mul(rhs);
        if b {
            None
        } else {
            Some(a)
        }
    }

    /// Checked integer division. Computes `self / rhs`, returning `None` if `rhs == 0`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let three = u5::try_from(3).unwrap();
    /// let seven = u5::try_from(7).unwrap();
    /// let twenty_one = u5::try_from(21).unwrap();
    /// assert_eq!(twenty_one.checked_div(seven), Some(three));
    /// assert_eq!(u5::MAX.checked_div(u5::ZERO), None);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn checked_div(self, rhs: Self) -> Option<Self> {
        if rhs.0 == 0 {
            return None;
        }

        let (a, b) = self.overflowing_div(rhs);
        if b {
            None
        } else {
            Some(a)
        }
    }

    /// Checked integer remainder. Computes `self % rhs`, returning `None`a if `rhs == 0`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let five = u5::try_from(5).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let one = u5::try_from(1).unwrap();
    /// assert_eq!(five.checked_rem(two), Some(one));
    /// assert_eq!(five.checked_rem(u5::ZERO), None);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn checked_rem(self, rhs: Self) -> Option<Self> {
        // Cannot use map: error: `Option::<T>::map` is not yet stable as a const fn.
        match self.0.checked_rem(rhs.0) {
            Some(r) => Some(u5(r)),
            None => None,
        }
    }

    /// Checked shift left. Computes `self << rhs`, returning `None` if `rhs` is larger than or
    /// equal to the number of bits in `self`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0001_0010;
    /// let m = 0b0001_0000;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// let y = u5::try_from(m).expect("m is less than 32");
    /// assert_eq!(x.checked_shl(3), Some(y));
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn checked_shl(self, rhs: u32) -> Option<Self> {
        let (a, b) = self.overflowing_shl(rhs);
        if b {
            None
        } else {
            Some(a)
        }
    }

    /// Checked shift right. Computes `self >> rhs`, returning `None` if `rhs` is larger than or
    /// equal to the number of bits in `self`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let n = 0b0001_0010;
    /// let m = 0b0000_0010;
    /// let x = u5::try_from(n).expect("n is less than 32");
    /// let y = u5::try_from(m).expect("m is less than 32");
    /// assert_eq!(x.checked_shr(3), Some(y));
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn checked_shr(self, rhs: u32) -> Option<Self> {
        let (a, b) = self.overflowing_shr(rhs);
        if b {
            None
        } else {
            Some(a)
        }
    }

    /// Checked exponentiation. Computes `self.pow(exp)`, returning `None` if
    /// overflow occurred.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let three = u5::try_from(3).unwrap();
    /// let nine = u5::try_from(9).unwrap();
    /// assert_eq!(three.checked_pow(2), Some(nine));
    /// assert_eq!(u5::MAX.checked_pow(2), None);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn checked_pow(self, exp: u32) -> Option<Self> {
        match self.0.checked_pow(exp) {
            Some(x) =>
                if x > 31 {
                    None
                } else {
                    Some(u5(x))
                },
            None => None,
        }
    }

    /// Saturating integer addition. Computes `self + rhs`, saturating at the numeric bounds instead
    /// of overflowing.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// assert_eq!(one.saturating_add(two), three);
    /// assert_eq!(u5::MAX.saturating_add(three), u5::MAX);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn saturating_add(self, rhs: Self) -> Self {
        match self.checked_add(rhs) {
            Some(x) => x,
            None => u5::MAX,
        }
    }

    /// Saturating integer subtraction. Computes `self - rhs`, saturating at the numeric bounds instead
    /// of overflowing.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// assert_eq!(three.saturating_sub(two), one);
    /// assert_eq!(one.saturating_sub(three), u5::ZERO);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn saturating_sub(self, rhs: Self) -> Self {
        match self.checked_sub(rhs) {
            Some(x) => x,
            None => u5::ZERO,
        }
    }

    /// Saturating integer multiplication. Computes `self * rhs`, saturating at the numeric bounds instead
    /// of overflowing.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// let six = u5::try_from(6).unwrap();
    /// assert_eq!(three.saturating_mul(two), six);
    /// assert_eq!(u5::MAX.saturating_mul(two), u5::MAX);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn saturating_mul(self, rhs: Self) -> Self {
        match self.checked_mul(rhs) {
            Some(x) => x,
            None => u5::MAX,
        }
    }

    /// Saturating integer division. Computes `self / rhs`, saturating at the numeric bounds instead
    /// of overflowing.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let five = u5::try_from(5).unwrap();
    /// assert_eq!(five.saturating_div(two), two);
    /// ```
    ///
    /// ```should_panic
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let _ = two.saturating_div(u5::ZERO);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn saturating_div(self, rhs: Self) -> Self {
        // on unsigned types, there is no overflow in integer division
        self.wrapping_div(rhs)
    }

    /// Saturating integer exponentiation. Computes `self.pow(exp)`, saturating at the numeric
    /// bounds instead of overflowing.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let three = u5::try_from(3).unwrap();
    /// let nine = u5::try_from(9).unwrap();
    /// assert_eq!(three.saturating_pow(2), nine);
    /// assert_eq!(u5::MAX.saturating_pow(2), u5::MAX);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn saturating_pow(self, exp: u32) -> Self {
        match self.checked_pow(exp) {
            Some(x) => x,
            None => Self::MAX,
        }
    }

    /// Wrapping (modular) addition. Computes `self + rhs`, wrapping around at the boundary of the
    /// type.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// assert_eq!(one.wrapping_add(two), three);
    /// assert_eq!(two.wrapping_add(u5::MAX), one);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn wrapping_add(self, rhs: Self) -> Self {
        let sum = self.0 + rhs.0;
        let wrapped = if sum > 31 { sum - 32 } else { sum };
        u5::from_low_5_bits(wrapped)
    }

    /// Wrapping (modular) subtraction. Computes `self - rhs`, wrapping around at the boundary of
    /// the type.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// assert_eq!(three.wrapping_sub(two), one);
    /// assert_eq!(one.wrapping_sub(u5::MAX), two);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn wrapping_sub(self, rhs: Self) -> Self {
        let (x, _) = self.overflowing_sub(rhs);
        x
    }

    /// Wrapping (modular) multiplication. Computes `self * rhs`, wrapping around at the boundary of
    /// the type.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let four = u5::try_from(4).unwrap();
    /// let eight = u5::try_from(8).unwrap();
    /// let ten = u5::try_from(10).unwrap();
    /// assert_eq!(two.wrapping_mul(four), eight);
    /// assert_eq!(four.wrapping_mul(ten), eight);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn wrapping_mul(self, rhs: Self) -> Self {
        let (x, _) = self.overflowing_mul(rhs);
        x
    }

    /// Wrapping (modular) division. Computes `self / rhs`, wrapping around at the boundary of the
    /// type.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let four = u5::try_from(4).unwrap();
    /// assert_eq!(four.wrapping_div(two), two);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn wrapping_div(self, rhs: Self) -> Self {
        // Can't use `/` because our operators are not const.
        let x = self.0 / rhs.0;
        u5(x)
    }

    /// Panic-free bitwise shift-left; yields `self << mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-left; the RHS of a wrapping shift-left is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. The primitive integer types all implement a
    /// [`rotate_left`](Self::rotate_left) function, which may be what you want instead.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let sixteen = u5::try_from(16).unwrap();
    /// assert_eq!(one.wrapping_shl(4), sixteen);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn wrapping_shl(self, rhs: u32) -> Self {
        let x = self.0 as u32;
        let r = x << rhs;
        u5::from_low_5_bits(r as u8)
    }

    /// Panic-free bitwise shift-right; yields `self >> mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-right; the RHS of a wrapping shift-right is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. The primitive integer types all implement a
    /// [`rotate_right`](Self::rotate_right) function, which may be what you want instead.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let sixteen = u5::try_from(16).unwrap();
    /// assert_eq!(sixteen.wrapping_shr(4), one);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn wrapping_shr(self, rhs: u32) -> Self {
        let x = self.0 as u32;
        let r = x >> rhs;
        u5::from_low_5_bits(r as u8)
    }

    /// Wrapping (modular) exponentiation. Computes `self * rhs`, wrapping around at the boundary of
    /// the type.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let four = u5::try_from(4).unwrap();
    /// let ten = u5::try_from(10).unwrap();
    /// assert_eq!(two.wrapping_pow(2), four);
    /// assert_eq!(ten.wrapping_pow(2), four);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn wrapping_pow(self, exp: u32) -> Self {
        let mut x = self.0.pow(exp);
        while x > 31 {
            x -= 32
        }
        u5::from_low_5_bits(x)
    }

    /// Calculates `self` + `rhs`
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// assert_eq!(one.overflowing_add(two), (three, false));
    /// assert_eq!(two.overflowing_add(u5::MAX), (one, true));
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let x = self.0 + rhs.0;
        let (x, overflow) = if x > 31 { (x - 32, true) } else { (x, false) };
        (u5::from_low_5_bits(x), overflow)
    }

    /// Calculates `self` - `rhs`
    ///
    /// Returns a tuple of the subtraction along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// assert_eq!(three.overflowing_sub(two), (one, false));
    /// assert_eq!(one.overflowing_sub(u5::MAX), (two, true));
    /// ```
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let x = self.0 as i32 - rhs.0 as i32;
        let (x, overflow) = if x < 0 { (x + 32, true) } else { (x, false) };
        (u5::from_low_5_bits(x as u8), overflow)
    }

    /// Computes the absolute difference between `self` and `other`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// assert_eq!(one.abs_diff(three), two);
    /// assert_eq!(three.abs_diff(one), two);
    /// ```
    #[inline]
    #[must_use = "this returns the result of the operation, without modifying the original"]
    pub fn abs_diff(self, other: Self) -> Self {
        // We can make traits const but the  stdlib operators or const so use them.
        let a = self.0;
        let b = other.0;
        if a < b {
            u5(b - a)
        } else {
            u5(a - b)
        }
    }

    /// Calculates the multiplication of `self` and `rhs`.
    ///
    /// Returns a tuple of the multiplication along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let three = u5::try_from(3).unwrap();
    /// assert_eq!(one.overflowing_add(two), (three, false));
    /// assert_eq!(two.overflowing_add(u5::MAX), (one, true));
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn overflowing_mul(self, rhs: Self) -> (Self, bool) {
        // Use u32 because 31 * 31 does not fit in a u8.
        let mut x = self.0 as u32 * rhs.0 as u32;
        let overflow = x > 31;

        while x > 31 {
            x -= 32
        }

        (u5(x as u8), overflow)
    }

    /// Calculates the divisor when `self` is divided by `rhs`.
    ///
    /// Returns a tuple of the divisor along with a boolean indicating whether an arithmetic
    /// overflow would occur. Note that for unsigned integers overflow never occurs, so the second
    /// value is always `false`.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let four = u5::try_from(4).unwrap();
    /// assert_eq!(four.overflowing_div(two), (two, false));
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn overflowing_div(self, rhs: Self) -> (Self, bool) {
        let x = self.0 / rhs.0;
        (u5(x), false)
    }

    /// Calculates the remainder when `self` is divided by `rhs`.
    ///
    /// Returns a tuple of the remainder after dividing along with a boolean
    /// indicating whether an arithmetic overflow would occur. Note that for
    /// unsigned integers overflow never occurs, so the second value is
    /// always `false`.
    ///
    /// # Panics
    ///
    /// This function will panic if `rhs` is 0.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let two = u5::try_from(2).unwrap();
    /// let five = u5::try_from(5).unwrap();
    /// assert_eq!(five.overflowing_rem(two), (one, false));
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn overflowing_rem(self, rhs: Self) -> (Self, bool) {
        let mut x = self;
        while x > rhs {
            x = x - rhs
        }
        (x, false)
    }

    /// Shifts self left by `rhs` bits.
    ///
    /// Returns a tuple of the shifted version of self along with a boolean indicating whether the
    /// shift value was larger than or equal to the number of bits. If the shift value is too large,
    /// then value is masked (N-1) where N is the number of bits, and this value is then used to
    /// perform the shift.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(0x01).unwrap();
    /// let sixteen = u5::try_from(0x10).unwrap();
    /// assert_eq!(one.overflowing_shl(4), (sixteen, false));
    /// assert_eq!(one.overflowing_shl(6), (u5::ZERO, true));
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn overflowing_shl(self, rhs: u32) -> (Self, bool) {
        (self.wrapping_shl(rhs), (rhs > 4))
    }

    /// Shifts self right by `rhs` bits.
    ///
    /// Returns a tuple of the shifted version of self along with a boolean indicating whether the
    /// shift value was larger than or equal to the number of bits. If the shift value is too large,
    /// then value is masked (N-1) where N is the number of bits, and this value is then used to
    /// perform the shift.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(0x01).unwrap();
    /// let sixteen = u5::try_from(0x10).unwrap();
    /// assert_eq!(sixteen.overflowing_shr(4), (one, false));
    /// assert_eq!(sixteen.overflowing_shr(6), (u5::ZERO, true));
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn overflowing_shr(self, rhs: u32) -> (Self, bool) {
        (self.wrapping_shr(rhs), (rhs > 4))
    }

    /// Raises self to the power of `exp`, using exponentiation by squaring.
    ///
    /// Returns a tuple of the exponentiation along with a bool indicating whether an overflow
    /// happened.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let four = u5::try_from(4).unwrap();
    /// let ten = u5::try_from(10).unwrap();
    /// assert_eq!(two.overflowing_pow(2), (four, false));
    /// assert_eq!(ten.overflowing_pow(2), (four, true));
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn overflowing_pow(self, mut exp: u32) -> (Self, bool) {
        if exp == 0 {
            return (u5(1), false);
        }

        let mut base = self;
        let mut acc: Self = u5(1);
        let mut overflow = false;

        // Scratch space for storing results of overflowing_mul.
        let mut r;

        while exp > 1 {
            if (exp & 1) == 1 {
                r = acc.overflowing_mul(base);
                acc = r.0;
                overflow |= r.1;
            }
            exp /= 2;
            r = base.overflowing_mul(base);
            base = r.0;
            overflow |= r.1;
        }

        // since exp!=0, finally the exp must be 1. Deal with the final bit of the exponent
        // separately, since squaring the base afterwards is not necessary and may cause a needless
        // overflow.
        r = acc.overflowing_mul(base);
        r.1 |= overflow;

        r
    }

    /// Raises self to the power of `exp`, using exponentiation by squaring.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let four = u5::try_from(4).unwrap();
    /// let ten = u5::try_from(10).unwrap();
    /// assert_eq!(two.pow(2), four);
    /// assert_eq!(ten.pow(2), four);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn pow(self, exp: u32) -> Self { self.overflowing_pow(exp).0 }

    /// Calculates the quotient of `self` and `rhs`, rounding the result towards negative infinity.
    ///
    /// This is the same as performing `self / rhs` for all unsigned integers.
    ///
    /// # Panics
    ///
    /// This function will panic if `rhs` is zero.
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let one = u5::try_from(1).unwrap();
    /// let four = u5::try_from(4).unwrap();
    /// let seven = u5::try_from(7).unwrap();
    /// assert_eq!(seven.div_floor(four), one);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn div_floor(self, rhs: Self) -> Self {
        self / rhs
    }

    /// Calculates the quotient of `self` and `rhs`, rounding the result towards positive infinity.
    ///
    /// # Panics
    ///
    /// This function will panic if `rhs` is zero.
    ///
    /// ## Overflow behavior
    ///
    /// On overflow, this function will panic if overflow checks are enabled (default in debug
    /// mode) and wrap if overflow checks are disabled (default in release mode).
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let two = u5::try_from(2).unwrap();
    /// let four = u5::try_from(4).unwrap();
    /// let seven = u5::try_from(7).unwrap();
    /// assert_eq!(seven.div_ceil(four), two);
    /// ```
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[inline]
    pub fn div_ceil(self, rhs: Self) -> Self {
        let d = self / rhs;
        let r = self % rhs;
        if r > u5::ZERO && rhs > u5::ZERO {
            d + u5::try_from(1).expect("valid value")
        } else {
            d
        }
    }

    /// Calculates the smallest value greater than or equal to `self` that
    /// is a multiple of `rhs`.
    ///
    /// # Panics
    ///
    /// This function will panic if `rhs` is zero.
    ///
    /// ## Overflow behavior
    ///
    /// On overflow, this function will panic if overflow checks are enabled (default in debug
    /// mode) and wrap if overflow checks are disabled (default in release mode).
    ///
    /// # Examples
    /// ```
    /// # use core::convert::TryFrom;
    /// # use u5::u5;
    /// let four = u5::try_from(4).unwrap();
    /// let seven = u5::try_from(7).unwrap();
    /// let eight = u5::try_from(8).unwrap();
    /// assert_eq!(seven.next_multiple_of(four), eight);
    pub fn next_multiple_of(self, rhs: Self) -> Self {
        match self % rhs {
            u5::ZERO => self,
            r => self + (rhs - r)
        }
    }
}

impl Add for u5 {
    type Output = Self;

    /// This can silently overflow, consider using [`u5::checked_add`].
    #[inline]
    fn add(self, rhs: Self) -> Self {
        let (res, _) = self.overflowing_add(rhs);
        res
    }
}

impl Sub for u5 {
    type Output = Self;

    #[inline]
    /// This can silently overflow, consider using [`u5::checked_sub`].
    fn sub(self, rhs: Self) -> Self::Output {
        let (res, _) = self.overflowing_sub(rhs);
        res
    }
}

impl Mul for u5 {
    type Output = Self;

    /// This can silently overflow, consider using [`u5::checked_mul`].
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let (res, _) = self.overflowing_mul(rhs);
        res
    }
}

impl Div for u5 {
    type Output = Self;

    /// This can silently overflow, consider using [`u5::checked_div`].
    #[inline]
    fn div(self, rhs: Self) -> Self::Output {
        let (res, _) = self.overflowing_div(rhs);
        res
    }
}

impl Rem for u5 {
    type Output = Self;

    #[inline]
    fn rem(self, rhs: Self) -> Self::Output {
        let (res, _) = self.overflowing_rem(rhs);
        res
    }
}

impl From<u5> for u8 {
    fn from(v: u5) -> u8 { v.0 }
}

// TODO: Turn this into a macro and implement for other integer types?
impl TryFrom<u8> for u5 {
    type Error = OverflowError;

    /// Errors if `value` is out of range.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 31 {
            Err(OverflowError(value))
        } else {
            Ok(u5(value))
        }
    }
}

impl TryFrom<String> for u5 {
    type Error = ParseIntError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str_radix(&s, 10)
    }
}

impl TryFrom<Box<str>> for u5 {
    type Error = ParseIntError;

    fn try_from(s: Box<str>) -> Result<Self, Self::Error> {
        Self::from_str_radix(&String::from(s), 10)
    }
}

impl<'a> TryFrom<&'a str> for u5 {
    type Error = ParseIntError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::from_str_radix(s, 10)
    }
}

// TODO: Implement FromStr and TryFrom for stringly types?

impl AsRef<u8> for u5 {
    fn as_ref(&self) -> &u8 { &self.0 }
}

/// Value is invalid, overflows a `u5`.
#[derive(Clone, Debug, PartialEq)]
pub struct OverflowError(u8);

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "value is invalid, overflows a u5)")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OverflowError {}

/// Possible error type returned while parsing a string.
// TODO: Consider using code from bitcoin/src/parse.rs
#[derive(Clone, Debug, PartialEq)]
pub enum ParseIntError {
    /// Error returned by `num` trying to parse a `u8`.
    Num(num::ParseIntError),
    /// Error returned if value is bigger than a `u5`.
    Overflow(u8),
}

impl fmt::Display for ParseIntError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseIntError::*;

        match self {
            Num(e) => write!(f, "{}", e),
            Overflow(x) => write!(f, "parsed value is invalid, overflows a u5 ({})", x),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseIntError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseIntError::*;

        match self {
            Num(e) => Some(e),
            Overflow(_) => None,
        }
    }
}

impl From<num::ParseIntError> for ParseIntError {
    fn from(e: num::ParseIntError) -> Self {
        ParseIntError::Num(e)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_operators() {
        let one = u5::try_from(1).unwrap();
        let two = u5::try_from(2).unwrap();
        let three = u5::try_from(3).unwrap();
        let six = u5::try_from(6).unwrap();

        assert_eq!(one + two, three);
        assert_eq!(three - two, one);
        assert_eq!(two * three, six);
        assert_eq!(six / two, three);
        assert_eq!(three % two, one);
    }

    macro_rules! from_low_5_bits {
        ($($test_name:ident, $in:literal, $want:literal);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let got = u5::from_low_5_bits($in);
                    let want = u5($want);
                    assert_eq!(got, want);
                }
            )*
        }
    }

    from_low_5_bits! {
            from_low_5_bits_a, 0x00, 0x00;
            from_low_5_bits_b, 0x01, 0x01;
            from_low_5_bits_c, 0x0f, 0x0f;
            from_low_5_bits_d, 0x1e, 0x1e;
            from_low_5_bits_e, 0x1f, 0x1f;
            from_low_5_bits_f, 0x3f, 0x1f;
            from_low_5_bits_g, 0xff, 0x1f;
    }

    macro_rules! count_ones {
        ($($test_name:ident, $in:literal, $want:literal);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let x = u5::try_from($in).expect("test case input value overflowed");
                    let got = x.count_ones();
                    assert_eq!(got, $want)
                }
            )*
        }
    }

    count_ones! {
        count_ones_a, 0x00, 0;
        count_ones_b, 0x01, 1;
        count_ones_c, 0x03, 2;
        count_ones_d, 0x07, 3;
        count_ones_e, 0x0f, 4;
        count_ones_f, 0x1f, 5;
        count_ones_g, 0x0d, 3;
        count_ones_h, 0x0c, 2;
        count_ones_i, 0x0a, 2;
    }

    macro_rules! leading_zeros {
        ($($test_name:ident, $in:literal, $want:literal);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let x = u5::try_from($in).expect("test case input value overflowed");
                    let got = x.leading_zeros();
                    assert_eq!(got, $want)
                }
            )*
        }
    }

    leading_zeros! {
        leading_zeros_a, 0x00, 5;
        leading_zeros_b, 0x01, 4;
        leading_zeros_c, 0x03, 3;
        leading_zeros_d, 0x07, 2;
        leading_zeros_e, 0x0f, 1;
        leading_zeros_f, 0x1f, 0;
        leading_zeros_g, 0x10, 0;
        leading_zeros_h, 0x0c, 1;
        leading_zeros_i, 0x0a, 1;
    }

    macro_rules! trailing_zeros {
        ($($test_name:ident, $in:literal, $want:literal);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let x = u5::try_from($in).expect("test case input value overflowed");
                    let got = x.trailing_zeros();
                    assert_eq!(got, $want)
                }
            )*
        }
    }

    trailing_zeros! {
        trailing_zeros_a, 0x00, 5;
        trailing_zeros_b, 0x01, 0;
        trailing_zeros_c, 0x03, 0;
        trailing_zeros_d, 0x07, 0;
        trailing_zeros_e, 0x0f, 0;
        trailing_zeros_f, 0x1f, 0;
        trailing_zeros_g, 0x10, 4;
        trailing_zeros_h, 0x0c, 2;
        trailing_zeros_i, 0x0a, 1;
    }

    #[cfg(feature = "rust_1_46_0")]
    macro_rules! leading_ones {
        ($($test_name:ident, $in:literal, $want:literal);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let x = u5::try_from($in).expect("test case input value overflowed");
                    let got = x.leading_ones();
                    assert_eq!(got, $want)
                }
            )*
        }
    }

    #[cfg(feature = "rust_1_46_0")]
    leading_ones! {
        leading_ones_a, 0x1f, 5;
        leading_ones_b, 0x0f, 0;
        leading_ones_c, 0x0e, 0;
        leading_ones_d, 0x08, 0;
        leading_ones_e, 0x11, 1;
        leading_ones_f, 0x1c, 3;
    }

    #[cfg(feature = "rust_1_46_0")]
    macro_rules! trailing_ones {
        ($($test_name:ident, $in:literal, $want:literal);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let x = u5::try_from($in).expect("test case input value overflowed");
                    let got = x.trailing_ones();
                    assert_eq!(got, $want)
                }
            )*
        }
    }

    #[cfg(feature = "rust_1_46_0")]
    trailing_ones! {
        trailing_ones_a, 0x00, 0;
        trailing_ones_b, 0x01, 1;
        trailing_ones_c, 0x03, 2;
        trailing_ones_d, 0x07, 3;
        trailing_ones_e, 0x0f, 4;
        trailing_ones_f, 0x1f, 5;
        trailing_ones_g, 0x10, 0;
        trailing_ones_h, 0x0c, 0;
        trailing_ones_i, 0x0a, 0;
    }

    macro_rules! overflowing_add {
        ($($test_name:ident, $a:literal, $b:literal, $want:literal, $overflow:literal);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let a = u5($a);
                    let b = u5($b);

                    let want = (u5($want), $overflow);
                    let got = a.overflowing_add(b);
                    assert_eq!(got, want)
                }
            )*
        }
    }

    overflowing_add! {
        overflowing_add_a, 1, 2, 3, false;
        overflowing_add_b, 30, 1, 31, false;
        overflowing_add_c, 31, 0, 31, false;
        overflowing_add_d, 31, 1, 0, true;
        overflowing_add_e, 32, 32, 0, true;
        overflowing_add_f, 30, 3, 1, true;
    }

    macro_rules! checked_add {
        ($($test_name:ident, $a:literal, $b:literal, $want:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let a = u5($a);
                    let b = u5($b);

                    let want = $want.map(u5::from_low_5_bits);
                    let got = a.checked_add(b);
                    assert_eq!(got, want)
                }
            )*
        }
    }

    checked_add! {
        checked_add_a, 1, 2, Some(3);
        checked_add_b, 30, 1, Some(31);
        checked_add_c, 31, 0, Some(31);
        checked_add_d, 31, 1, None;
        checked_add_e, 32, 32, None;
        checked_add_f, 30, 3, None;
    }

    macro_rules! overflowing_sub {
        ($($test_name:ident, $a:literal, $b:literal, $want:literal, $overflow:literal);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let a = u5($a);
                    let b = u5($b);

                    let want = (u5($want), $overflow);
                    let got = a.overflowing_sub(b);
                    assert_eq!(got, want)
                }
            )*
        }
    }

    overflowing_sub! {
        overflowing_sub_a, 2, 1, 1, false;
        overflowing_sub_b, 1, 1, 0, false;
        overflowing_sub_c, 31, 0, 31, false;
        overflowing_sub_d, 0, 1, 31, true;
        overflowing_sub_e, 0, 2, 30, true;
        overflowing_sub_f, 0, 3, 29, true;
    }

    macro_rules! checked_sub {
        ($($test_name:ident, $a:literal, $b:literal, $want:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let a = u5($a);
                    let b = u5($b);

                    let want = $want.map(u5::from_low_5_bits);
                    let got = a.checked_sub(b);
                    assert_eq!(got, want)
                }
            )*
        }
    }

    checked_sub! {
        checked_sub_a, 7, 5, Some(2);
        checked_sub_b, 30, 1, Some(29);
        checked_sub_c, 31, 0, Some(31);
        checked_sub_d, 0, 1, None;
        checked_sub_e, 0, 2, None;
        checked_sub_f, 0, 31, None;
    }

    macro_rules! wrapping_mul {
        ($($test_name:ident, $a:literal, $b:literal, $want:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let a = u5($a);
                    let b = u5($b);

                    let want = u5::from_low_5_bits($want);
                    let got = a.wrapping_mul(b);
                    assert_eq!(got, want)
                }
            )*
        }
    }

    wrapping_mul! {
        wrapping_mul_a, 3, 5, 15;
        wrapping_mul_b, 4, 10, 8;
        wrapping_mul_c, 30, 10, 12;
    }

    macro_rules! add {
        ($($test_name:ident, $a:literal, $b:literal, $want:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    let sum = $a + $b;
                    let want = u5::from_low_5_bits(sum);

                    let a = u5($a);
                    let b = u5($b);
                    let got = a + b;

                    assert_eq!(got, want)
                }
            )*
        }
    }

    add! {
        add_a, 3, 5, 8;
        add_b, 10, 21, 31;
        add_c, 10, 22, 0;
        add_d, 20, 29, 17;
        add_e, 20, 30, 18;
    }

    #[test]
    fn is_bit_set() {
        let x = u5(0b0001_0101);
        assert!(x.is_bit_set(0));
        assert!(x.is_bit_set(2));
        assert!(x.is_bit_set(4));
        assert!(!x.is_bit_set(1));
        assert!(!x.is_bit_set(3));
    }

    #[test]
    fn set_bit() {
        let mut x = u5::from_low_5_bits(0x00);
        x.set_bit(0);
        assert_eq!(x.0, 0x01);

        x.set_bit(1);
        assert_eq!(x.0, 0x03);

        x.set_bit(3);
        assert_eq!(x.0, 0x0b);
    }
}
