// SPDX-License-Identifier: MIT

//! Generic Field Traits

use core::convert::TryInto;
use core::iter::{Skip, Take};
use core::{fmt, hash, iter, ops};

/// A generic field.
pub trait Field:
    Sized
    + PartialEq
    + Eq
    + Clone
    + Default
    + hash::Hash
    + fmt::Debug
    + fmt::Display
    + iter::Sum
    + for<'a> iter::Sum<&'a Self>
    + ops::Add<Self, Output = Self>
    + ops::Sub<Self, Output = Self>
    + ops::AddAssign
    + ops::SubAssign
    + ops::Mul<Self, Output = Self>
    + ops::MulAssign
    + ops::Div<Self, Output = Self>
    + ops::DivAssign
    + for<'a> ops::Add<&'a Self, Output = Self>
    + for<'a> ops::AddAssign<&'a Self>
    + for<'a> ops::Sub<&'a Self, Output = Self>
    + for<'a> ops::SubAssign<&'a Self>
    + for<'a> ops::Mul<&'a Self, Output = Self>
    + for<'a> ops::MulAssign<&'a Self>
    + for<'a> ops::Div<&'a Self, Output = Self>
    + for<'a> ops::DivAssign<&'a Self>
    + ops::Neg<Output = Self>
{
    /// The zero constant of the field.
    const ZERO: Self;

    /// The one constant of the field.
    const ONE: Self;

    /// A primitive element, i.e. a generator of the multiplicative group of the field.
    const GENERATOR: Self;

    /// The smallest integer n such that 1 + ... + 1, n times, equals 0.
    ///
    /// If this is 0, this indicates that no such integer exists.
    const CHARACTERISTIC: usize;

    /// The order of the multiplicative group of the field.
    const MULTIPLICATIVE_ORDER: usize;

    /// All factors of the multiplicative order, in increasing order.
    ///
    /// Include both 1 and the number itself. So for example if you have `n` distinct
    /// prime factors which each appearing once, this array would have size `2^n`.
    const MULTIPLICATIVE_ORDER_FACTORS: &'static [usize];

    /// Computes the multiplicative inverse of an element.
    fn multiplicative_inverse(self) -> Self;

    /// Takes the element times some integer.
    fn muli(&self, mut n: i64) -> Self {
        let base = if n >= 0 {
            self.clone()
        } else {
            n *= -1;
            self.clone().multiplicative_inverse()
        };

        let mut ret = Self::ZERO;
        // Special case some particular characteristics
        match Self::CHARACTERISTIC {
            1 => unreachable!("no field has characteristic 1"),
            2 => {
                // Special-case 2 because it's easy and also the only characteristic used
                // within the library. The compiler should prune away the other code.
                if n % 2 == 0 {
                    Self::ZERO
                } else {
                    self.clone()
                }
            }
            x => {
                // This is identical to powi below, but with * replaced by +.
                if x > 0 {
                    n %= x as i64;
                }

                let mut mask = x.next_power_of_two() as i64;
                while mask > 0 {
                    ret += ret.clone();
                    if n & mask != 0 {
                        ret += &base;
                    }
                    mask >>= 1;
                }
                ret
            }
        }
    }

    /// Takes the element to the power of some integer.
    fn powi(&self, mut n: i64) -> Self {
        let base = if n >= 0 {
            self.clone()
        } else {
            n *= -1;
            self.clone().multiplicative_inverse()
        };
        n %= Self::MULTIPLICATIVE_ORDER as i64;

        let mut mask = Self::MULTIPLICATIVE_ORDER.next_power_of_two() as i64;
        let mut ret = Self::ONE;
        while mask > 0 {
            ret *= ret.clone();
            if n & mask != 0 {
                ret *= &base;
            }
            mask >>= 1;
        }
        ret
    }

    /// The multiplicative order of an element.
    fn multiplicative_order(&self) -> usize {
        for &ord in Self::MULTIPLICATIVE_ORDER_FACTORS {
            if self.powi(ord as i64) == Self::ONE {
                return ord;
            }
        }
        panic!(
            "bug: `ExtensionField::MULTIPLICATIVE_ORDER_FACTORS` did not include full group order"
        );
    }

    /// Constructs an iterator over all the powers of an element from 0 onward.
    fn powers(self) -> Powers<Self> { Powers { base: self, next: Self::ONE } }

    /// Constructs an iterator over all the powers of an element within a given range.
    ///
    /// # Panics
    ///
    /// Panics if given a range whose start is greater than its end, or whose range
    /// is from 0 to `usize::MAX`. Its intended use is with [`crate::Checksum::ROOT_EXPONENTS`]
    /// for which neither of these conditions should ever be true.
    fn powers_range(self, range: ops::RangeInclusive<usize>) -> Take<Skip<Powers<Self>>> {
        self.powers().skip(*range.start()).take(*range.end() - range.start() + 1)
    }
}

/// Trait describing a simple extension field (field obtained from another by
/// adjoining one element).
pub trait ExtensionField: Field + From<Self::BaseField> + TryInto<Self::BaseField> {
    /// The type of the base field.
    type BaseField: Field;

    /// The degree of the extension.
    ///
    /// Must be strictly greater than 1.
    const DEGREE: usize;

    /// An extension field is defined as `GF32[x]/p(x)`, for some irreducible
    /// monic polynomial p whose degree then becomes the degree of the extension.
    ///
    /// If p(x) = x^d + ... p_1x + p_0 we can represent p by an element of
    /// the extension field, specifically the image of p(x) - x^d. Equivalently,
    /// if zeta is the image of x in the quotient map, then this value is
    /// equal to zeta^d.
    ///
    /// This value is used to define multiplication in the extension field.
    const POLYNOMIAL: Self;

    /// The element which is adjoined to the base field to get this field.
    ///
    /// In other words, the image of x in the isomorphism from
    /// [`Self::BaseField`]`[x]`/[`Self::POLYNOMIAL`] to [`Self`].
    const EXT_ELEM: Self;
}

mod private {
    /// Sealing trait.
    pub trait Sealed {}

    impl Sealed for crate::Fe32 {}
    impl Sealed for crate::Fe1024 {}
    impl Sealed for crate::Fe32768 {}
}

/// Sealed trait which extends [`Field`] with extra functionality
/// needed internally to this library.
///
/// This trait should not be used directly by users of the library.
pub trait Bech32Field: private::Sealed + Sized {
    /// Adds a value to `self`. This is a helper function for implementing the
    /// [`ops::Add`] and [`ops::AddAssign`] traits.
    fn _add(&self, other: &Self) -> Self;

    /// Subtracts a value from `self`. This is a helper function for implementing the
    /// [`ops::Sub`] and [`ops::SubAssign`] traits.
    fn _sub(&self, other: &Self) -> Self {
        self._add(other) // all fields in this library are binary fields
    }

    /// Multiplies a value by `self`. This is a helper function for implementing the
    /// [`ops::Mul`] and [`ops::MulAssign`] traits.
    fn _mul(&self, other: &Self) -> Self;

    /// Divides a value from `self`. This is a helper function for implementing the
    /// [`ops::Div`] and [`ops::DivAssign`] traits.
    fn _div(&self, other: &Self) -> Self;

    /// Computes the additive inverse of an element.
    fn _neg(self) -> Self;

    /// Utility method to format a field element as Rust code.
    fn format_as_rust_code(&self, f: &mut fmt::Formatter) -> fmt::Result;
}

macro_rules! impl_ops_for_fe {
    (impl for $op:ident) => {
        // add
        impl core::ops::Add<$op> for $op {
            type Output = Self;
            #[inline]
            fn add(self, other: $op) -> $op { $crate::primitives::Bech32Field::_add(&self, &other) }
        }

        impl core::ops::Add<&$op> for $op {
            type Output = Self;
            #[inline]
            fn add(self, other: &$op) -> $op { $crate::primitives::Bech32Field::_add(&self, other) }
        }

        impl core::ops::Add<$op> for &$op {
            type Output = $op;
            #[inline]
            fn add(self, other: $op) -> $op { $crate::primitives::Bech32Field::_add(self, &other) }
        }

        impl core::ops::Add<&$op> for &$op {
            type Output = $op;
            #[inline]
            fn add(self, other: &$op) -> $op { $crate::primitives::Bech32Field::_add(self, other) }
        }

        impl core::ops::AddAssign for $op {
            #[inline]
            fn add_assign(&mut self, other: $op) {
                *self = $crate::primitives::Bech32Field::_add(self, &other)
            }
        }

        impl core::ops::AddAssign<&$op> for $op {
            #[inline]
            fn add_assign(&mut self, other: &$op) {
                *self = $crate::primitives::Bech32Field::_add(self, other)
            }
        }

        // sub
        impl core::ops::Sub<$op> for $op {
            type Output = Self;
            #[inline]
            fn sub(self, other: $op) -> $op { $crate::primitives::Bech32Field::_sub(&self, &other) }
        }

        impl core::ops::Sub<&$op> for $op {
            type Output = Self;
            #[inline]
            fn sub(self, other: &$op) -> $op { $crate::primitives::Bech32Field::_sub(&self, other) }
        }

        impl core::ops::Sub<$op> for &$op {
            type Output = $op;
            #[inline]
            fn sub(self, other: $op) -> $op { $crate::primitives::Bech32Field::_sub(self, &other) }
        }

        impl core::ops::Sub<&$op> for &$op {
            type Output = $op;
            #[inline]
            fn sub(self, other: &$op) -> $op { $crate::primitives::Bech32Field::_sub(self, other) }
        }

        impl core::ops::SubAssign for $op {
            #[inline]
            fn sub_assign(&mut self, other: $op) {
                *self = $crate::primitives::Bech32Field::_sub(self, &other)
            }
        }

        impl core::ops::SubAssign<&$op> for $op {
            #[inline]
            fn sub_assign(&mut self, other: &$op) {
                *self = $crate::primitives::Bech32Field::_sub(self, other)
            }
        }

        // mul
        impl core::ops::Mul<$op> for $op {
            type Output = Self;
            #[inline]
            fn mul(self, other: $op) -> $op { $crate::primitives::Bech32Field::_mul(&self, &other) }
        }

        impl core::ops::Mul<&$op> for $op {
            type Output = Self;
            #[inline]
            fn mul(self, other: &$op) -> $op { $crate::primitives::Bech32Field::_mul(&self, other) }
        }

        impl core::ops::Mul<$op> for &$op {
            type Output = $op;
            #[inline]
            fn mul(self, other: $op) -> $op { $crate::primitives::Bech32Field::_mul(self, &other) }
        }

        impl core::ops::Mul<&$op> for &$op {
            type Output = $op;
            #[inline]
            fn mul(self, other: &$op) -> $op { $crate::primitives::Bech32Field::_mul(self, other) }
        }

        impl core::ops::MulAssign for $op {
            #[inline]
            fn mul_assign(&mut self, other: $op) {
                *self = $crate::primitives::Bech32Field::_mul(self, &other)
            }
        }

        impl core::ops::MulAssign<&$op> for $op {
            #[inline]
            fn mul_assign(&mut self, other: &$op) {
                *self = $crate::primitives::Bech32Field::_mul(self, other)
            }
        }

        // div
        impl core::ops::Div<$op> for $op {
            type Output = Self;
            #[inline]
            fn div(self, other: $op) -> $op { $crate::primitives::Bech32Field::_div(&self, &other) }
        }

        impl core::ops::Div<&$op> for $op {
            type Output = Self;
            #[inline]
            fn div(self, other: &$op) -> $op { $crate::primitives::Bech32Field::_div(&self, other) }
        }

        impl core::ops::Div<$op> for &$op {
            type Output = $op;
            #[inline]
            fn div(self, other: $op) -> $op { $crate::primitives::Bech32Field::_div(self, &other) }
        }

        impl core::ops::Div<&$op> for &$op {
            type Output = $op;
            #[inline]
            fn div(self, other: &$op) -> $op { $crate::primitives::Bech32Field::_div(self, other) }
        }

        impl core::ops::DivAssign for $op {
            #[inline]
            fn div_assign(&mut self, other: $op) {
                *self = $crate::primitives::Bech32Field::_div(self, &other)
            }
        }

        impl core::ops::DivAssign<&$op> for $op {
            #[inline]
            fn div_assign(&mut self, other: &$op) {
                *self = $crate::primitives::Bech32Field::_div(self, other)
            }
        }

        // neg
        impl core::ops::Neg for $op {
            type Output = Self;
            #[inline]
            fn neg(self) -> Self { $crate::primitives::Bech32Field::_neg(self) }
        }

        // sum
        impl core::iter::Sum for $op {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(crate::primitives::Field::ZERO, |i, acc| i + acc)
            }
        }

        impl<'s> core::iter::Sum<&'s Self> for $op {
            fn sum<I: Iterator<Item = &'s Self>>(iter: I) -> Self {
                iter.fold(crate::primitives::Field::ZERO, |i, acc| i + acc)
            }
        }
    };
}
pub(super) use impl_ops_for_fe;

/// An iterator over the powers of a field, starting from zero.
///
/// This iterator starts from 1, but has an optimized version of [`Iterator::nth`]
/// which allows efficient construction.
pub struct Powers<F: Field> {
    base: F,
    next: F,
}

impl<F: Field> Iterator for Powers<F> {
    type Item = F;

    fn next(&mut self) -> Option<F> {
        let ret = Some(self.next.clone());
        self.next *= &self.base;
        ret
    }

    /// Compute next by calling `F::powi`.
    ///
    /// The default implementation of `nth` will simply call the iterator `n`
    /// times, throwing away the result, which takes O(n) field multiplications.
    /// For a power iterator we can do much better, taking O(log(n)) multiplications.
    ///
    /// This is important because this method is called internally by `Iterator::skip`.
    fn nth(&mut self, n: usize) -> Option<F> {
        let ni64 = (n % F::MULTIPLICATIVE_ORDER) as i64; // cast ok since modulus should be small
        self.next *= self.base.powi(ni64);
        self.next()
    }
}
