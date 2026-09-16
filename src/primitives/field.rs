// SPDX-License-Identifier: MIT

//! Generic Field Traits

use core::convert::{TryFrom as _, TryInto};
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
    fn muli(&self, n: i64) -> Self {
        let mut base = if n >= 0 { self.clone() } else { -self.clone() };
        let mut n = n.unsigned_abs();

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
                    // Just an optimization, fine if this doesn't run for large x on obscure
                    // systems where usize won't cast to u64.
                    if let Ok(x) = u64::try_from(x) {
                        n %= x;
                    }
                }

                while n > 0 {
                    if n & 1 == 1 {
                        ret += &base;
                    }
                    base += base.clone();
                    n >>= 1;
                }
                ret
            }
        }
    }

    /// Takes the element to the power of some unsigned integer.
    fn powu(&self, mut n: u64) -> Self {
        if *self == Self::ZERO {
            // Special-case 0^n and early-return before we manipulate `n` at all.
            if n == 0 {
                return Self::ONE;
            } else {
                return Self::ZERO;
            }
        }

        // Just an optimization, fine if this doesn't run for large x on obscure
        // systems where usize won't cast to u64.
        if let Ok(x) = u64::try_from(Self::MULTIPLICATIVE_ORDER) {
            n %= x;
        }

        let mut ret = Self::ONE;
        let mut base = self.clone();
        while n > 0 {
            if n & 1 == 1 {
                ret *= &base;
            }
            base *= base.clone();
            n >>= 1;
        }
        ret
    }

    /// Takes the element to the power of some signed integer.
    ///
    /// # Panics
    ///
    /// Panics if `self` is the zero element and `n` is less than 0.
    fn powi(&self, n: i64) -> Self {
        let base = if n >= 0 { self.clone() } else { self.clone().multiplicative_inverse() };
        let n = n.unsigned_abs();
        base.powu(n)
    }

    /// The multiplicative order of an element.
    fn multiplicative_order(&self) -> usize {
        for &ord in Self::MULTIPLICATIVE_ORDER_FACTORS {
            // This `expect` cannot be hit on any real system.
            let ord64 = u64::try_from(ord).expect("multiplicative order in excess of 2^64 - 1");
            if self.powu(ord64) == Self::ONE {
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

    /// Compute next by calling `F::powu`.
    ///
    /// The default implementation of `nth` will simply call the iterator `n`
    /// times, throwing away the result, which takes O(n) field multiplications.
    /// For a power iterator we can do much better, taking O(log(n)) multiplications.
    ///
    /// This is important because this method is called internally by `Iterator::skip`.
    fn nth(&mut self, n: usize) -> Option<F> {
        let n = u64::try_from(n).expect("multiplicative order in excess of 2^64 - 1");
        self.next *= self.base.powu(n);
        self.next()
    }
}

#[cfg(test)]
#[cfg(target_pointer_width = "64")]
pub(crate) mod large_odd_field {
    use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

    use super::*;

    /// Integers mod 9223372036854778487 which is 2^63 + 2679.
    ///
    /// Unlike the fields actually used by this library, this (a) has odd characteristic so that
    /// addition and negation are different, and (b) has characteristic > 2^63 so that any naive
    /// generic operations will trigger overflows.
    #[derive(Copy, Clone, PartialEq, Eq, Debug, Default, Hash)]
    pub struct LargeOddFe(u64);

    impl LargeOddFe {
        pub const MODULUS: u64 = 9_223_372_036_854_778_487;

        pub const fn new(n: u64) -> Self { Self(n % Self::MODULUS) }

        fn reduce(n: u128) -> Self { Self((n % Self::MODULUS as u128) as u64) }
    }

    impl Field for LargeOddFe {
        const ZERO: Self = Self(0);
        const ONE: Self = Self(1);
        const GENERATOR: Self = Self(5); // checked with sage
        const CHARACTERISTIC: usize = 9_223_372_036_854_778_487;
        const MULTIPLICATIVE_ORDER: usize = 9_223_372_036_854_778_486;
        const MULTIPLICATIVE_ORDER_FACTORS: &'static [usize] =
            &[1, 2, 4_611_686_018_427_389_243, 9_223_372_036_854_778_486];

        fn multiplicative_inverse(self) -> Self {
            assert_ne!(self, Self::ZERO, "division by zero");
            self.powu(Self::MODULUS - 2)
        }
    }

    impl fmt::Display for LargeOddFe {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
    }

    macro_rules! impl_op {
        ($op:ident, $method:ident, $assign:ident, $assign_method:ident,
         |$a:ident, $b:ident| $body:expr) => {
            impl $op for LargeOddFe {
                type Output = Self;

                fn $method(self, rhs: Self) -> Self {
                    let ($a, $b) = (self, rhs);
                    $body
                }
            }

            impl $op<&LargeOddFe> for LargeOddFe {
                type Output = Self;

                fn $method(self, rhs: &Self) -> Self { self.$method(*rhs) }
            }

            impl $assign for LargeOddFe {
                fn $assign_method(&mut self, rhs: Self) { *self = (*self).$method(rhs); }
            }

            impl $assign<&LargeOddFe> for LargeOddFe {
                fn $assign_method(&mut self, rhs: &Self) { *self = (*self).$method(*rhs); }
            }
        };
    }

    impl_op!(Add, add, AddAssign, add_assign, |a, b| {
        LargeOddFe::reduce(a.0 as u128 + b.0 as u128)
    });

    impl_op!(Sub, sub, SubAssign, sub_assign, |a, b| {
        LargeOddFe::reduce(a.0 as u128 + LargeOddFe::MODULUS as u128 - b.0 as u128)
    });

    impl_op!(Mul, mul, MulAssign, mul_assign, |a, b| {
        LargeOddFe::reduce(a.0 as u128 * b.0 as u128)
    });

    impl_op!(Div, div, DivAssign, div_assign, |a, b| a * b.multiplicative_inverse());

    impl Neg for LargeOddFe {
        type Output = Self;

        fn neg(self) -> Self {
            if self.0 == 0 {
                self
            } else {
                Self(Self::MODULUS - self.0)
            }
        }
    }

    impl iter::Sum for LargeOddFe {
        fn sum<I: Iterator<Item = Self>>(iter: I) -> Self { iter.fold(Self::ZERO, |a, b| a + b) }
    }

    impl<'a> iter::Sum<&'a LargeOddFe> for LargeOddFe {
        fn sum<I: Iterator<Item = &'a LargeOddFe>>(iter: I) -> Self { iter.copied().sum() }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_pointer_width = "64")]
    use super::large_odd_field::LargeOddFe as Fe;
    use super::*;
    use crate::Fe32;

    #[test]
    #[allow(clippy::iter_nth_zero)] // we are testing this
    fn zero_pow() {
        assert_eq!(Fe32::ZERO.powi(0), Fe32::ONE);
        assert_eq!(Fe32::ZERO.powi(31), Fe32::ZERO);
        assert_eq!(Fe32::ZERO.powu(0), Fe32::ONE);
        assert_eq!(Fe32::ZERO.powu(31), Fe32::ZERO);
        assert_eq!(Fe32::ZERO.powers().take(2).collect::<Vec<_>>(), vec![Fe32::ONE, Fe32::ZERO]);
        assert_eq!(Fe32::ZERO.powers().nth(0), Some(Fe32::ONE));
        assert_eq!(Fe32::ZERO.powers().nth(31), Some(Fe32::ZERO));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn multiplicative_order_supports_large_factors() {
        assert_eq!(Fe::GENERATOR.multiplicative_order(), Fe::MULTIPLICATIVE_ORDER,);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn powers_nth_preserves_large_unsigned_exponents() {
        let exponent = 1usize << 63;
        let expected = Fe::new(7_725_530_454_779_639_848); // checked with sage
        assert_eq!(Fe::GENERATOR.powers().nth(exponent), Some(expected));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn muli_large_field() {
        assert_eq!(Fe::new(0).muli(-1), Fe::new(0));
        assert_eq!(Fe::new(1).muli(-1), Fe::new(Fe::MODULUS - 1));
        assert_eq!(Fe::new(1), Fe::new(Fe::MODULUS - 1).muli(-1));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn muli_i64_min() {
        assert_eq!(Fe::new(0).muli(i64::MIN), Fe::new(0));
        assert_eq!(Fe::new(1).muli(i64::MIN), Fe::new(2679));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn powu_large_field() {
        assert_eq!(Fe::new(1).powu(0), Fe::new(1));
        assert_eq!(Fe::new(100).powu(0), Fe::new(1));
        assert_eq!(Fe::new(Fe::MODULUS - 10_000).powu(0), Fe::new(1));

        assert_eq!(Fe::new(1).powu(1), Fe::new(1));

        assert_eq!(Fe::new(2).powu(5), Fe::new(32));

        assert_eq!(Fe::new(1 << 9).powu(7), Fe::new(Fe::MODULUS - 2679));
        assert_eq!(Fe::new(1 << 9).powu(14), Fe::new(2679 * 2679));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn powi_large_field() {
        assert_eq!(Fe::new(1).powi(0), Fe::new(1));
        assert_eq!(Fe::new(100).powi(0), Fe::new(1));
        assert_eq!(Fe::new(Fe::MODULUS - 10_000).powi(0), Fe::new(1));

        assert_eq!(Fe::new(1).powi(-1), Fe::new(1));
        assert_eq!(Fe::new(1).powi(1), Fe::new(1));

        assert_eq!(Fe::new(2).powi(5), Fe::new(32));

        assert_eq!(Fe::new(1 << 9).powi(7), Fe::new(Fe::MODULUS - 2679));
        assert_eq!(Fe::new(1 << 9).powi(14), Fe::new(2679 * 2679));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn powi_i64_min() {
        assert_eq!(Fe::new(1).powi(i64::MIN), Fe::new(1));
        assert_eq!(Fe::new(Fe::MODULUS - 1).powi(i64::MIN), Fe::new(1));
    }
}
