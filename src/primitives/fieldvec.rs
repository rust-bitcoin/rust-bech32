// SPDX-License-Identifier: MIT

//! Field Element Vector
//!
//! Provides a nostd-compatible vector for storing field elements. This has
//! an ad-hoc API and some limitations and should *not* be exposed in the
//! public API.
//!
//! Its primary purpose is to be a backing for the `Polynomial` type. The
//! idea is that `FieldVec` will act like a vector of arbitrary objects,
//! but manage alloc/no-alloc weirdness, while `Polynomial` defines all
//! the arithmetic operations without worrying about these things.
//!
//! This is very similar to the `ArrayVec` type from the `arrayvec` crate,
//! with two major differences:
//!
//! * In the case that an allocator is available, switches to being unbounded.
//! * It is specialized to field elements, and provides a number of utility
//!   functions and constructors specifically for that case.
//!
//! Because it stores field elements, and fields always have a zero element,
//! we can avoid working with uninitialized memory by setting "undefined"
//! values to zero. There is theoretically a performance cost here, but
//! given that our arrays are limited in size to low tens of elements, it
//! is unlikely for this to be measurable.
//!
//! The purpose of this vector is to be a backing for the various (reduced)
//! polynomials we encounter when processing BCH codes. These polynomials
//! have degree <= the degree of the generator polynomial, whose degree
//! in turn is a small integer (6 for bech32, 8 for descriptors, and 13
//! or 15 for codex32, as examples).
//!
//! An example of a reduced polynomial is the residue computed when
//! validating checksums. Typically, validating a BCH checksum just means
//! computing this residue, comparing it to a target value, and throwing
//! it away. However, we may want to keep the value in two cases:
//!
//! 1. When doing error correction, the residue value encodes the location
//!    and values of the errors (assuming there are not too many).
//! 2. When distinguishing between bech32 and bech32m, which differ only
//!    in their target residues, we may want to know the computed residue
//!    so we can do a manual comparison against both values.
//!
//! Despite these arrays being very small for all checksums we are aware
//! of being practically used, in principle they can be any size, and we
//! don't want to limit our users artificially. We cannot have arbitrary
//! sized objects without an allocator, so we split the difference by
//! using a fixed-size array, and when the user tries to go beyond this,
//! panicking if an allocator is unavailable.
//!
//! Users of this type should take care not to expose this panic to users.
//! This shouldn't be too hard, because this type is internal to the library
//! which has two use cases:
//!
//! 1. Distinguishing bech32 and bech32m residues (within the limit).
//! 2. Doing error correction (should have a small top-level API and easy
//!    to early-detect things outside the limit and return an error).
//!

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;
use core::{iter, mem, ops, slice};

use super::Field;
use crate::primitives::correction::NO_ALLOC_MAX_LENGTH;

/// A vector of field elements.
///
/// Parameterized by the field type `F` which can be anything, but for most methods
/// to be enabled needs `Default` and `Clone`. (Both are implied by `Field`.)
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct FieldVec<F> {
    inner_a: [F; NO_ALLOC_MAX_LENGTH],
    len: usize,
    #[cfg(feature = "alloc")]
    inner_v: Vec<F>,
}

impl<F> FieldVec<F> {
    /// Determines whether the residue is representable, given the current
    /// compilation context.
    ///
    /// For small enough residues (which includes, in particular, bech32 and
    /// bech32m), will always return true. Otherwise, returns true iff the
    /// **alloc** feature is turned on.
    ///
    /// If you just want to panic when this is false, use `assert_has_data`.
    #[inline]
    pub fn has_data(&self) -> bool { self.len <= NO_ALLOC_MAX_LENGTH || cfg!(feature = "alloc") }

    /// Panics if [`Self::has_data`] is false, with an informative panic message.
    #[inline]
    pub fn assert_has_data(&self) {
        assert!(
            self.has_data(),
            "checksums of {} characters (more than {}) require the `alloc` feature of `bech32` to be enabled",
            self.len,
            NO_ALLOC_MAX_LENGTH,
        );
    }

    /// Number of stored field elements
    #[inline]
    pub fn len(&self) -> usize { self.len }

    /// Whether the vector is empty
    #[inline]
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Returns an immutable iterator over the elements in the vector.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::has_data`] is false.
    pub fn iter(&self) -> slice::Iter<F> {
        if self.len > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return self.inner_v[..self.len].iter();
        }
        self.inner_a[..self.len].iter()
    }

    /// Returns a mutable iterator over the elements in the vector.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::has_data`] is false.
    pub fn iter_mut(&mut self) -> slice::IterMut<F> {
        if self.len > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return self.inner_v[..self.len].iter_mut();
        }
        self.inner_a[..self.len].iter_mut()
    }
}

impl<F: Field> FieldVec<F> {
    /// Constructor from the powers of an element, from 0 upward.
    ///
    /// If the **alloc** feature is disabled and `n` exceeds the maximum size for
    /// a no-alloc vector, this method will return a "dead" vector which will
    /// panic if it is used. Users should use [`Self::has_data`] to determine
    /// whether this is the case.
    #[inline]
    pub fn from_powers(elem: F, n: usize) -> Self {
        iter::successors(Some(F::ONE), |gen| Some(elem.clone() * gen)).take(n + 1).collect()
    }

    /// Multiply the elements of two vectors together, pointwise.
    ///
    /// # Panics
    ///
    /// Panics if the vectors are different lengths, or if [`Self::has_data`] is
    /// false for either vector.
    #[inline]
    pub fn mul_assign_pointwise(&mut self, other: &Self) {
        assert_eq!(self.len, other.len, "cannot add vectors of different lengths");
        for (i, fe) in self.iter_mut().enumerate() {
            *fe *= &other[i];
        }
    }

    /// Multiply the elements of two vectors together, pointwise.
    ///
    /// # Panics
    ///
    /// Panics if the vectors are different lengths, or if [`Self::has_data`] is
    /// false for either vector.
    #[inline]
    pub fn mul_pointwise(mut self, other: &Self) -> Self {
        self.mul_assign_pointwise(other);
        self
    }

    #[inline]
    /// Lifts a vector of field elements to a vector of elements in an extension
    /// field, via the inclusion map.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::has_data`] is false.
    pub fn lift<E: Field + From<F>>(&self) -> FieldVec<E> {
        self.iter().cloned().map(E::from).collect()
    }
}

impl<F: Default> FieldVec<F> {
    /// Pushes an item onto the end of the vector.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::has_data`] is false, or if it would be false after the push.
    pub fn push(&mut self, item: F) {
        self.len += 1;
        self.assert_has_data();

        #[cfg(not(feature = "alloc"))]
        {
            self.inner_a[self.len - 1] = item;
        }

        #[cfg(feature = "alloc")]
        if self.len < NO_ALLOC_MAX_LENGTH + 1 {
            self.inner_a[self.len - 1] = item;
        } else {
            if self.len == NO_ALLOC_MAX_LENGTH + 1 {
                let inner_a = mem::take(&mut self.inner_a);
                self.inner_v = inner_a.into();
            }
            self.inner_v.push(item);
        }
    }

    /// Pops an item off the end of the vector.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::has_data`] is false.
    pub fn pop(&mut self) -> Option<F> {
        self.assert_has_data();
        if self.len == 0 {
            return None;
        }

        self.len -= 1;
        #[cfg(not(feature = "alloc"))]
        {
            Some(mem::take(&mut self.inner_a[self.len]))
        }

        #[cfg(feature = "alloc")]
        if self.len < NO_ALLOC_MAX_LENGTH {
            Some(mem::take(&mut self.inner_a[self.len]))
        } else {
            use core::convert::TryFrom;

            let ret = self.inner_v.pop();
            let inner_v = mem::take(&mut self.inner_v);
            match <[F; NO_ALLOC_MAX_LENGTH]>::try_from(inner_v) {
                Ok(arr) => self.inner_a = arr,
                Err(vec) => self.inner_v = vec,
            }
            ret
        }
    }
}

impl<F: Clone + Default> iter::FromIterator<F> for FieldVec<F> {
    /// Constructor from an iterator of elements.
    ///
    /// If the **alloc** feature is disabled and `n` exceeds the maximum size for
    /// a no-alloc vector, this method will return a "dead" vector which will
    /// panic if it is used. Users should use [`Self::has_data`] to determine
    /// whether this is the case.
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = F>,
    {
        let mut iter = iter.into_iter();
        // This goofy map construction is needed because we cannot use the
        // `[F::default(); N]` syntax without adding a `Copy` bound to `F`.
        // After Rust 1.63 we will be able to use array::from_fn.
        let mut inner_a = [(); NO_ALLOC_MAX_LENGTH].map(|_| F::default());
        let mut len = 0;
        for elem in iter.by_ref().take(NO_ALLOC_MAX_LENGTH) {
            inner_a[len] = elem;
            len += 1;
        }
        #[allow(unused_variables)]
        if let Some(next) = iter.next() {
            #[cfg(feature = "alloc")]
            {
                let mut inner_v = inner_a.to_vec();
                inner_v.push(next);
                inner_v.extend(iter);
                Self { inner_a, len: inner_v.len(), inner_v }
            }
            #[cfg(not(feature = "alloc"))]
            {
                // Create a dead FieldVec that will fail Self::has_data.
                // It is still useful to be able to construct these, in
                // order to populate the InvalidResidueError type.
                // Accessors on that type must check its validity before
                // using the vector.
                Self { len: inner_a.len() + 1 + iter.count(), inner_a }
            }
        } else {
            Self {
                inner_a,
                len,
                #[cfg(feature = "alloc")]
                inner_v: Vec::default(),
            }
        }
    }
}

impl<'a, F> IntoIterator for &'a FieldVec<F> {
    type Item = &'a F;
    type IntoIter = slice::Iter<'a, F>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.iter() }
}

impl<'a, F> IntoIterator for &'a mut FieldVec<F> {
    type Item = &'a mut F;
    type IntoIter = slice::IterMut<'a, F>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.iter_mut() }
}

impl<F> ops::Index<usize> for FieldVec<F> {
    type Output = F;
    fn index(&self, index: usize) -> &F {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &self.inner_v[..self.len][index];
        }
        &self.inner_a[..self.len][index]
    }
}

impl<F> ops::Index<ops::Range<usize>> for FieldVec<F> {
    type Output = [F];
    fn index(&self, index: ops::Range<usize>) -> &[F] {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &self.inner_v[..self.len][index];
        }
        &self.inner_a[..self.len][index]
    }
}

impl<F> ops::Index<ops::RangeFrom<usize>> for FieldVec<F> {
    type Output = [F];
    fn index(&self, index: ops::RangeFrom<usize>) -> &[F] {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &self.inner_v[..self.len][index];
        }
        &self.inner_a[..self.len][index]
    }
}

impl<F> ops::Index<ops::RangeTo<usize>> for FieldVec<F> {
    type Output = [F];
    fn index(&self, index: ops::RangeTo<usize>) -> &[F] {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &self.inner_v[..self.len][index];
        }
        &self.inner_a[..self.len][index]
    }
}

impl<F> ops::Index<ops::RangeFull> for FieldVec<F> {
    type Output = [F];
    fn index(&self, index: ops::RangeFull) -> &[F] {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &self.inner_v[..self.len][index];
        }
        &self.inner_a[..self.len][index]
    }
}

impl<F> ops::IndexMut<usize> for FieldVec<F> {
    fn index_mut(&mut self, index: usize) -> &mut F {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &mut self.inner_v[..self.len][index];
        }
        &mut self.inner_a[..self.len][index]
    }
}

impl<F> ops::IndexMut<ops::Range<usize>> for FieldVec<F> {
    fn index_mut(&mut self, index: ops::Range<usize>) -> &mut [F] {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &mut self.inner_v[..self.len][index];
        }
        &mut self.inner_a[..self.len][index]
    }
}

impl<F> ops::IndexMut<ops::RangeFrom<usize>> for FieldVec<F> {
    fn index_mut(&mut self, index: ops::RangeFrom<usize>) -> &mut [F] {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &mut self.inner_v[..self.len][index];
        }
        &mut self.inner_a[..self.len][index]
    }
}

impl<F> ops::IndexMut<ops::RangeTo<usize>> for FieldVec<F> {
    fn index_mut(&mut self, index: ops::RangeTo<usize>) -> &mut [F] {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &mut self.inner_v[..self.len][index];
        }
        &mut self.inner_a[..self.len][index]
    }
}

impl<F> ops::IndexMut<ops::RangeFull> for FieldVec<F> {
    fn index_mut(&mut self, index: ops::RangeFull) -> &mut [F] {
        if self.len() > NO_ALLOC_MAX_LENGTH {
            self.assert_has_data();
            #[cfg(feature = "alloc")]
            return &mut self.inner_v[..self.len][index];
        }
        &mut self.inner_a[..self.len][index]
    }
}