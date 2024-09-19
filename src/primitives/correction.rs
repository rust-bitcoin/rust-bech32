// SPDX-License-Identifier: MIT

//! Error Correction
//!
//! Implements the Berlekamp-Massey algorithm to locate errors, with Forney's
//! equation to identify the error values, in a BCH-encoded string.
//!

use core::convert::TryInto;
use core::marker::PhantomData;

use crate::primitives::decode::{
    CheckedHrpstringError, ChecksumError, InvalidResidueError, SegwitHrpstringError,
};
use crate::primitives::{Field as _, FieldVec, LfsrIter, Polynomial};
#[cfg(feature = "alloc")]
use crate::DecodeError;
use crate::{Checksum, Fe32};

/// **One more than** the maximum length (in characters) of a checksum which
/// can be error-corrected without an allocator.
///
/// When the **alloc** feature is enabled, this constant is practically irrelevant.
/// When the feature is disabled, it represents a length beyond which this library
/// does not support error correction.
///
/// If you need this value to be increased, please file an issue describing your
/// usecase. Bear in mind that an increased value will increase memory usage for
/// all users, and the focus of this library is the Bitcoin ecosystem, so we may
/// not be able to accept your request.
// This constant is also used when comparing bech32 residues against the
// bech32/bech32m targets, which should work with no-alloc. Therefore this
// constant must be > 6 (the length of the bech32(m) checksum).
//
// Otherwise it basically represents a tradeoff between stack usage and the
// size of error types, vs functionality in a no-alloc setting. The value
// of 7 covers bech32 and bech32m. To get the descriptor checksum we need a
// value and the descriptor checksum. To also get codex32 it should be >13,
// and for "long codex32" >15 ... but consider that no-alloc contexts are
// likely to be underpowered and will struggle to do correction on these
// big codes anyway.
//
// Perhaps we will want to add a feature gate, off by default, that boosts
// this to 16, or maybe even higher. But we will wait for implementors who
// complain.
pub const NO_ALLOC_MAX_LENGTH: usize = 7;

/// Trait describing an error for which an error correction algorithm is applicable.
///
/// Essentially, this trait represents an error which contains an [`InvalidResidueError`]
/// variant.
pub trait CorrectableError {
    /// Given a decoding error, if this is a "checksum failed" error, extract
    /// that specific error type.
    ///
    /// There are many ways in which decoding a checksummed string might fail.
    /// If the string was well-formed in all respects except that the final
    /// checksum characters appear to be wrong, it is possible to run an
    /// error correction algorithm to attempt to extract errors.
    ///
    /// In all other cases we do not have enough information to do correction.
    ///
    /// This is the function that implementors should implement.
    fn residue_error(&self) -> Option<&InvalidResidueError>;

    /// Wrapper around [`Self::residue_error`] that outputs a correction context.
    ///
    /// Will return None if the error is not a correctable one, or if the **alloc**
    /// feature is disabled and the checksum is too large. See the documentation
    /// for [`NO_ALLOC_MAX_LENGTH`] for more information.
    ///
    /// This is the function that users should call.
    fn correction_context<Ck: Checksum>(&self) -> Option<Corrector<Ck>> {
        #[cfg(not(feature = "alloc"))]
        if Ck::CHECKSUM_LENGTH >= NO_ALLOC_MAX_LENGTH {
            return None;
        }

        self.residue_error().map(|e| Corrector { residue: e.residue(), phantom: PhantomData })
    }
}

impl CorrectableError for InvalidResidueError {
    fn residue_error(&self) -> Option<&InvalidResidueError> { Some(self) }
}

impl CorrectableError for ChecksumError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            ChecksumError::InvalidResidue(ref e) => Some(e),
            _ => None,
        }
    }
}

impl CorrectableError for SegwitHrpstringError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            SegwitHrpstringError::Checksum(ref e) => e.residue_error(),
            _ => None,
        }
    }
}

impl CorrectableError for CheckedHrpstringError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            CheckedHrpstringError::Checksum(ref e) => e.residue_error(),
            _ => None,
        }
    }
}

#[cfg(feature = "alloc")]
impl CorrectableError for crate::segwit::DecodeError {
    fn residue_error(&self) -> Option<&InvalidResidueError> { self.0.residue_error() }
}

#[cfg(feature = "alloc")]
impl CorrectableError for DecodeError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            DecodeError::Checksum(ref e) => e.residue_error(),
            _ => None,
        }
    }
}

/// An error-correction context.
pub struct Corrector<Ck> {
    residue: Polynomial<Fe32>,
    phantom: PhantomData<Ck>,
}

impl<Ck: Checksum> Corrector<Ck> {
    /// Returns an iterator over the errors in the string.
    ///
    /// Returns `None` if it can be determined that there are too many errors to be
    /// corrected. However, returning an iterator from this function does **not**
    /// imply that the intended string can be determined. It only implies that there
    /// is a unique closest correct string to the erroneous string, and gives
    /// instructions for finding it.
    ///
    /// If the input string has sufficiently many errors, this unique closest correct
    /// string may not actually be the intended string.
    pub fn bch_errors(&self) -> Option<ErrorIterator<Ck>> {
        // 1. Compute all syndromes by evaluating the residue at each power of the generator.
        let syndromes: FieldVec<_> = Ck::ROOT_GENERATOR
            .powers_range(Ck::ROOT_EXPONENTS)
            .map(|rt| self.residue.evaluate(&rt))
            .collect();

        // 2. Use the Berlekamp-Massey algorithm to find the connection polynomial of the
        //    LFSR that generates these syndromes. For magical reasons this will be equal
        //    to the error locator polynomial for the syndrome.
        let lfsr = LfsrIter::berlekamp_massey(&syndromes[..]);
        let conn = lfsr.coefficient_polynomial();

        // 3. The connection polynomial is the error locator polynomial. Use this to get
        //    the errors.
        let max_correctable_errors =
            (Ck::ROOT_EXPONENTS.end() - Ck::ROOT_EXPONENTS.start() + 1) / 2;
        if conn.degree() <= max_correctable_errors {
            Some(ErrorIterator {
                evaluator: conn.mul_mod_x_d(
                    &Polynomial::from(syndromes),
                    Ck::ROOT_EXPONENTS.end() - Ck::ROOT_EXPONENTS.start() + 1,
                ),
                locator_derivative: conn.formal_derivative(),
                inner: conn.find_nonzero_distinct_roots(Ck::ROOT_GENERATOR),
                a: Ck::ROOT_GENERATOR,
                c: *Ck::ROOT_EXPONENTS.start(),
            })
        } else {
            None
        }
    }
}

/// An iterator over the errors in a string.
///
/// The errors will be yielded as `(usize, Fe32)` tuples.
///
/// The first component is a **negative index** into the string. So 0 represents
/// the last element, 1 the second-to-last, and so on.
///
/// The second component is an element to **add to** the element at the given
/// location in the string.
///
/// The maximum index is one less than [`Checksum::CODE_LENGTH`], regardless of the
/// actual length of the string. Therefore it is not safe to simply subtract the
/// length of the string from the returned index; you must first check that the
/// index makes sense. If the index exceeds the length of the string or implies that
/// an error occurred in the HRP, the string should simply be rejected as uncorrectable.
///
/// Out-of-bound error locations will not occur "naturally", in the sense that they
/// will happen with extremely low probability for a string with a valid HRP and a
/// uniform error pattern. (The probability is 32^-n, where n is the size of the
/// range [`Checksum::ROOT_EXPONENTS`], so it is not neglible but is very small for
/// most checksums.) However, it is easy to construct adversarial inputs that will
/// exhibit this behavior, so you must take it into account.
///
/// Out-of-bound error locations may occur naturally in the case of a string with a
/// corrupted HRP, because for checksumming purposes the HRP is treated as twice as
/// many field elements as characters, plus one. If the correct HRP is known, the
/// caller should fix this before attempting error correction. If it is unknown,
/// the caller cannot assume anything about the intended checksum, and should not
/// attempt error correction.
pub struct ErrorIterator<Ck: Checksum> {
    evaluator: Polynomial<Ck::CorrectionField>,
    locator_derivative: Polynomial<Ck::CorrectionField>,
    inner: super::polynomial::RootIter<Ck::CorrectionField>,
    a: Ck::CorrectionField,
    c: usize,
}

impl<Ck: Checksum> Iterator for ErrorIterator<Ck> {
    type Item = (usize, Fe32);

    fn next(&mut self) -> Option<Self::Item> {
        // Compute -i, which is the location we will return to the user.
        let neg_i = match self.inner.next() {
            None => return None,
            Some(0) => 0,
            Some(x) => Ck::ROOT_GENERATOR.multiplicative_order() - x,
        };

        // Forney's equation, as described in https://en.wikipedia.org/wiki/BCH_code#Forney_algorithm
        //
        // It is rendered as
        //
        //                   a^i evaluator(a^-i)
        //     e_k = - ---------------------------------
        //              a^(ci) locator_derivative(a^-i)
        //
        // where here a is `Ck::ROOT_GENERATOR`, c is the first element of the range
        // `Ck::ROOT_EXPONENTS`, and both evalutor and locator_derivative are polynomials
        // which are computed when constructing the ErrorIterator.

        let a_i = self.a.powi(neg_i as i64);
        let a_neg_i = a_i.clone().multiplicative_inverse();

        let num = self.evaluator.evaluate(&a_neg_i) * &a_i;
        let den = a_i.powi(self.c as i64) * self.locator_derivative.evaluate(&a_neg_i);
        let ret = -num / den;
        match ret.try_into() {
            Ok(ret) => Some((neg_i, ret)),
            Err(_) => unreachable!("error guaranteed to  lie in base field"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::decode::SegwitHrpstring;
    use crate::Bech32;

    #[test]
    fn bech32() {
        // Last x should be q
        let s = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx";
        match SegwitHrpstring::new(s) {
            Ok(_) => panic!("{} successfully, and wrongly, parsed", s),
            Err(e) => {
                let ctx = e.correction_context::<Bech32>().unwrap();
                let mut iter = ctx.bch_errors().unwrap();

                assert_eq!(iter.next(), Some((0, Fe32::X)));
                assert_eq!(iter.next(), None);
            }
        }

        // f should be z, 6 chars from the back.
        let s = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzfwf5mdq";
        match SegwitHrpstring::new(s) {
            Ok(_) => panic!("{} successfully, and wrongly, parsed", s),
            Err(e) => {
                let ctx = e.correction_context::<Bech32>().unwrap();
                let mut iter = ctx.bch_errors().unwrap();

                assert_eq!(iter.next(), Some((6, Fe32::T)));
                assert_eq!(iter.next(), None);
            }
        }

        // 20 characters from the end there is a q which should be 3
        let s = "bc1qar0srrr7xfkvy5l64qlydnw9re59gtzzwf5mdq";
        match SegwitHrpstring::new(s) {
            Ok(_) => panic!("{} successfully, and wrongly, parsed", s),
            Err(e) => {
                let ctx = e.correction_context::<Bech32>().unwrap();
                let mut iter = ctx.bch_errors().unwrap();

                assert_eq!(iter.next(), Some((20, Fe32::_3)));
                assert_eq!(iter.next(), None);
            }
        }

        // Two errors.
        let s = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mxx";
        match SegwitHrpstring::new(s) {
            Ok(_) => panic!("{} successfully, and wrongly, parsed", s),
            Err(e) => {
                let ctx = e.correction_context::<Bech32>().unwrap();
                assert!(ctx.bch_errors().is_none());
            }
        }
    }
}
