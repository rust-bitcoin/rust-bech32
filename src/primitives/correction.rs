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
    /// `non_hrp_len` is the length of the string to be corrected, including the checksum
    /// but excluding the HRP and the `1` separator. For segwit addresses this is typically
    /// 39 (for p2wpkh) or 59 (for p2wsh and Taproot).
    ///
    /// Will return None if the error is unrelated to checksum validation, or if the **alloc**
    /// feature is disabled and the checksum is too large. See the documentation for
    /// [`NO_ALLOC_MAX_LENGTH`] for more information.
    ///
    /// This is the function that users should call.
    fn correction_context<Ck: Checksum>(&self, non_hrp_len: usize) -> Option<Corrector<Ck>> {
        #[cfg(not(feature = "alloc"))]
        if Ck::CHECKSUM_LENGTH >= NO_ALLOC_MAX_LENGTH {
            return None;
        }

        self.residue_error().filter(|e| e.residue_length_matches::<Ck>()).map(|e| Corrector {
            erasures: FieldVec::new(),
            residue: e.residue(),
            max_index: non_hrp_len,
            phantom: PhantomData,
        })
    }
}

impl CorrectableError for InvalidResidueError {
    fn residue_error(&self) -> Option<&InvalidResidueError> { Some(self) }
}

impl CorrectableError for ChecksumError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            Self::InvalidResidue(ref e) => Some(e),
            _ => None,
        }
    }
}

impl CorrectableError for SegwitHrpstringError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            Self::Checksum(ref e) => e.residue_error(),
            _ => None,
        }
    }
}

impl CorrectableError for CheckedHrpstringError {
    fn residue_error(&self) -> Option<&InvalidResidueError> {
        match self {
            Self::Checksum(ref e) => e.residue_error(),
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
            Self::Checksum(ref e) => e.residue_error(),
            _ => None,
        }
    }
}

/// An error-correction context.
pub struct Corrector<Ck: Checksum> {
    erasures: FieldVec<usize>,
    residue: Polynomial<Fe32>,
    max_index: usize,
    phantom: PhantomData<Ck>,
}

impl<Ck: Checksum> Corrector<Ck> {
    /// A bound on the number of errors and erasures (errors with known location)
    /// that can be corrected by this corrector.
    ///
    /// Returns N such that, given E errors and X erasures, correction is possible
    /// iff 2E + X <= N.
    pub fn singleton_bound(&self) -> usize {
        // d - 1, where d = [number of consecutive roots] + 2
        Ck::ROOT_EXPONENTS.end() - Ck::ROOT_EXPONENTS.start() + 1
    }

    /// Informs the correction context of the location of erasures (known errors).
    ///
    /// These erasures are indexed from the end of the string, so that the final character has
    /// index 0, the one before that index 1, and so on.
    pub fn add_erasures(&mut self, locs: &[usize]) {
        for loc in locs {
            // If the user tries to add too many erasures, just ignore them. In
            // this case error correction is guaranteed to fail anyway, because
            // the user must have exceeded the singleton bound of the checksum
            // before hitting this alloc limit. (Or they are using a large custom
            // checksum that exceeds the alloc limit and which won't work without
            // "alloc" anyway.)
            //
            // Each erasure contributes degree 1 to the "erasure locator" polynomial,
            // whose maximum degree is `NO_ALLOC_MAX_LENGTH - 1`.
            #[cfg(not(feature = "alloc"))]
            if self.erasures.len() == NO_ALLOC_MAX_LENGTH {
                break;
            }
            // Similarly, if the user exceeds the singleton bound, just drop any remaining
            // erasures since we know correction will fail.
            if self.erasures.len() > self.singleton_bound() {
                break;
            }
            self.erasures.push(*loc);
        }
    }

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
    pub fn bch_errors(&self) -> Option<ErrorIterator<'_, Ck>> {
        // Early fail if there are too many erasures.
        if self.erasures.len() > self.singleton_bound() {
            return None;
        }

        // 1. Compute all syndromes by evaluating the residue at each power of the generator.
        let syndromes: Polynomial<_> = Ck::ROOT_GENERATOR
            .powers_range(Ck::ROOT_EXPONENTS)
            .map(|rt| self.residue.evaluate(&rt))
            .collect();

        // 1a. Compute the "Forney syndrome polynomial" which is the product of the syndrome
        //     polynomial and the erasure locator. This "erases the erasures" so that B-M
        //     can find only the errors.
        let mut erasure_locator = Polynomial::with_monic_leading_term(&[]); // 1
        for loc in &self.erasures {
            let factor: Polynomial<_> =
                [Ck::CorrectionField::ONE, -Ck::ROOT_GENERATOR.powi(*loc as i64)]
                    .iter()
                    .cloned()
                    .collect(); // alpha^-ix - 1
            erasure_locator = erasure_locator.mul_mod_x_d(&factor, usize::MAX);
        }
        let forney_syndromes = erasure_locator.convolution(&syndromes);

        // 2. Use the Berlekamp-Massey algorithm to find the connection polynomial of the
        //    LFSR that generates these syndromes. For magical reasons this will be equal
        //    to the error locator polynomial for the syndrome.
        let lfsr = LfsrIter::berlekamp_massey(&forney_syndromes.as_inner()[..]);
        let conn = lfsr.coefficient_polynomial();

        // 3. The connection polynomial is the error locator polynomial. Use this to get
        //    the errors.
        if erasure_locator.degree() + 2 * conn.degree() <= self.singleton_bound() {
            // 3a. Compute the "errata locator" which is the product of the error locator
            //     and the erasure locator. Note that while we used the Forney syndromes
            //     when calling the BM algorithm, in all other cases we use the ordinary
            //     unmodified syndromes.
            let errata_locator = conn.mul_mod_x_d(&erasure_locator, usize::MAX);
            let evaluator = errata_locator.mul_mod_x_d(&syndromes, self.singleton_bound());

            // If we are within the correction radius, it can be shown that the evaluator degree
            // is strictly less than the locator degree. This is a very cheap check, so do it here.
            if evaluator.degree() < errata_locator.degree() {
                let ret = ErrorIterator {
                    evaluator,
                    locator_derivative: errata_locator.formal_derivative(),
                    erasures: &self.erasures[..],
                    errors: conn.find_nonzero_distinct_roots(Ck::ROOT_GENERATOR),
                    a: Ck::ROOT_GENERATOR,
                    c: *Ck::ROOT_EXPONENTS.start(),
                };

                // ...however, if we are outside of the correction radius, several things may still
                // go wrong. In particular, we may have fewer roots than we expect (the locator
                // polynomial is not fully reducible) or we may have roots that lie outside of the
                // base field (our syndromes are "best explained" by some weird object which is not
                // an error pattern).
                //
                // In the latter case, because our iterator terminates early if it would return
                // something not in the base field, our root count will fail. So we don't need to
                // do a separate "not in the base field" check here.
                //
                // Alternately, we may obtain a "valid correction" whose error pattern goes outside
                // the bounds of the string. This is also nonsensical, so we filter it out.
                let n_roots = ret.clone().filter(|(idx, _)| *idx < self.max_index).count();
                if n_roots == errata_locator.degree() {
                    Some(ret)
                } else {
                    None
                }
            } else {
                None
            }
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
/// range [`Checksum::ROOT_EXPONENTS`], so it is not negligible but is very small for
/// most checksums.) However, it is easy to construct adversarial inputs that will
/// exhibit this behavior, so you must take it into account.
///
/// Out-of-bound error locations may occur naturally in the case of a string with a
/// corrupted HRP, because for checksumming purposes the HRP is treated as twice as
/// many field elements as characters, plus one. If the correct HRP is known, the
/// caller should fix this before attempting error correction. If it is unknown,
/// the caller cannot assume anything about the intended checksum, and should not
/// attempt error correction.
pub struct ErrorIterator<'c, Ck: Checksum> {
    evaluator: Polynomial<Ck::CorrectionField>,
    locator_derivative: Polynomial<Ck::CorrectionField>,
    erasures: &'c [usize],
    errors: super::polynomial::RootIter<Ck::CorrectionField>,
    a: Ck::CorrectionField,
    c: usize,
}

impl<Ck: Checksum> Clone for ErrorIterator<'_, Ck> {
    fn clone(&self) -> Self {
        Self {
            evaluator: self.evaluator.clone(),
            locator_derivative: self.locator_derivative.clone(),
            erasures: self.erasures,
            errors: self.errors.clone(),
            a: self.a.clone(),
            c: self.c,
        }
    }
}

impl<Ck: Checksum> Iterator for ErrorIterator<'_, Ck> {
    type Item = (usize, Fe32);

    fn next(&mut self) -> Option<Self::Item> {
        // Compute -i, which is the location we will return to the user.
        let neg_i = if self.erasures.is_empty() {
            match self.errors.next() {
                None => return None,
                Some(0) => 0,
                Some(x) => Ck::ROOT_GENERATOR.multiplicative_order() - x,
            }
        } else {
            let pop = self.erasures[0];
            self.erasures = &self.erasures[1..];
            pop
        };

        // Forney's equation, as described in https://en.wikipedia.org/wiki/BCH_code#Forney_algorithm
        //
        // It is rendered as
        //
        //                       evaluator(a^-i)
        //     e_k = - -----------------------------------------
        //              (a^i)^(c - 1)) locator_derivative(a^-i)
        //
        // where here a is `Ck::ROOT_GENERATOR`, c is the first element of the range
        // `Ck::ROOT_EXPONENTS`, and both evaluator and locator_derivative are polynomials
        // which are computed when constructing the ErrorIterator.
        let a_i = self.a.powi(neg_i as i64);
        let a_neg_i = a_i.clone().multiplicative_inverse();
        let locator_eval = self.locator_derivative.evaluate(&a_neg_i);
        if locator_eval == Ck::CorrectionField::ZERO {
            return None;
        }

        let num = self.evaluator.evaluate(&a_neg_i);
        let den = a_i.powi(self.c as i64 - 1) * locator_eval;

        let ret = -num / den;
        ret.try_into().ok().map(|ret| (neg_i, ret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::decode::{
        CheckedHrpstringError, SegwitHrpstring, SegwitHrpstringError, UncheckedHrpstring,
    };
    use crate::Bech32;

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum Codex32 {}

    impl Checksum for Codex32 {
        type MidstateRepr = u128;
        type CorrectionField = crate::Fe1024;
        const ROOT_GENERATOR: Self::CorrectionField = crate::Fe1024::new([Fe32::_9, Fe32::_9]);
        const ROOT_EXPONENTS: core::ops::RangeInclusive<usize> = 9..=16;
        const CHECKSUM_LENGTH: usize = 13;
        const CODE_LENGTH: usize = 93;
        const GENERATOR_SH: [u128; 5] = [
            0x19dc500ce73fde210,
            0x1bfae00def77fe529,
            0x1fbd920fffe7bee52,
            0x1739640bdeee3fdad,
            0x07729a039cfc75f5a,
        ];
        const TARGET_RESIDUE: u128 = 0x10ce0795c2fd1e62a;
    }

    #[test]
    fn bech32() {
        // Last x should be q
        let s = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx";
        match SegwitHrpstring::new(s) {
            Ok(_) => panic!("{} successfully, and wrongly, parsed", s),
            Err(e) => {
                let mut ctx = e.correction_context::<Bech32>(39).unwrap();
                let mut iter = ctx.bch_errors().unwrap();
                assert_eq!(iter.next(), Some((0, Fe32::X)));
                assert_eq!(iter.next(), None);

                ctx.add_erasures(&[0]);
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
                let mut ctx = e.correction_context::<Bech32>(39).unwrap();
                let mut iter = ctx.bch_errors().unwrap();
                assert_eq!(iter.next(), Some((6, Fe32::T)));
                assert_eq!(iter.next(), None);

                ctx.add_erasures(&[6]);
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
                let ctx = e.correction_context::<Bech32>(39).unwrap();
                let mut iter = ctx.bch_errors().unwrap();

                assert_eq!(iter.next(), Some((20, Fe32::_3)));
                assert_eq!(iter.next(), None);
            }
        }

        // Two errors; cannot correct.
        let s = "bc1qar0srrr7xfkvy5l64qlydnw9re59gtzzwf5mdx";
        match SegwitHrpstring::new(s) {
            Ok(_) => panic!("{} successfully, and wrongly, parsed", s),
            Err(e) => {
                let mut ctx = e.correction_context::<Bech32>(39).unwrap();
                assert!(ctx.bch_errors().is_none());

                // But we can correct it if we inform where an error is.
                ctx.add_erasures(&[0]);
                let mut iter = ctx.bch_errors().unwrap();
                assert_eq!(iter.next(), Some((0, Fe32::X)));
                assert_eq!(iter.next(), Some((20, Fe32::_3)));
                assert_eq!(iter.next(), None);

                ctx.add_erasures(&[20]);
                let mut iter = ctx.bch_errors().unwrap();
                assert_eq!(iter.next(), Some((0, Fe32::X)));
                assert_eq!(iter.next(), Some((20, Fe32::_3)));
                assert_eq!(iter.next(), None);
            }
        }

        // In fact, if we know the locations, we can correct up to 3 errors.
        let s = "bc1q9r0srrr7xfkvy5l64qlydnw9re59gtzzwf5mdx";
        match SegwitHrpstring::new(s) {
            Ok(_) => panic!("{} successfully, and wrongly, parsed", s),
            Err(e) => {
                let mut ctx = e.correction_context::<Bech32>(39).unwrap();
                ctx.add_erasures(&[37, 0, 20]);
                let mut iter = ctx.bch_errors().unwrap();

                assert_eq!(iter.next(), Some((37, Fe32::C)));
                assert_eq!(iter.next(), Some((0, Fe32::X)));
                assert_eq!(iter.next(), Some((20, Fe32::_3)));
                assert_eq!(iter.next(), None);
            }
        }
    }

    #[test]
    fn residue_error() {
        let checksum_error = UncheckedHrpstring::new("A1G7SGD8")
            .expect("vector should parse")
            .validate_checksum::<Bech32>()
            .expect_err("vector should have invalid checksum residue");
        let residue =
            checksum_error.residue_error().expect("checksum error should expose invalid residue");
        assert!(residue.residue_error().is_some(), "invalid residue error should expose itself");

        let checked_checksum = CheckedHrpstringError::Checksum(checksum_error.clone());
        assert!(
            checked_checksum.residue_error().is_some(),
            "checked checksum errors should expose invalid residue"
        );

        let segwit_no_data = SegwitHrpstringError::NoData;
        assert!(segwit_no_data.residue_error().is_none(), "no-data errors are not correctable");

        #[cfg(feature = "alloc")]
        {
            let segwit_checksum = SegwitHrpstringError::Checksum(checksum_error.clone());
            let segwit_decode = crate::segwit::DecodeError(segwit_checksum.clone());
            assert!(
                segwit_decode.residue_error().is_some(),
                "segwit decode wrapper should expose invalid residue"
            );

            let decode_checksum = crate::DecodeError::Checksum(checksum_error.clone());
            assert!(
                decode_checksum.residue_error().is_some(),
                "top-level decode checksum errors should expose invalid residue"
            );
        }
    }

    #[test]
    fn regression_vector_1() {
        // Found by fuzzer. Produces errors that don't live in the base field, causing a panic in
        // ErrorIterator::next. (This happens despite passing the various degree checks, proving
        // that these cheap checks are not sufficient.)
        let e = UncheckedHrpstring::new(
            "bc1awzrzyqr3ja8w7hnja2spmkgfdcgvqwp5sw94af4ngsjecfz0w0pqud7k38",
        )
        .expect("well-formed string")
        .validate_checksum::<crate::Bech32>()
        .expect_err("invalid bech32 string");
        let mut ctx = e.correction_context::<Bech32>(59).unwrap();
        assert!(ctx.bch_errors().is_none(), "cannot correct");
        ctx.add_erasures(&[23]);
        assert!(ctx.bch_errors().is_none(), "cannot correct");
    }

    #[test]
    fn regression_vector_2() {
        // Found by fuzzer. *Should* be correctable. Has one unknown error and one erasure.
        let e = UncheckedHrpstring::new(
            "bc1qwzrryqr3ja8w7hnda2spmkgfdcgvqwp5swz4pf4ngsjecfz0w0pqud7k38",
        )
        .expect("well-formed string")
        .validate_checksum::<crate::Bech32>()
        .expect_err("invalid bech32 string");
        let mut ctx = e.correction_context::<Bech32>(59).unwrap();
        assert!(ctx.bch_errors().is_none(), "cannot correct");
        ctx.add_erasures(&[21]);
        assert!(ctx.bch_errors().is_some(), "should be able to correct");
    }

    #[test]
    fn regression_vector_3() {
        // Found by fuzzer. Two errors plus an erasure. Not correctable, but the error correction
        // logic returns a "correction" that would lie outside of the string.
        let e = UncheckedHrpstring::new(
            "bc1wwzruyqr3ja8w7hnja2spmkgfdcgvqwp5swz4hf4ngsjecfz0w0pqud7k38",
        )
        .expect("well-formed string")
        .validate_checksum::<crate::Bech32>()
        .expect_err("invalid bech32m string");
        let mut ctx = e.correction_context::<Bech32>(59).unwrap();
        assert!(ctx.bch_errors().is_none(), "cannot correct");
        ctx.add_erasures(&[21]);
        assert!(ctx.bch_errors().is_none(), "cannot correct");
    }

    #[test]
    fn regression_vector_4() {
        // Found by ChatGPT 6 Astra (given a specific prompt). This has an uncorrectable pattern
        // of errors that 'corrects' to a single error at exactly the index of the HRP separator.
        // We should refuse to correct this.
        let e = UncheckedHrpstring::new("a1h2d2fd")
            .expect("well-formed string")
            .validate_checksum::<crate::Bech32>()
            .expect_err("invalid bech32 string");
        let ctx = e.correction_context::<Bech32>(6).unwrap();
        assert!(ctx.bch_errors().is_none(), "cannot correct");
    }

    #[test]
    fn regression_vector_5() {
        // Found by fuzzer. This has a single (nontrivial) error, which is covered by an
        // erasure, plus three further erasures, for a total of four -- one more than the
        // singleton bound of 3. The erasure list is processed one at a time, and the
        // decision point is when `erasures.len()` is exactly equal to the bound: we must
        // push the fourth erasure (after which `bch_errors` correctly refuses, since four
        // erasures can never be corrected). Mutants which tighten the break condition to
        // `len == bound` or `len >= bound` stop at three erasures instead -- and since
        // three erasures are within the bound, they would then happily return a
        // "correction". See issue #312.
        let e = UncheckedHrpstring::new(
            "bc1qwzrryqr3ja8w7hnza2spmkgfdcgvqwp5swz4af4ngsjecfz0w0pqud7k38",
        )
        .expect("well-formed string")
        .validate_checksum::<crate::Bech32>()
        .expect_err("invalid bech32 string");

        // With only the first three erasures we are exactly at the bound, and correction
        // succeeds. This is what the mutants would end up doing if given all four.
        let mut ctx = e.correction_context::<Bech32>(59).unwrap();
        ctx.add_erasures(&[42, 23, 19]);
        assert!(ctx.bch_errors().is_some(), "three erasures are exactly at the bound");

        // With all four erasures, we must keep all four (not silently drop the last one)
        // and refuse to correct.
        let mut ctx = e.correction_context::<Bech32>(59).unwrap();
        ctx.add_erasures(&[42, 23, 19, 58]);
        assert!(ctx.bch_errors().is_none(), "four erasures exceed the bound");
    }

    #[test]
    fn regression_vector_6() {
        // Found by fuzzer. This has two unknown errors and no erasures: 2E + X = 4 exceeds
        // the singleton bound of 3, so we refuse to correct. The `+` -> `*` mutant in
        // `bch_errors` instead computes deg(erasure_locator) * 2 * deg(conn) = 0 * 4 = 0,
        // which is trivially within the bound, and accepts -- the resulting "correction"
        // passes all the subsequent degree and root-count checks. With no erasures the
        // left side of the bound check degenerates, which is why this vector is needed.
        // See issue #312.
        let e = UncheckedHrpstring::new(
            "bc1gwzrryqr3ja8w7hnja2spmkgfdcgvqwp5uwz4af4ngsjecfz0w0pqud7k38",
        )
        .expect("well-formed string")
        .validate_checksum::<crate::Bech32>()
        .expect_err("invalid bech32 string");
        let ctx = e.correction_context::<Bech32>(59).unwrap();
        assert!(ctx.bch_errors().is_none(), "two errors cannot be corrected");
    }

    #[test]
    fn regression_vector_7() {
        // Found by fuzzer. One (nontrivial) error marked as an erasure, in a pattern for
        // which deg(evaluator) == deg(errata_locator) == 1. The real code requires the
        // evaluator degree to be *strictly* less than the locator degree; the `<` -> `<=`
        // mutant accepts equality, and this vector's bogus locator has a full set of
        // in-bounds roots, so the mutant would return a correction where we (correctly)
        // return None. See issue #312.
        let e = UncheckedHrpstring::new(
            "bc1s0z6ryqr3ja807hnja2s7mkgfdcgvqwp5swz4ff4ngsjecfz0w0pqud7k38",
        )
        .expect("well-formed string")
        .validate_checksum::<crate::Bech32>()
        .expect_err("invalid bech32 string");
        let mut ctx = e.correction_context::<Bech32>(59).unwrap();
        ctx.add_erasures(&[16]);
        assert!(ctx.bch_errors().is_none(), "cannot correct");
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn regression_vector_8() {
        // Found by fuzzer. Same as `regression_vector_6` but for Codex32, whose singleton
        // bound is 8, and which sits right at the edge of the correction radius: four
        // unknown errors plus one erasure gives 2E + X = 9, just one past the bound. The
        // `+` -> `*` mutant computes 1 * 2 * 4 = 8 <= 8 and accepts; its "correction"
        // passes all the subsequent checks. See issue #312.
        let e = UncheckedHrpstring::new("ms10tes2sxxxxxxxxxxxxxxxxxxxxxwxfxx4nzvcx9kmczlw")
            .expect("well-formed string")
            .validate_checksum::<Codex32>()
            .expect_err("invalid codex32 string");
        let mut ctx = e.correction_context::<Codex32>(55).unwrap();
        ctx.add_erasures(&[17]);
        assert!(ctx.bch_errors().is_none(), "4 errors and 1 erasure exceed the bound of 8");
    }

    #[test]
    fn too_many_erasures_do_not_panic_without_alloc() {
        let checksum_error = UncheckedHrpstring::new("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx")
            .expect("vector should parse")
            .validate_checksum::<Bech32>()
            .expect_err("vector should have an invalid checksum residue");
        let mut ctx = checksum_error
            .correction_context::<Bech32>(39)
            .expect("invalid checksum residue should be correctable");
        let mut erasures = [0; NO_ALLOC_MAX_LENGTH];
        for (idx, loc) in erasures.iter_mut().enumerate() {
            *loc = idx;
        }

        ctx.add_erasures(&erasures);
        let _ = ctx.bch_errors();
    }

    #[test]
    fn wide_invalid_residue_comparison_does_not_panic() {
        let checksum_error =
            UncheckedHrpstring::new("ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlq")
                .expect("vector should parse")
                .validate_checksum::<Codex32>()
                .expect_err("vector should have an invalid checksum residue");

        assert!(!checksum_error
            .residue_error()
            .expect("is a residue error")
            .matches_bech32_checksum());
    }

    #[test]
    fn mismatched_checksum_context_does_not_panic_without_alloc() {
        let checksum_error =
            UncheckedHrpstring::new("ms10testsxxxxxxxxxxxxxxxxxxxxxxxxxx4nzvca9cmczlq")
                .expect("vector should parse")
                .validate_checksum::<Codex32>()
                .expect_err("vector should have an invalid checksum residue");

        assert!(
            checksum_error.correction_context::<Bech32>(45).is_none(),
            "a short mismatched checksum must not materialize an oversized residue"
        );
    }

    /// A checksum that can correct exactly NO_ALLOC_MAX_LENGTH erasures.
    ///
    /// Generated by the `generate_erasure_cap_checksum` test.
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum RsMaxNoAlloc {}
    // Code block generated by Checksum::print_impl polynomial h079f9p target qqqqqp)
    impl Checksum for RsMaxNoAlloc {
        type MidstateRepr = u32; // checksum packs into 30 bits

        type CorrectionField = Fe32;
        const ROOT_GENERATOR: Self::CorrectionField = Fe32::Z;
        const ROOT_EXPONENTS: core::ops::RangeInclusive<usize> = 1..=6;

        const CODE_LENGTH: usize = 31;
        const CHECKSUM_LENGTH: usize = 6;
        const GENERATOR_SH: [u32; 5] = [0x0a92f9f7, 0x152557c7, 0x28da0eae, 0x03a0987c, 0x05d130d1];
        const TARGET_RESIDUE: u32 = 0x00000001;
    }

    #[test]
    fn generate_erasure_cap_checksum() {
        use core::convert::TryFrom as _;

        use crate::primitives::checksum::{PackedFe32 as _, PrintImpl};

        // Make a generator polynomial of the form product_i (x - Z^i) which will have
        // correction field Fe32 (no/trivial extension) and be able to correct exactly
        // n erasures for length n.
        //
        // The resulting code will be remarkably compact, for its correction properties,
        // but have length 31 which is not super useful. But it will let us test edge
        // cases for our NO_ALLOC_MAX_LENGTH logic.
        let mut generator = Polynomial::with_monic_leading_term(&[]);
        for i in 1..=u64::try_from(NO_ALLOC_MAX_LENGTH - 1).expect("lol") {
            let factor = Polynomial::with_monic_leading_term(&[Fe32::Z.powu(i)]);
            generator = generator.mul_mod_x_d(&factor, usize::MAX);
        }
        assert_eq!(generator.degree(), NO_ALLOC_MAX_LENGTH - 1);

        // Sanity check that the existing RsMaxNoAlloc appears to be this.
        // Weirdly annoying to get the generator from PrintImpl into a Polynomial...
        let actual_generator = (0..NO_ALLOC_MAX_LENGTH - 1)
            .map(|i| Fe32(RsMaxNoAlloc::GENERATOR_SH[0].unpack(i)))
            .chain(core::iter::once(Fe32::P))
            .collect();
        if generator != actual_generator {
            // ...and the reverse direction.
            let mut gen_coeffs = generator.clone().into_inner();
            gen_coeffs.reverse();
            let mut residue = [Fe32::Q; NO_ALLOC_MAX_LENGTH - 1];
            residue[NO_ALLOC_MAX_LENGTH - 2] = Fe32::P;

            println!("{}", PrintImpl::<Fe32>::new("RsMaxNoAlloc", &gen_coeffs[1..], &residue));

            panic!(
                "Mismatch between `RsMaxNoAlloc` checksum and the formula that computes it. \
                 If you changed NO_ALLOC_MAX_LENGTH then you must also update the checksum in \
                 corrections.rs.

                 Generator polynomial: {}\n
                 Computed generator: {}\n",
                actual_generator, generator,
            );
        }
    }

    #[test]
    fn erasure_cap_without_alloc() {
        let bad_string = "rs1ry9x8gqqqq0l7ptm";

        #[cfg(feature = "alloc")]
        {
            let correct = crate::encode::<RsMaxNoAlloc>(
                crate::Hrp::parse_unchecked("rs"),
                &[0; NO_ALLOC_MAX_LENGTH - 1],
            )
            .unwrap();

            // Corrupt the string by changing every character
            let mut correct_b = correct.as_bytes().to_owned();
            for (i, byte) in correct_b.iter_mut().enumerate().skip(3).take(NO_ALLOC_MAX_LENGTH - 1)
            {
                *byte = Fe32(i as u8).to_char() as u8;
            }
            let incorrect = core::str::from_utf8(&correct_b).unwrap();

            if incorrect != bad_string {
                panic!("Please update 'bad_string' to \"{}\"", incorrect);
            }
        }

        let checksum_error = UncheckedHrpstring::new(bad_string)
            .expect("vector should parse")
            .validate_checksum::<RsMaxNoAlloc>()
            .expect_err("vector should have an invalid checksum residue");
        let mut ctx = checksum_error
            .correction_context::<RsMaxNoAlloc>(bad_string.len() - 3)
            .expect("residue should fit the correction context");

        let mut erasures = [0; NO_ALLOC_MAX_LENGTH - 1];
        for (i, erasure) in erasures.iter_mut().enumerate() {
            *erasure = bad_string.len() - 4 - i;
        }
        ctx.add_erasures(&erasures);
        let mut iter = ctx.bch_errors().expect("# of erasures exactly at the bound, correctable");
        for i in 0..erasures.len() {
            assert_eq!(
                iter.next(),
                Some((bad_string.len() - 4 - i, Fe32(3 + i as u8))),
                "error at {}",
                i
            );
        }
        assert_eq!(iter.next(), None, "exactly six errors");

        // Asking for `NO_ALLOC_MAX_LENGTH` erasures must not panic, but nor should it work.
        let mut ctx = checksum_error.correction_context::<RsMaxNoAlloc>(15).unwrap();
        ctx.add_erasures(&[0, 1, 2, 3, 4, 5, 6]);
        assert!(ctx.bch_errors().is_none(), "7 erasures exceed the singleton bound of 6");
    }
}
