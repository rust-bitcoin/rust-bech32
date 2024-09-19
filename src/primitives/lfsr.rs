// SPDX-License-Identifier: MIT

//! Linear-Feedback Shift Registers
//!
//! A core part of our error-correction algorithm is the Berlekamp-Massey algorithm
//! for finding shift registers. A shift register is a collection of values along
//! with a rule (a particular linear combination) used to generate the next value.
//! When the next value is generated, it is added to the end and everything shifted
//! to the left, with the first value removed from the register and returned.
//!
//! For example, any linear recurrence relation, such as that for the Fibonacci
//! numbers, can be described as a shift register (`a_n = a_{n-1} + a_{n-2}`).
//!
//! This module contains the general Berlekamp-Massey algorithm, from Massey's
//! 1969 paper, implemented over a generic field.

#[cfg(feature = "alloc")]
use alloc::collections::VecDeque;

use super::{Field, FieldVec, Polynomial};

/// An iterator which returns the output of a linear-feedback-shift register
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LfsrIter<F: Field> {
    #[cfg(feature = "alloc")]
    contents: VecDeque<F>,
    #[cfg(not(feature = "alloc"))]
    contents: FieldVec<F>,
    /// The coefficients are internally represented as a polynomial so that
    /// they can be returned as such for use in error correction.
    ///
    /// However, they really aren't a polynomial but rather a list of
    /// coefficients of a linear transformation. Within the algorithm
    /// they are always treated as a FieldVec, by calling `self.coeffs.as_inner`.
    coeffs: Polynomial<F>,
}

impl<F: Field> LfsrIter<F> {
    /// Accessor for the coefficients used to compute the next element.
    pub fn coefficients(&self) -> &[F] { &self.coeffs.as_inner()[1..] }

    /// Accessor for the coefficients used to compute the next element.
    pub(super) fn coefficient_polynomial(&self) -> &Polynomial<F> { &self.coeffs }

    /// Create a minimal LFSR iterator that generates a set of initial
    /// contents, using Berlekamp's algorithm.
    ///
    /// # Panics
    ///
    /// Panics if given an empty list of initial contents.
    pub fn berlekamp_massey(initial_contents: &[F]) -> LfsrIter<F> {
        assert_ne!(initial_contents.len(), 0, "cannot create a LFSR with no initial contents");

        // Step numbers taken from Massey 1969 "Shift-register synthesis and BCH decoding"
        // PDF: https://crypto.stanford.edu/~mironov/cs359/massey.pdf
        //
        // The notation in that paper is super confusing. It uses polynomials in
        // `D`, uses `x` as an integer (the difference between the length of the
        // connection polynomial and the length of the previous connection
        // polynomial), uses `n` as a constant bound and `N` as a counter up to `n`.
        //
        // It also manually accounts for various values which are implicitly
        // always equal to the lengths of polynomials.

        // Step 1 (init)
        // `conn` and `last_conn` are `C(D)` and `B(D)` respectively, in BE order.
        let mut conn = FieldVec::<F>::with_capacity(1 + initial_contents.len());
        let mut old_conn = FieldVec::<F>::with_capacity(1 + initial_contents.len());
        let mut old_d = F::ONE; // `b` in the paper
        let mut x = 1;

        conn.push(F::ONE);
        old_conn.push(F::ONE);

        // Step 2-6 (loop)
        for n in 0..initial_contents.len() {
            assert_eq!(conn[0], F::ONE, "we always maintain a monic polynomial");
            // Step 2
            // Compute d = s_n + sum C_i s_{n - i}, which is the difference between
            // what our current LSFR computes and the actual next initial value.
            // Since we always have C_0 = 1 we can compute this as sum C_i s_{n-i}
            // for all i ranging from 0 to the length of C.
            let d = conn
                .iter()
                .cloned()
                .zip(initial_contents.iter().take(1 + n).rev())
                .map(|(a, b)| a * b)
                .sum::<F>();

            if d == F::ZERO {
                // Step 3: if d == 0, i.e. we correctly computed the next value,
                // just increase our shift and iterate.
                x += 1;
            } else {
                let db_inv = d.clone() / &old_d;
                assert_eq!(db_inv.clone() * &old_d, d, "tried to compute {:?}/{:?}", d, old_d);
                // If d != 0, we need to adjust our connection polynomial, which we do
                // by subtracting a shifted multiplied version of our "old" connection
                // polynomial.
                //
                // Here the "old" polynomial is the one we had before the last length
                // change. The algorithm in the paper determines whether a length change
                // is needed via the auxiliary variable L, which is initially set to 0
                // and then set to L <- n + 1 - L each time we increase the length.
                //
                // By an annoying recursive argument it can be shown that L, thus set,
                // is always equal to `conn.len()`. This assignment corresponds to a
                // length increase exactly when `L < n + 1 - L` or `2L <= n`, so the
                // algorithm determines when a length increase is needed by comparing
                // 2L to n.
                //
                // This is all very clever but entirely pointless and doesn't even show
                // up in the proof of the algorithm (which instead has the English text
                // "if a change in length is needed"). Instead we can use x and a little
                // bit of arithmetic to directly compute the change in length and decide
                // whether it is > 0.
                let poly_add_length = old_conn.len() + x;
                if poly_add_length <= conn.len() {
                    // Step 4
                    for i in 0..old_conn.len() {
                        conn[i + x] -= db_inv.clone() * &old_conn[i];
                    }
                    x += 1;
                } else {
                    // Step 5
                    let tmp = conn.clone();
                    for _ in conn.len()..poly_add_length {
                        conn.push(F::ZERO);
                    }
                    for i in 0..old_conn.len() {
                        conn[i + x] -= db_inv.clone() * &old_conn[i];
                    }
                    old_conn = tmp;
                    old_d = d;
                    x = 1;
                }
            }
        }
        // The connection polynomial has an initial monic term. For use as a LFSR we
        // need to be a bit careful about this, since it is implicit in the formula
        // for generating output from the shift register. So e.g. when generating
        // our initial contents we use `conn.len() - 1` to get "the number of nontrivial
        // coefficients", and in self.coefficients() we skip the monic term.
        //
        // In fact, if the purpose of this type were just to be a LFSR-based iterator,
        // we could drop the monic term entirely. But since for error correction we
        // instead want to extract the connection polynomial and treat it as an actual
        // polynomial, we need to keep it.

        // Copy conn.len() (less the monic term) initial elements into the LSFR.
        let contents = initial_contents.iter().take(conn.len() - 1).cloned().collect();
        LfsrIter { contents, coeffs: conn.into() }
    }
}

impl<F: Field> Iterator for LfsrIter<F> {
    type Item = F;
    fn next(&mut self) -> Option<F> {
        debug_assert_eq!(self.contents.len(), self.coefficients().len());

        let next = self
            .coefficients()
            .iter()
            .zip(self.contents.iter().rev())
            .map(|(a, b)| a.clone() * b)
            .sum();

        let ret = self.contents.pop_front();
        self.contents.push_back(next);
        ret // will always be Some
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Fe32;

    #[test]
    fn berlekamp_massey_constant() {
        for elem in LfsrIter::berlekamp_massey(&[Fe32::ONE, Fe32::ONE]).take(10) {
            assert_eq!(elem, Fe32::ONE);
        }

        for elem in LfsrIter::berlekamp_massey(&[Fe32::J, Fe32::J]).take(10) {
            assert_eq!(elem, Fe32::J);
        }

        // If we just give B-M a *single* element, it'll use that as the connection
        // polynomial and return a series of increasing powers of that element.
        let mut expect = Fe32::J;
        for elem in LfsrIter::berlekamp_massey(&[Fe32::J]).take(10) {
            assert_eq!(elem, expect);
            expect *= Fe32::J;
        }
    }

    #[test]
    fn berlekamp_massey_fibonacci() {
        for elem in LfsrIter::berlekamp_massey(&[Fe32::P, Fe32::P]).take(10) {
            assert_eq!(elem, Fe32::P);
        }

        // In a characteristic-2 field we can only really generate the parity of
        // the fibonnaci sequence, but that in itself is kinda interesting.
        let parities: Vec<_> =
            LfsrIter::berlekamp_massey(&[Fe32::P, Fe32::P, Fe32::Q]).take(10).collect();
        assert_eq!(
            parities,
            [
                Fe32::P,
                Fe32::P,
                Fe32::Q,
                Fe32::P,
                Fe32::P,
                Fe32::Q,
                Fe32::P,
                Fe32::P,
                Fe32::Q,
                Fe32::P
            ],
        );
    }

    #[test]
    fn berlekamp_massey() {
        // A few test vectors that I was able to trigger interesting coverage
        // with using the fuzzer.

        // Does a length change of more than 1 in a single iteration.
        LfsrIter::berlekamp_massey(&[Fe32::Q, Fe32::P]).take(10).count();

        // Causes old_conn.len + x to be less than conn.len (so naively subtracting
        // these to check for a length increase will trigger an overflow). Hits the
        // the "2L <= N" path with x != L.
        LfsrIter::berlekamp_massey(&[Fe32::Q, Fe32::Y, Fe32::H]).take(10).count();

        // Hits the the "2L <= N" path with x != L, without overflowing subtraction
        // as in the above vector.
        LfsrIter::berlekamp_massey(&[Fe32::Y, Fe32::H, Fe32::Q, Fe32::Q]).take(10).count();

        // Triggers a length change with x != n + 1 - ell. The reason you might expect
        // this is that ell is initially set to 0, then re-set to (n + 1 - ell) on each
        // length change, i.e. it is a "count of how much n+1 increased since the last
        // length change".
        //
        // Meanwhile, x is incremented on each iteration but reset to 1 on each length
        // change. These assignment patterns sound very similar, but they are not the
        // same, because the initial values and +1s are not the same.
        LfsrIter::berlekamp_massey(&[Fe32::P, Fe32::P, Fe32::Y, Fe32::Q, Fe32::Q]).take(10).count();
    }
}
