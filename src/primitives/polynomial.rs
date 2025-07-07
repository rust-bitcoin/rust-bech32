// SPDX-License-Identifier: MIT

//! Polynomials over Finite Fields

use core::{cmp, fmt, iter, ops, slice};

use super::checksum::PackedFe32;
use super::{ExtensionField, Field, FieldVec};
use crate::Fe32;

/// A polynomial over some field.
#[derive(Clone, Debug)]
pub struct Polynomial<F> {
    /// The coefficients of the polynomial, in "little-endian" order.
    /// That is the constant term is at index 0.
    inner: FieldVec<F>,
}

impl<F: Field> PartialEq for Polynomial<F> {
    fn eq(&self, other: &Self) -> bool { self.coefficients() == other.coefficients() }
}

impl<F: Field> Eq for Polynomial<F> {}

impl Polynomial<Fe32> {
    pub fn from_residue<R: PackedFe32>(residue: R) -> Self {
        (0..R::WIDTH).map(|i| Fe32(residue.unpack(i))).collect()
    }
}
impl<F: Field> Polynomial<F> {
    /// Determines whether the residue is representable, given the current
    /// compilation context.
    pub fn has_data(&self) -> bool { self.inner.has_data() }

    /// Panics if [`Self::has_data`] is false, with an informative panic message.
    pub fn assert_has_data(&self) { self.inner.assert_has_data() }

    /// Provides access to the underlying [`FieldVec`].
    pub fn into_inner(self) -> FieldVec<F> { self.inner }

    /// Provides access to the underlying [`FieldVec`].
    pub fn as_inner(&self) -> &FieldVec<F> { &self.inner }

    /// Constructs a polynomial from a slice of field elements, prepending
    /// a 1 value to produce a monic polynomial.
    pub fn with_monic_leading_term(coeffs: &[F]) -> Self {
        let mut inner: FieldVec<_> = coeffs.iter().rev().cloned().collect();
        inner.push(F::ONE);
        Polynomial { inner }
    }

    /// The degree of the polynomial.
    ///
    /// For constants it will return zero, including for the constant zero.
    pub fn degree(&self) -> usize {
        debug_assert_ne!(self.inner.len(), 0, "polynomials never have no terms");
        let degree_without_leading_zeros = self.inner.len() - 1;
        let leading_zeros = self.inner.iter().rev().take_while(|el| **el == F::ZERO).count();
        degree_without_leading_zeros.saturating_sub(leading_zeros)
    }

    /// Accessor for the coefficients of the polynomial, in "little endian" order.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::has_data`] is false.
    pub fn coefficients(&self) -> &[F] { &self.inner[..self.degree() + 1] }

    /// An iterator over the coefficients of the polynomial.
    ///
    /// Yields value in "little endian" order; that is, the constant term is returned first.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::has_data`] is false.
    pub fn iter(&self) -> slice::Iter<'_, F> {
        self.assert_has_data();
        self.coefficients().iter()
    }

    /// The leading term of the polynomial.
    ///
    /// For the constant 0 polynomial, will return 0.
    pub fn leading_term(&self) -> F {
        for term in self.inner.iter().rev() {
            if *term != F::ZERO {
                return term.clone();
            }
        }
        F::ZERO
    }

    /// Whether 0 is a root of the polynomial. Equivalently, whether `x` is a
    /// factor of the polynomial.
    pub fn zero_is_root(&self) -> bool { self.inner.is_empty() || self.leading_term() == F::ZERO }

    /// Computes the formal derivative of the polynomial
    pub fn formal_derivative(&self) -> Self {
        self.iter().enumerate().map(|(n, fe)| fe.muli(n as i64)).skip(1).collect()
    }

    /// Helper function to add leading 0 terms until the polynomial has a specified
    /// length.
    fn zero_pad_up_to(&mut self, len: usize) {
        while self.inner.len() < len {
            self.inner.push(F::default());
        }
    }

    /// An iterator over the roots of the polynomial.
    ///
    /// Takes a base element `base`. The roots of the residue will be yielded as
    /// nonnegative integers between 0 and 1 less than the order of the base,
    /// inclusive. If `base` is a primitive element of the extension field, then
    /// all distinct roots (in the extension field) will be found.
    ///
    /// Iterates via Chien search, which is a form of brute force. Internally it
    /// will do as many iterations as the multiplicative order of `base`, regardless
    /// of how many roots are actually found.
    ///
    /// Only roots which are a power of `base` are returned, so if `base` is *not*
    /// a primitive element then not all roots may be returned.
    ///
    /// This will **not** return 0 as a root under any circumstances. To check
    /// whether zero is a root of the polynomial, run [`Self::zero_is_root`].
    ///
    /// # Panics
    ///
    /// Panics if [`Self::has_data`] is false.
    pub fn find_nonzero_distinct_roots<E: Field + From<F>>(&self, base: E) -> RootIter<E> {
        self.inner.assert_has_data();

        RootIter {
            idx: 0,
            max_idx: base.multiplicative_order(),
            base_powers: FieldVec::from_powers(base, self.inner.len() - 1),
            polynomial: self.inner.lift(),
        }
    }

    /// Evaluate the polynomial at a given element.
    pub fn evaluate<E: Field + From<F>>(&self, elem: &E) -> E {
        let mut res = E::ZERO;
        for fe in self.iter().rev() {
            res *= elem;
            res += E::from(fe.clone());
        }
        res
    }

    /// TODO
    pub fn convolution(&self, syndromes: &Self) -> Self {
        let mut ret = FieldVec::new();
        let terms = (1 + syndromes.inner.len()).saturating_sub(1 + self.degree());
        if terms == 0 {
            ret.push(F::ZERO);
            return Self::from(ret);
        }

        let n = 1 + self.degree();
        for idx in 0..terms {
            ret.push(
                (0..n).map(|i| self.inner[n - i - 1].clone() * &syndromes.inner[idx + i]).sum(),
            );
        }
        Self::from(ret)
    }

    /// Multiplies two polynomials modulo x^d, for some given `d`.
    ///
    /// Can be used to simply multiply two polynomials, by passing `usize::MAX` or
    /// some other suitably large number as `d`.
    pub fn mul_mod_x_d(&self, other: &Self, d: usize) -> Self {
        if d == 0 {
            return Self { inner: FieldVec::new() };
        }

        let sdeg = self.degree();
        let odeg = other.degree();

        let convolution_product = |exp: usize| {
            let sidx = exp.saturating_sub(sdeg);
            let eidx = cmp::min(exp, odeg);
            (sidx..=eidx).map(|i| self.inner[exp - i].clone() * &other.inner[i]).sum()
        };

        let max_n = cmp::min(sdeg + odeg + 1, d - 1);
        (0..=max_n).map(convolution_product).collect()
    }

    /// Given a BCH generator polynomial, find an element alpha that maximizes the
    /// consecutive range i..j such that `alpha^i `through `alpha^j` are all roots
    /// of the polynomial.
    ///
    /// (Despite the name, the returned element might not actually be a primitive
    /// element. For a "primitive BCH code" it will be, but in general not. But
    /// there is no standard name for the element this function returns, and
    /// "primitive element" is suggestive.)
    ///
    /// # Panics
    ///
    /// Panics if there are fewer roots than the degree of the polynomial, or if
    /// the longest geometric series in the roots appears to be of the form
    /// alpha*beta^i where alpha is not 1. Either situation indicates that your
    /// BCH generator polynomial is weird in some way, and you should file a bug
    /// or (more likely) fix your polynomial.
    ///
    /// # Returns
    ///
    /// Returns a primitive element, its order (which is the length of the code),
    /// and the longest range of exponents of the element which are roots of the
    /// polynomial. For the avoidance of doubt it returns a [`ops::RangeInclusive`]
    /// (syntax `a..=b`) rather than the more-common [`ops::Range`] (syntax `a..b`).
    /// Both endpoints are included in the set of values.
    ///
    /// Internally this function analyzes the roots in an arbitrary (randomized)
    /// order, and therefore may return different values on consecutive runs. If
    /// there is a particular "elegant" value you are looking for, it may be
    /// worthwhile to run the function multiple times.
    pub fn bch_generator_primitive_element<E: ExtensionField<BaseField = F>>(
        &self,
    ) -> (E, usize, ops::RangeInclusive<usize>) {
        let roots: FieldVec<usize> = self.find_nonzero_distinct_roots(E::GENERATOR).collect();
        debug_assert!(roots.len() <= self.degree());
        // debug_assert!(roots.is_sorted()); // nightly only API
        assert_eq!(
            self.degree() + usize::from(self.zero_is_root()),
            roots.len(),
            "Found {} roots ({:?}) for a polynomial of degree {}; polynomial appears not to split.",
            roots.len(),
            roots,
            self.degree(),
        );

        // Brute-force (worst case n^3*log(n) in the length of the polynomial) the longest
        // geometric series within the set of roots. The common ratio between these
        // roots will be our primitive element.
        //
        // We also learn the length of the series and the first root in the series.

        let mut max_length = 0; // length of the max-length geometric series
        let mut max_start = 0; // i such that the max-length series starts with gen^i
        let mut max_ratio = 0; // i such that the ratio between terms is gen^i

        for i in 0..roots.len() {
            for j in 0..roots.len() {
                if i == j {
                    continue;
                }
                let r1 = roots[i];
                let mut r2 = roots[j];

                let ratio = (E::MULTIPLICATIVE_ORDER + r2 - r1) % E::MULTIPLICATIVE_ORDER;
                // To avoid needing alloc, we binary-search the slice rather than
                // putting the roots into a HashSet or something so we can O(1)
                // search them. In practice this doesn't matter because we have
                // such a small number of roots (it may actually be faster than
                // using a hashset) and because the root-finding takes such a
                // long time that noboby can use this method in a loop anyway.
                let mut len = 2;
                while let Ok(k) = roots[..].binary_search(&((r2 + ratio) % E::MULTIPLICATIVE_ORDER))
                {
                    len += 1;
                    r2 = roots[k];
                }

                if len > max_length {
                    max_length = len;
                    max_start = roots[i];
                    max_ratio = ratio;
                }
            }
        }

        let prim_elem = E::GENERATOR.powi(max_ratio as i64);
        let code_len = prim_elem.multiplicative_order();
        // We have the primitive element (prim_elem) and the first element in the
        // series with that ratio (GENERATOR ** max_start). But we want to know
        // an exponent i such that GENERATOR ** max_start = prim_elem ** i.
        //
        // It may occur that no such i exists, if the entire series is in a coset
        // of the group generated by prim_elem. In *theory* this means that we
        // should go back and find the second-longest geometric series and try
        // that, because for a real-life BCH code this situation indicates that
        // something is wrong and we should just panic.
        let initial_elem = E::GENERATOR.powi(max_start as i64);
        let mut min_index = None;
        let mut base = E::ONE;
        for i in 0..code_len {
            if base == initial_elem {
                min_index = Some(i);
            }
            base *= &prim_elem;
        }
        let min_index = match min_index {
            Some(idx) => idx,
            None => panic!("Found geometric series within roots starting from {} (ratio {} length {}), but the series does not consist of powers of the ratio.", initial_elem, prim_elem, max_length),
        };

        // We write `a..=b - 1` instead of `a..b` because RangeInclusive is actually
        // a different type than Range, so the two syntaxes are not equivalent here.
        (prim_elem, code_len, min_index..=min_index + max_length - 1)
    }
}

impl<F: Field> fmt::Display for Polynomial<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.has_data() {
            for fe in self.iter() {
                write!(f, "{}", fe)?;
            }
            Ok(())
        } else {
            f.write_str("<residue>")
        }
    }
}

impl<F: Field> iter::FromIterator<F> for Polynomial<F> {
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = F>,
    {
        Polynomial { inner: FieldVec::from_iter(iter) }
    }
}

impl<F> From<FieldVec<F>> for Polynomial<F> {
    fn from(inner: FieldVec<F>) -> Self { Self { inner } }
}

impl<F: Field> ops::Add<&Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;

    fn add(mut self, other: &Polynomial<F>) -> Polynomial<F> {
        self += other;
        self
    }
}

impl<F: Field> ops::Add<Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;
    fn add(self, other: Polynomial<F>) -> Polynomial<F> { self + &other }
}

impl<F: Field> ops::Sub<&Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;
    fn sub(mut self, other: &Polynomial<F>) -> Polynomial<F> {
        self -= other;
        self
    }
}

impl<F: Field> ops::Sub<Polynomial<F>> for Polynomial<F> {
    type Output = Polynomial<F>;
    fn sub(self, other: Polynomial<F>) -> Polynomial<F> { self - &other }
}

impl<F: Field> ops::AddAssign<&Polynomial<F>> for Polynomial<F> {
    fn add_assign(&mut self, other: &Self) {
        self.zero_pad_up_to(other.inner.len());
        for i in 0..other.inner.len() {
            self.inner[i] += &other.inner[i];
        }
    }
}

impl<F: Field> ops::AddAssign for Polynomial<F> {
    fn add_assign(&mut self, other: Polynomial<F>) { *self += &other; }
}

impl<F: Field> ops::SubAssign<&Polynomial<F>> for Polynomial<F> {
    fn sub_assign(&mut self, other: &Polynomial<F>) {
        self.zero_pad_up_to(other.inner.len());
        for i in 0..other.inner.len() {
            self.inner[i] -= &other.inner[i];
        }
    }
}

impl<F: Field> ops::SubAssign for Polynomial<F> {
    fn sub_assign(&mut self, other: Polynomial<F>) { *self -= &other; }
}

/// An iterator over the roots of a polynomial.
///
/// This iterator is constructed by the [`Polynomial::find_nonzero_distinct_roots`]
/// method, which takes a field element as a base. The roots of the
/// polynomial are yielded as exponents of the base. See the documentation
/// of that method for more information.
pub struct RootIter<F> {
    idx: usize,
    max_idx: usize,
    base_powers: FieldVec<F>,
    polynomial: FieldVec<F>,
}

impl<F: Field> Iterator for RootIter<F> {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        // A zero-length polynomial has no nonzero roots. Special-case this
        // so that we can freely index the first coefficient of the polynomial.
        if self.polynomial.is_empty() {
            return None;
        }

        while self.idx < self.max_idx {
            let sum = self.polynomial.iter().sum::<F>();
            self.polynomial.mul_assign_pointwise(&self.base_powers);
            self.idx += 1;
            if sum == F::ZERO {
                return Some(self.idx - 1);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use Fe32 as F;

    use super::*;
    use crate::{Fe1024, Fe32};

    #[test]
    #[cfg(feature = "alloc")]
    fn roots() {
        #[rustfmt::skip]
        let mut bip93_poly = Polynomial::with_monic_leading_term(
            &[F::E, F::M, F::_3, F::G, F::Q, F::E, F::E, F::E, F::L, F::M, F::C, F::S, F::S]
        );

        assert_eq!(bip93_poly.leading_term(), F::P);
        assert!(!bip93_poly.zero_is_root());
        assert_eq!(bip93_poly.degree(), 13);

        bip93_poly.zero_pad_up_to(1000); // should have no visible effect

        let (elem, order, root_indices) = bip93_poly.bch_generator_primitive_element::<Fe1024>();
        // Basically, only the order and the length of the `root_indices` range are
        // guaranteed to be consistent across runs. There will be two possible ranges,
        // a "low" one (in this case 9..16) and a "high one" (77..84) whose generator
        // is the multiplicative inverse of the small one. These correspond to the
        // fact that for any order-93 element, e^x = (e^-1)^(93 - x).
        //
        // Then in addition to the element/inverse symmetry, for this polynomial there
        // is also an entire second generator which can produce the same set of roots.
        // So we get that one and _its_ inverse.
        //
        // Also, BTW, the range 77..84 appears in the Appendix to BIP93 so you can
        // verify its correctness there.
        assert_eq!(order, 93);
        // These next three assertions just illustrate the above comment...
        assert_eq!(
            Fe1024::new([Fe32::Q, Fe32::_9]).multiplicative_inverse(),
            Fe1024::new([Fe32::G, Fe32::G]),
        );
        assert_eq!(
            Fe1024::new([Fe32::Q, Fe32::_9]).powi(9),
            Fe1024::new([Fe32::G, Fe32::G]).powi(84),
        );
        assert_eq!(
            Fe1024::new([Fe32::Q, Fe32::_9]).powi(16),
            Fe1024::new([Fe32::G, Fe32::G]).powi(77),
        );
        // ...and these ones are actual unit tests.
        //
        // (In the actual implementation, which is now deterministic, only one of
        // these if branches will ever be taken (I think the first). But all of them
        // are algebraically valid and we reserve the right to change which one we
        // return.)
        if elem == Fe1024::new([Fe32::_9, Fe32::_9]) {
            assert_eq!(root_indices, 9..=16);
        } else if elem == Fe1024::new([Fe32::Q, Fe32::G]) {
            assert_eq!(root_indices, 77..=84);
        } else if elem == Fe1024::new([Fe32::Q, Fe32::_9]) {
            assert_eq!(root_indices, 9..=16);
        } else if elem == Fe1024::new([Fe32::G, Fe32::G]) {
            assert_eq!(root_indices, 77..=84);
        } else {
            panic!("Unexpected generator {}", elem);
        }
    }

    #[test]
    fn roots_bech32() {
        // Exactly the same test as above, but for bech32
        let bech32_poly =
            Polynomial::with_monic_leading_term(&[F::A, F::K, F::_5, F::_4, F::A, F::J]);

        assert_eq!(
            bech32_poly.iter().copied().collect::<Vec<_>>(),
            [F::J, F::A, F::_4, F::_5, F::K, F::A, F::P],
        );

        let (elem, order, root_indices) = bech32_poly.bch_generator_primitive_element::<Fe1024>();
        // As above, only the order and the length of the `root_indices` range are
        // guaranteed to be consistent across runs. There will be two possible ranges,
        // a "low" one (in this case 24..27) and a "high one" (997..1000) whose generator
        // is the multiplicative inverse of the small one. These correspond to the
        // fact that for any order-1023 element, e^x = (e^-1)^(1023 - x).
        assert_eq!(order, 1023);
        // This assertion just illustrate the above comment...
        assert_eq!(
            Fe1024::new([Fe32::P, Fe32::X]).multiplicative_inverse(),
            Fe1024::new([Fe32::_7, Fe32::F]),
        );
        // ...and these ones are actual unit tests.
        if elem == Fe1024::new([Fe32::P, Fe32::X]) {
            assert_eq!(root_indices, 24..=26);
        } else if elem == Fe1024::new([Fe32::_7, Fe32::F]) {
            assert_eq!(root_indices, 997..=999);
        } else {
            panic!("Unexpected generator {}", elem);
        }
    }

    #[test]
    fn mul_mod() {
        let x_minus_1: Polynomial<_> = [Fe32::P, Fe32::P].iter().copied().collect();
        assert_eq!(
            x_minus_1.mul_mod_x_d(&x_minus_1, 3),
            [Fe32::P, Fe32::Q, Fe32::P].iter().copied().collect(),
        );
        assert_eq!(x_minus_1.mul_mod_x_d(&x_minus_1, 2), [Fe32::P].iter().copied().collect(),);
    }

    #[test]
    #[cfg(feature = "alloc")] // needed since `mul_mod_x_d` produces extra 0 coefficients
    fn factor_then_mul() {
        let bech32_poly: Polynomial<Fe32> = {
            use Fe32 as F;
            [F::J, F::A, F::_4, F::_5, F::K, F::A, F::P]
        }
        .iter()
        .copied()
        .collect();

        let bech32_poly_lift = Polynomial { inner: bech32_poly.inner.lift() };

        let factors = bech32_poly
            .find_nonzero_distinct_roots(Fe1024::GENERATOR)
            .map(|idx| Fe1024::GENERATOR.powi(idx as i64))
            .map(|root| [root, Fe1024::ONE].iter().copied().collect::<Polynomial<_>>())
            .collect::<Vec<_>>();

        let product = factors.iter().fold(
            Polynomial::with_monic_leading_term(&[]),
            |acc: Polynomial<_>, factor: &Polynomial<_>| acc.mul_mod_x_d(factor, 100),
        );
        assert_eq!(bech32_poly_lift, product);
    }
}
