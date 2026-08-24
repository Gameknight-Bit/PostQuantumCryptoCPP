// R_q = Z_q[x]/(x^n+1): the polynomial ring Ring-LWE operates over.
// Built directly on Zq<T> -- each Rq<T> is just n coefficients, each one
// a Zq<T>, with multiplication defined by negacyclic convolution
// (reduction using x^n = -1).

use crate::zq::{Zq, ZqLimb};
use rand::distributions::uniform::SampleUniform;
use rand_distr::{Distribution, Normal};
use rand::Rng;

/// An element of R_q = Z_q[x]/(x^n+1). `coeffs[i]` is the coefficient of
/// x^i; `n = coeffs.len()` and `q` (implicit, carried by each Zq) are
/// fixed for the lifetime of the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rq<T: ZqLimb> {
    pub coeffs: Vec<Zq<T>>,
}

impl<T: ZqLimb> Rq<T> {
    pub fn zero(n: usize, q: T) -> Self {
        let z = Zq::new(T::from_i128(0), q);
        Rq {coeffs: vec![z; n]}
    }

    pub fn n(&self) -> usize {
        self.coeffs.len()
    }

    pub fn modulus(&self) -> T {
        self.coeffs[0].modulus()
    }

    fn ck_compatible(&self, other: &Self) {
        debug_assert_eq!(self.coeffs.len(), other.coeffs.len(), "ring elements have different degree n");
        debug_assert_eq!(self.modulus(), other.modulus(), "ring elements have different moduli");
    }

    pub fn add(&self, rhs: &Self) -> Self {
        self.ck_compatible(rhs);
        let coeffs = self.coeffs.iter().zip(rhs.coeffs.iter()).map(|(&a, &b)| a + b).collect();
        Rq { coeffs }
    }
 
    pub fn sub(&self, rhs: &Self) -> Self {
        self.ck_compatible(rhs);
        let coeffs = self.coeffs.iter().zip(rhs.coeffs.iter()).map(|(&a, &b)| a - b).collect();
        Rq { coeffs }
    }

    /// Negacyclic convolution: multiplication in Z_q[x]/(x^n+1).
    /// Naive O(n^2) approach. An
    /// NTT-based O(n log n) multiply is the natural upgrade once n grows
    /// and q is chosen NTT-friendly (q = 1 mod 2n); not needed yet.
    pub fn mul(&self, rhs: &Self) -> Self {
        self.ck_compatible(rhs);
        let n = self.coeffs.len();
        let q = self.modulus();
        let zero = Zq::new(T::from_i128(0), q);
        let mut acc = vec![zero; n];
 
        for i in 0..n {
            for j in 0..n {
                let prod = self.coeffs[i] * rhs.coeffs[j];
                let deg = i + j;
                if deg < n {
                    acc[deg] = acc[deg] + prod;
                } else {
                    // x^n = -1, so x^(n+k) = -x^k: fold the overflow
                    // term back in with a sign flip.
                    acc[deg - n] = acc[deg - n] - prod;
                }
            }
        }
        Rq { coeffs: acc }
    }
}

/// Sample a uniformly random ring element (every coefficient uniform
/// mod q, independently).
pub fn sample_uniform_ring<T, R>(rng: &mut R, n: usize, q: T) -> Rq<T>
where
    T: ZqLimb + SampleUniform + PartialOrd,
    R: Rng + ?Sized,
{
    let coeffs = (0..n).map(|_| Zq::new(rng.gen_range(T::from_i128(0)..q), q)).collect();
    Rq { coeffs }
}

/// Sample a "small" ring element by drawing each coefficient
/// independently from the given error sampler (rounded discrete
/// Gaussian). Used for both the secret `s` and the noise terms
/// `e`, `r`, `e1`, `e2` -- in textbook LPR they're all drawn from
/// the same distribution chi.
pub fn sample_error_ring<T, R>(rng: &mut R, sampler: &Normal<f64>, n: usize, q: T) -> Rq<T>
where
    T: ZqLimb,
    R: Rng + ?Sized,
{
    let coeffs = (0..n).map(|_| Zq::from_signed(sampler.sample(rng).round() as i64, q)).collect();
    Rq { coeffs }
}

/// Encode up to n bits into a ring element, each bit scaled to 0 or
/// floor(q/2) -- the same trick as plain LWE's single-bit encoding,
/// applied independently per coefficient. This is what lets one Ring-LWE
/// ciphertext carry n bits instead of one.
pub fn encode_bits<T: ZqLimb>(bits: &[bool], n: usize, q: T) -> Rq<T> {
    debug_assert!(bits.len() <= n, "too many bits for ring degree n");
    let half_q = Zq::new(T::from_i128(q.to_i128() / 2), q);
    let zero = Zq::new(T::from_i128(0), q);
    let coeffs = (0..n)
        .map(|i| if i < bits.len() && bits[i] { half_q } else { zero })
        .collect();
    Rq { coeffs }
}
 
/// Decode a ring element back to bits: per-coefficient threshold against
/// [q/4, 3q/4], identical logic to the plain-LWE decrypt_bit comparison,
/// just run once per coefficient instead of once total.
pub fn decode_bits<T: ZqLimb>(poly: &Rq<T>) -> Vec<bool> {
    poly.coeffs
        .iter()
        .map(|c| {
            let v = c.value().to_i128();
            let q = c.modulus().to_i128();
            v >= q / 4 && v <= (3 * q) / 4
        })
        .collect()
}



