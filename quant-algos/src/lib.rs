//use nalgebra as na;
pub mod zq;
pub mod bitcodec;
pub mod ring;

use core::fmt;

use zq::{Zq, dot, add};
use ring::{Rq};
use bitcodec::BitCodec;
use rand::{Rng, thread_rng};
use rand_distr::{Distribution, Normal};

use crate::ring::{sample_error_ring, sample_uniform_ring, encode_bits};

/// Learning With Errors - Public Key Cryptosystem ///
/// Based on Regev's proposed system in http://portal.acm.org/citation.cfm?id=1060590.1060603

pub type LWEPubKeyTy = Vec<(Vec<Zq<u64>>, Zq<u64>)>;
pub type LWEPrivKeyTy = Vec<Zq<u64>>;
pub type LWEBitCiphertext = (Vec<Zq<u64>>, Zq<u64>);
pub type LWEStringCiphertext = Vec<(Vec<Zq<u64>>, Zq<u64>)>;

#[derive(Clone, Copy)]
pub struct LWEParams {
    n: usize,
    m: usize,
    q: u64
}

pub struct LWESystem {
    public_key: LWEPubKeyTy,
    private_key: LWEPrivKeyTy,
    params: LWEParams
} 

impl LWESystem {
    /* --- Key Generation Functions --- */
    /// Uses Crypto safe rust thread_rng to generate both private and public keys
    /// key_gen assumes safe n, m, q, and sigma have been chosen in accordance to Regev's correctness proof
    pub fn key_gen(n: usize, m: usize, q: u64, sigma: f64) -> Self {
        Self::key_gen_with_rng(&mut thread_rng(), n, m, q, sigma)
    }

    //Uses Custom RNG to generate both private and public keys
    pub fn key_gen_with_rng<R: Rng + ?Sized>(rng: &mut R, n: usize, m: usize, q: u64, sigma: f64) -> Self {
        debug_assert!(q as usize >= n*n, "q should be a prime larger than around n^2 (and usually less than 2n^2");

        // Private Key Gen: Zq^n generated uniformly at random //
        let private_key: LWEPrivKeyTy = (0..n).map(|_| Zq::new(rng.gen_range(0..q), q)).collect();

        // Public Key Gen: m (n length vector + one error) pairs generated uniformly at random //
        let m_vecs: Vec<Vec<Zq<u64>>> = (0..m)
            .map(|_| (0..n)
                .map(|_| Zq::new(rng.gen_range(0..q), q)).collect()
            ).collect();

        //Error sampling arround the gaussian
        let sampler = Normal::new(0.0, sigma).expect("sigma must be finite and > 0");
        let errs: Vec<i64> = (0..m).map(|_| sampler.sample(rng).round() as i64).collect();
        let bs: Vec<Zq<u64>> = m_vecs
            .iter()
            .zip(errs.iter())
            .map(|(row, &e)| {
                let dot_prod = dot(&private_key, row, q);
                Zq::from_signed(dot_prod.to_signed() + e, q)
            })
            .collect();

        //Pack Public Key
        let public_key: LWEPubKeyTy = m_vecs.into_iter().zip(bs.into_iter()).collect();
        
        //Pack Parameters for Enc and Dec
        let params = LWEParams {n, m, q};

        LWESystem {public_key, private_key, params}
    }

    //Expose Public Key (and Parameters) for decryption of Ciphertexts
    pub fn public_key(&self) -> &LWEPubKeyTy { &self.public_key }
    pub fn params(&self) -> LWEParams { self.params }

    //ONLY FOR DEBUGGING/TESTING DO NOT EXPOSE TO PUBLIC
    pub fn private_key(&self) -> &LWEPrivKeyTy { &self.private_key }

    /* --- Encryption and Decryption Functions --- */
    //Encrypt one bit (x_bit=true => x=1 and x_bit=false => x=0)
    //Doesn't require knowledge of private_key
    pub fn encrypt_bit(public_key: &LWEPubKeyTy, params: LWEParams, x_bit: bool) -> LWEBitCiphertext {
        Self::encrypt_bit_with_rng(&mut thread_rng(), public_key, params, x_bit)
    }
    //Encrypt one bit with custom rng
    pub fn encrypt_bit_with_rng<R: Rng + ?Sized>(rng: &mut R, public_key: &LWEPubKeyTy, params: LWEParams, x_bit: bool) -> LWEBitCiphertext {
        debug_assert_eq!(public_key.len(), params.m, "public key length doesn't match params.m");
        let m: usize = params.m;
        let n: usize = params.n;
        let q: u64 = params.q;
        let mask: Vec<bool> = Self::gen_mask(rng, m);
        
        let a: Vec<Zq<u64>> = public_key
            .iter()
            .zip(mask.iter())
            .filter(|(_, incl)| **incl)
            .fold(vec![Zq::new(0, q); n], |acc, ((row, _b), _)| {
                add(&acc, row)
            });

        let sum_b: Zq<u64> = public_key
            .iter()
            .zip(mask.iter())
            .filter(|(_, incl)| **incl)
            .fold(Zq::new(0, q), |acc, ((_row, b), _)| acc + *b);

        let b: Zq<u64> = sum_b + if x_bit {Zq::new(q/2, q)} else {Zq::new(0, q)};
        (a,b)
    }

    //Encrypt bitvector
    //To encrypt structures/types, encode them with BitCodec: see src/bitcodec.rs
    pub fn encrypt<BitTy: BitCodec>(public_key: &LWEPubKeyTy, params: LWEParams, bit_data: BitTy) -> Vec<LWEBitCiphertext>{
        let bitvec = bit_data.to_bits();
        bitvec.iter().map(|&x_bit| Self::encrypt_bit(public_key, params, x_bit)).collect()
    }

    //Decrypt one bit (ret_bit=true => x=1 and ret_bit=false => x=0)
    pub fn decrypt_bit(&self, bit_ciphertext: LWEBitCiphertext) -> bool {
        let q: u64 = self.params.q;

        let (a, b) = bit_ciphertext;
        let dot_prod = dot(&a, &self.private_key, q);
        let res = b - dot_prod;

        res.value() >= q/4 && res.value() <= (3*q)/4
    }

    //Decrypt Cipherstring
    //To Reconstruct more complex structures, reconstruct from their bitvector form with BitCodec: see src/bitcodec.rs
    pub fn decrypt<BitTy: BitCodec>(&self, cipher_string: Vec<LWEBitCiphertext>) -> BitTy {
        let bit_vec: Vec<bool> = cipher_string
            .iter()
            .map(|bit_c| self.decrypt_bit(bit_c.clone()))
            .collect();
        BitCodec::from_bits(&bit_vec).expect("Malformed cipher string, unable to reconstruct from BitType.
        Either cipher string is trying to decrypt from incorrect BitTy, or ciphertext is corrupted.")
    }

    /* Enc and Dec Helpers */
    //Generates bernoulli mask of size m with p=0.5
    fn gen_mask<R: Rng + ?Sized>(rng: &mut R, m: usize) -> Vec<bool> {
        loop {
            let mask: Vec<bool> = (0..m).map(|_| rng.gen_bool(0.5)).collect();
            if mask.iter().any(|&b| b) {
                //only return mask if non_empty case
                return mask;
            }
        }
    }
}

impl fmt::Debug for LWESystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Public Key: {:?}\nPrivate Key: {:?}", self.public_key, self.private_key)
    }
}


// End of Regev's Learning with Errors Systems

/// RING - Learning With Errors - Public Key Cryptosystem ///

pub type RingPubKeyTy = (Rq<u64>, Rq<u64>);
pub type RingPrivKeyTy = Rq<u64>;
pub type RingCiphertext = (Rq<u64>, Rq<u64>);

#[derive(Clone, Copy, Debug)]
pub struct RingParams {
    pub n: usize,
    pub q: u64,
    pub sigma: f64,
}

pub struct RingLWESystem {
    public_key: RingPubKeyTy,
    private_key: RingPrivKeyTy,
    params: RingParams
} 

impl RingLWESystem {
    pub fn key_gen(n: usize, q: u64, sigma: f64) -> Self {
        Self::key_gen_with_rng(&mut thread_rng(), n, q, sigma)
    }

    pub fn key_gen_with_rng<R: Rng + ?Sized>(rng: &mut R, n: usize, q: u64, sigma: f64) -> Self {
        debug_assert!(n.is_power_of_two(), "n must be a power of 2 for x^n+1 to be a cyclotomic polynomial");

        let a = sample_uniform_ring(rng, n, q);
        let sampler = Normal::new(0.0, sigma).expect("sigma must be finite and > 0");
        let s = sample_error_ring(rng, &sampler, n, q);
        let e = sample_error_ring(rng, &sampler, n, q);
        let b = a.mul(&s).add(&e);

        let params = RingParams { n, q, sigma };
        RingLWESystem {
            public_key: (a, b),
            private_key: s,
            params,
        }
    }

    pub fn public_key(&self) -> &RingPubKeyTy {
        &self.public_key
    }
 
    pub fn params(&self) -> RingParams {
        self.params
    }

    pub fn encrypt(public_key: &RingPubKeyTy, params: RingParams, bits: &[bool]) -> RingCiphertext {
        Self::encrypt_with_rng(&mut thread_rng(), public_key, params, bits)
    }

    pub fn encrypt_with_rng<R: Rng + ?Sized>(
        rng: &mut R,
        public_key: &RingPubKeyTy,
        params: RingParams,
        bits: &[bool],
    ) -> RingCiphertext {
        let (a, b) = public_key;
        let n = params.n;
        let q = params.q;
        let sampler = Normal::new(0.0, params.sigma).expect("Sigma should be >= 0");
 
        let r = sample_error_ring(rng, &sampler, n, q);
        let e1 = sample_error_ring(rng, &sampler, n, q);
        let e2 = sample_error_ring(rng, &sampler, n, q);
        let m_prime = encode_bits(bits, n, q);
 
        let u = a.mul(&r).add(&e1);
        let v = b.mul(&r).add(&e2).add(&m_prime);
        (u, v)
    }


}

