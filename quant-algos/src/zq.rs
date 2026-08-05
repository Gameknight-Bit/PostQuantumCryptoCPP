/// Rust implementation of a field on (usually) a prime q on the positive unsigned-integers
/// Simple operations are supported (add, sub, mul, neg, rem)
/// Also simple dot and add is supported for vectors of same length of type Vec<Zq<u64>>

use std::fmt;
use std::ops::{Add, Mul, Neg, Rem, Sub};

//ZqLimb is the primitive type of Zq (can only be u32 or u64)
pub trait ZqLimb: Copy + Eq + fmt::Debug {
    /// A wider unsigned type that can hold the full product of two
    /// `Self` values without overflow (u64 for u32, u128 for u64).
    type Wide: Copy
        + PartialOrd
        + Add<Output = Self::Wide>
        + Sub<Output = Self::Wide>
        + Mul<Output = Self::Wide>
        + Rem<Output = Self::Wide>
        + From<Self>;
 
    fn narrow(wide: Self::Wide) -> Self;
    fn to_i128(self) -> i128;
    fn from_i128(v: i128) -> Self;
}

impl ZqLimb for u32 {
    type Wide = u64;
    fn narrow(wide: u64) -> u32 {
        wide as u32
    }
    fn to_i128(self) -> i128 {
        self as i128
    }
    fn from_i128(v: i128) -> u32 {
        v as u32
    }
}
 
impl ZqLimb for u64 {
    type Wide = u128;
    fn narrow(wide: u128) -> u64 {
        wide as u64
    }
    fn to_i128(self) -> i128 {
        self as i128
    }
    fn from_i128(v: i128) -> u64 {
        v as u64
    }
}


#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Zq<T: ZqLimb> {
    val: T,
    q: T
}

impl<T: ZqLimb> Zq<T> {
    pub fn new(value: T, q: T) -> Self {
        let v = T::Wide::from(value) % T::Wide::from(q);
        Self {val: T::narrow(v), q}
    } 

    pub fn from_signed(val: i64, q: T) -> Self {
        let q128 = q.to_i128();
        let v128 = (val as i128).rem_euclid(q128);
        Zq { val: T::from_i128(v128), q }
    }

    pub fn to_signed(self) -> i64 {
        let q128 = self.q.to_i128();
        let v128 = self.val.to_i128();
        let signed = if v128 > q128 / 2 { v128 - q128 } else { v128 };
        signed as i64
    }

    pub fn value(self) -> T {
        self.val
    }
 
    pub fn modulus(self) -> T {
        self.q
    }

    fn ck_mod(self, rhs: Zq<T>) {
        debug_assert_eq!(self.q, rhs.q, "Both Zq values should have the same moduli!");
    }
}

impl<T: ZqLimb> Add for Zq<T> {
    type Output = Self;
    fn add(self, rhs: Zq<T>) -> Self {
        self.ck_mod(rhs);
        let q_w = T::Wide::from(self.q);
        let sum = T::Wide::from(self.val) + T::Wide::from(rhs.val);
        let r = if sum >= q_w {sum - q_w} else {sum};
        Zq {val: T::narrow(r), q: self.q}
    }
}

impl<T: ZqLimb> Sub for Zq<T> {
    type Output = Self;
    fn sub(self, rhs: Zq<T>) -> Self {
        self.ck_mod(rhs);
        let q_w = T::Wide::from(self.q);
        let a = T::Wide::from(self.val);
        let b = T::Wide::from(rhs.val);
        let r = if a >= b {a - b} else {a + q_w - b}; //better to just mod result?
        Zq {val: T::narrow(r), q: self.q}
    }
}

impl<T: ZqLimb> Mul for Zq<T> {
    type Output = Self;
    fn mul(self, rhs: Zq<T>) -> Self {
        self.ck_mod(rhs);
        let q_w = T::Wide::from(self.q);
        let prod = T::Wide::from(self.val) * T::Wide::from(rhs.val);
        Zq {val: T::narrow(prod % q_w), q: self.q}
    }
}

impl<T: ZqLimb> Neg for Zq<T> {
    type Output = Self;
    fn neg(self) -> Self {
        let q_w = T::Wide::from(self.q);
        let a = T::Wide::from(self.val);
        let r = (q_w - a) % q_w;
        Zq { val: T::narrow(r), q: self.q }
    }
}

impl<T: ZqLimb> fmt::Debug for Zq<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} (mod {:?})", self.val, self.q)
    }
}

//Custom Dot product for 2 (1xn) vectors of same length with same moduli
pub fn dot<T: ZqLimb>(lhs: &[Zq<T>], rhs: &[Zq<T>], q: T) -> Zq<T> {
    debug_assert_eq!(lhs.len(), rhs.len()); //Must be same length of vectors
    let r: Zq<T> = lhs.iter().enumerate()
        .fold(Zq::new(T::from_i128(0), q), |acc, (i, &l_v)| {
            let r_v = rhs[i];
            acc + (r_v * l_v)
        });
    r
}

//Custom add for 2 (1xn) vectors of same length with same moduli
pub fn add<T: ZqLimb>(lhs: &[Zq<T>], rhs: &[Zq<T>]) -> Vec<Zq<T>> {
    debug_assert_eq!(lhs.len(), rhs.len()); //Must be same length of vectors
    let r: Vec<Zq<T>> = lhs.iter().enumerate()
        .map(|(i, &l_v)| {
            let r_v = rhs[i];
            r_v + l_v
        }).collect();
    r
}