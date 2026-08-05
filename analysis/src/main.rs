use quant_algos::{LWESystem, PubKeyTy, PrivKeyTy, zq::Zq};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LweParamsChoice {
    pub n: usize,
    pub m: usize,
    pub q: u64,
    pub sigma: f64,
}
 
/// Derive a valid (m, q, sigma) triple for the given n.
pub fn choose_params(n: usize) -> LweParamsChoice {
    let q = find_prime_in_range(n);
    let m = compute_m(n, q);
    let sigma = compute_sigma(q, m);
    LweParamsChoice { n, m, q, sigma }
}
 
fn find_prime_in_range(n: usize) -> u64 {
    let lower = (n as u64) * (n as u64);
    let upper = 2 * lower;
    let mut candidate = lower.max(2);
    while candidate <= upper {
        if is_prime(candidate) {
            return candidate;
        }
        candidate += 1;
    }
    panic!("no prime found in [{lower}, {upper}) for n={n}; try a larger n");
}
 
// Trial-division primality test. Deliberately simple: even at
// realistic LWE dimensions (n in the hundreds, q up to ~2^20-2^30),
// sqrt(q) -- no need for Miller-Rabin at this scale.
fn is_prime(v: u64) -> bool {
    if v < 2 {
        return false;
    }
    if v % 2 == 0 {
        return v == 2;
    }
    let mut i = 3u64;
    while i * i <= v {
        if v % i == 0 {
            return false;
        }
        i += 2;
    }
    true
}
 
// m = (1+eps)(n+1) log2(q), rounded up. eps is an arbitrary constant
// per Regev's parameterization (eps = 0.5 should be small enough)
fn compute_m(n: usize, q: u64) -> usize {
    const EPS: f64 = 0.5;
    let log2_q = (q as f64).log2();
    (((1.0 + EPS) * (n as f64 + 1.0) * log2_q).ceil()) as usize
}
 
fn compute_sigma(q: u64, m: usize) -> f64 {
    (q as f64) / (16.0 * (m as f64).sqrt())
}

fn pub_key_bytes(pub_key: &PubKeyTy) -> usize {
    pub_key
        .iter()
        .map(|(row, _b)| row.len() * std::mem::size_of::<Zq<u64>>() + std::mem::size_of::<Zq<u64>>())
        .sum()
}

fn priv_key_bytes(priv_key: &PrivKeyTy) -> usize {
    priv_key.len() * std::mem::size_of::<Zq<u64>>()
}




fn main() {
    println!("Starting Learning With Errors PKC Simulation...");
    
    let rounds: u128 = 50;
    let n = 103;
    let param = choose_params(n);
    println!("Simulating {} rounds of 100 bit dec(enc(x)) executions with params:", rounds);
    println!("{:?}", param);
    let mut byte_sum_pub: u128 = 0;
    let mut byte_sum_priv: u128 = 0;
    let mut ct = 0;
    let start = Instant::now();
    for _ in 0..rounds {
        let crypto_system = LWESystem::key_gen(param.n, param.m, param.q, param.sigma);
        byte_sum_pub += pub_key_bytes(crypto_system.public_key()) as u128;
        byte_sum_priv += priv_key_bytes(crypto_system.private_key()) as u128;
        for _ in 0..100 {
            let cipher_bit = LWESystem::encrypt_bit(
                crypto_system.public_key(), 
                crypto_system.params(), 
                true);
            
            let result = crypto_system.decrypt_bit(cipher_bit);
            if !result {
                ct += 1;
            }
        }
    }
    let end = start.elapsed();
    println!("End of simulation: \n# of Bit Errors: {} \nTime Elapsed: {:?}ms \n(Avg time per round: {}ms)\nAvg pub_key size: {}kB\nAvg priv_key size: {}B", 
    ct, end.as_millis(), end.as_millis()/rounds, (byte_sum_pub/rounds)/1000, (byte_sum_priv/rounds));

    let rounds: u128 = 50;
    println!("\nSimulating {} rounds of string dec(enc(x)) executions with params:", rounds);
    println!("{:?}", param);
    let test_str = "Testing with a medium length string here!!! :) all utf-8 here!".to_string();
    let mut ct = 0;
    let start = Instant::now();
    for _ in 0..rounds {
        let crypto_system = LWESystem::key_gen(param.n, param.m, param.q, param.sigma);
        let cipher_string = 
            LWESystem::encrypt(crypto_system.public_key(), 
                crypto_system.params(), 
                test_str.clone());
        let result: String = crypto_system.decrypt(cipher_string);
        if result != test_str {
            ct += 1;
        }
    }
    let end = start.elapsed();
    println!("End of simulation: \nMalformed Outputs: {} \nTime Elapsed: {:?}ms \n(Avg time per round: {}ms)", ct, end.as_millis(), end.as_millis()/rounds);

}
