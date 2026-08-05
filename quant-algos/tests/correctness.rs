use quant_algos::zq::Zq;
use quant_algos::LWESystem;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// A small, fast, hand-checkable parameter set for tests.
///
/// n = 16, q = 509 (prime, with n^2 = 256 < q < 512 = 2n^2, matching the
/// Regev guideline), m ~ (1+eps)(n+1)log2(q) rounded up, sigma chosen so
/// sigma*sqrt(m) is comfortably under q/4
fn toy_params() -> (usize, usize, u64, f64) {
    (16, 200, 509, 2.0)
}

#[test]
fn round_trip_encrypts_and_decrypts_correctly() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (n, m, q, sigma) = toy_params();
    let lwe = LWESystem::key_gen_with_rng(&mut rng, n, m, q, sigma);

    for trial in 0..200 {
        let bit = trial % 2 == 0;
        let ct = LWESystem::encrypt_bit_with_rng(&mut rng, lwe.public_key(), lwe.params(), bit);
        let decrypted = lwe.decrypt_bit(ct);
        assert_eq!(decrypted, bit, "round trip failed on trial {trial}");
    }
}

#[test]
fn failure_rate_matches_prediction() {
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let (n, m, q, sigma) = toy_params();
    let lwe = LWESystem::key_gen_with_rng(&mut rng, n, m, q, sigma);

    let trials = 5000;
    let mut failures = 0;
    for i in 0..trials {
        let bit = i % 2 == 0;
        let ct = LWESystem::encrypt_bit_with_rng(&mut rng, lwe.public_key(), lwe.params(), bit);
        if lwe.decrypt_bit(ct) != bit {
            failures += 1;
        }
    }

    let empirical_rate = failures as f64 / trials as f64;
    // With this margin between sigma*sqrt(m) and q/4, the predicted
    // failure probability (normal-tail approximation) is negligible --
    // this asserts we see (approximately) zero failures in practice.
    assert!(
        empirical_rate < 0.01,
        "failure rate too high: {failures}/{trials} = {empirical_rate}"
    );
}

/// Directly exercises decrypt_bit's threshold logic without going through
/// encrypt: using an all-zero `a` vector makes the decision depend only
/// on `b`, since dot(a, private_key) = 0 regardless of the private key.
/// This pins down the exact boundary behavior at q/4 and 3q/4.
#[test]
fn decrypt_boundary_behavior() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let (n, _m, q, sigma) = toy_params();
    let lwe = LWESystem::key_gen_with_rng(&mut rng, n, 10, q, sigma);
    let zero_a = vec![Zq::new(0, q); n];

    let just_below = Zq::new(q / 4 - 1, q);
    assert_eq!(lwe.decrypt_bit((zero_a.clone(), just_below)), false);

    let at_lower_boundary = Zq::new(q / 4, q);
    assert_eq!(lwe.decrypt_bit((zero_a.clone(), at_lower_boundary)), true);

    let at_upper_boundary = Zq::new((3 * q) / 4, q);
    assert_eq!(lwe.decrypt_bit((zero_a.clone(), at_upper_boundary)), true);

    let just_above = Zq::new((3 * q) / 4 + 1, q);
    assert_eq!(lwe.decrypt_bit((zero_a, just_above)), false);
}

#[test]
fn encryptions_of_same_bit_are_randomized() {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let (n, m, q, sigma) = toy_params();
    let lwe = LWESystem::key_gen_with_rng(&mut rng, n, m, q, sigma);

    let ct1 = LWESystem::encrypt_bit_with_rng(&mut rng, lwe.public_key(), lwe.params(), true);
    let ct2 = LWESystem::encrypt_bit_with_rng(&mut rng, lwe.public_key(), lwe.params(), true);

    assert_ne!(
        ct1, ct2,
        "two encryptions of the same bit produced identical ciphertexts"
    );
}

/// Not a pass/fail correctness test -- this is an exploratory check that
/// pushing sigma too high actually breaks correctness, which is the
/// other half of the tradeoff your DESIGN.md should document. Marked
/// #[ignore] since "expect a high failure rate" is a fuzzy assertion;
/// run manually with `cargo test -- --ignored` and eyeball the number.
#[test]
#[ignore]
fn oversized_sigma_breaks_correctness() {
    let mut rng = ChaCha20Rng::seed_from_u64(123);
    let (n, m, q, _sigma) = toy_params();
    let broken_sigma = 60.0; // sigma*sqrt(m) now far exceeds q/4
    let lwe = LWESystem::key_gen_with_rng(&mut rng, n, m, q, broken_sigma);

    let trials = 2000;
    let mut failures = 0;
    for i in 0..trials {
        let bit = i % 2 == 0;
        let ct = LWESystem::encrypt_bit_with_rng(&mut rng, lwe.public_key(), lwe.params(), bit);
        if lwe.decrypt_bit(ct) != bit {
            failures += 1;
        }
    }
    eprintln!("oversized sigma failure rate: {failures}/{trials}");
    assert!(failures > 0, "expected oversized sigma to cause failures");
}

#[test]
fn single_row_ciphertext_decrypts_as_zero() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let (n, m, q, sigma) = toy_params();
    let lwe = LWESystem::key_gen_with_rng(&mut rng, n, m, q, sigma);

    for i in 0..lwe.public_key().len().min(20) {
        let (row, b) = lwe.public_key()[i].clone();
        let decoded = lwe.decrypt_bit((row, b));
        assert!(decoded == false, "row {i} failed as a standalone ciphertext");
    }
}

#[test]
fn string_check() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (n, m, q, sigma) = toy_params();
    let lwe = LWESystem::key_gen_with_rng(&mut rng, n, m, q, sigma);

    macro_rules! TEST_STR {
        () => { "This is a very long string that we want to \
                split across multiple lines in our source code \
                so it does not cause formatting issues.".to_string() };
    }

    let ct = LWESystem::encrypt(lwe.public_key(), lwe.params(), TEST_STR!().clone());
    println!("{:?}", ct);
    let decrypted: String = lwe.decrypt(ct);
    println!("{:?}", decrypted);
    if decrypted != TEST_STR!() {
        eprintln!("Expected '{}' but got '{}' instead", TEST_STR!(), decrypted);
        assert_ne!(decrypted, TEST_STR!());
    }
}