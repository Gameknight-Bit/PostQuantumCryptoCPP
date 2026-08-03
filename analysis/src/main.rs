use quant_algos::{LWESystem};

fn main() {
    println!("Starting Learning With Errors PKC Simulation...");
    let crypto_sys = LWESystem::key_gen(n, m, q, sigma);
}
