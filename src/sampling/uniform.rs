use num_bigint::{BigInt, RandBigInt};
use rand::thread_rng;

/// Sample uniform coefficients from [-bound, bound]
pub fn sample_uniform_coefficients(bound: &BigInt, count: usize) -> Vec<BigInt> {
    let mut rng = thread_rng();
    let mut samples = Vec::with_capacity(count);

    // Create range [-bound, bound + 1) since gen_bigint_range is exclusive of upper bound
    let lower_bound = -bound;
    let upper_bound = bound + 1;

    for _ in 0..count {
        let sample = rng.gen_bigint_range(&lower_bound, &upper_bound);
        samples.push(sample);
    }

    samples
}
