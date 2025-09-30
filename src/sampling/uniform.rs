use num_bigint::{BigInt, RandBigInt};
use rand::{CryptoRng, RngCore};

/// Sample uniform coefficients from [-bound, bound]
pub fn sample_uniform_coefficients<R: RngCore + CryptoRng>(
    bound: &BigInt,
    count: usize,
    rng: &mut R, // Add RNG parameter
) -> Vec<BigInt> {
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

/// Sample a vector of independent centered binomial distributions of a given
/// variance. Supports variance = 0.5 (CBD(1), support {-1,0,1}) or integer variances up to 16.
/// Returns an error if variance is outside [0.5, 16].
pub fn sample_vec_cbd<R: RngCore + CryptoRng>(
    vector_size: usize,
    variance: f32,
    rng: &mut R,
) -> Result<Vec<i64>, &'static str> {
    if !(0.5..=16.0).contains(&variance) {
        return Err("The variance should be between 0.5 and 16");
    }

    let mut out = Vec::with_capacity(vector_size);

    if (variance - 0.5).abs() < f32::EPSILON {
        // Special case: CBD(1) -> {-1,0,1}, variance = 0.5
        for _ in 0..vector_size {
            let b1 = rng.next_u32() & 1;
            let b2 = rng.next_u32() & 1;
            out.push((b1 as i64) - (b2 as i64));
        }
    } else {
        // General case: integer variance -> CBD(2 * variance)
        let variance = variance as usize;
        let number_bits = 4 * variance;
        let mask_add = ((u64::MAX >> (64 - number_bits)) >> (2 * variance)) as u128;
        let mask_sub = mask_add << (2 * variance);

        let mut current_pool = 0u128;
        let mut current_pool_nbits = 0;

        for _ in 0..vector_size {
            if current_pool_nbits < number_bits {
                current_pool |= (rng.next_u64() as u128) << current_pool_nbits;
                current_pool_nbits += 64;
            }
            debug_assert!(current_pool_nbits >= number_bits);
            out.push(
                ((current_pool & mask_add).count_ones() as i64)
                    - ((current_pool & mask_sub).count_ones() as i64),
            );
            current_pool >>= number_bits;
            current_pool_nbits -= number_bits;
        }
    }
    Ok(out)
}
