use num_bigint::{BigInt, RandBigInt};
use rand::thread_rng;
use rand::{CryptoRng, RngCore};

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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    #[test]
    fn test_cbd_variance_0_5() {
        let mut rng = OsRng;
        let vector_size = 10000; // Large sample for statistical analysis
        let variance = 0.5f32;

        // Sample the CBD distribution
        let samples =
            sample_vec_cbd(vector_size, variance, &mut rng).expect("CBD sampling should succeed");

        // Count occurrences of each value
        let mut counts = HashMap::new();
        for &sample in &samples {
            *counts.entry(sample).or_insert(0) += 1;
        }

        println!("CBD with variance 0.5 - Value distribution:");
        let mut sorted_keys: Vec<_> = counts.keys().collect();
        sorted_keys.sort();

        for &value in sorted_keys {
            let count = counts[&value];
            let percentage = (count as f64 / vector_size as f64) * 100.0;
            println!("  Value {value}: {count} occurrences ({percentage:.1}%)");
        }

        // Verify all values are in {-1, 0, 1}
        for &sample in &samples {
            assert!(
                (-1..=1).contains(&sample),
                "Sample {sample} is outside range [-1, 1]"
            );
        }

        // Calculate empirical variance
        let mean: f64 = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;
        let variance_empirical: f64 = samples
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / samples.len() as f64;

        println!("Empirical statistics:");
        println!("  Mean: {mean:.6}");
        println!("  Variance: {variance_empirical:.6}");
        println!("  Expected variance: 0.5");

        // Verify mean is close to 0 (centered distribution)
        assert!(
            mean.abs() < 0.1,
            "Mean {mean} is not close to 0 for centered distribution"
        );

        // Verify variance is close to 0.5
        assert!(
            (variance_empirical - 0.5).abs() < 0.1,
            "Empirical variance {variance_empirical} is not close to expected variance 0.5"
        );

        // Verify we only get values -1, 0, 1
        let unique_values: std::collections::HashSet<_> = samples.into_iter().collect();
        let expected_values: std::collections::HashSet<_> = [-1, 0, 1].iter().cloned().collect();

        // Check that all observed values are in the expected set
        for value in &unique_values {
            assert!(
                expected_values.contains(value),
                "Unexpected value {value} found"
            );
        }

        println!("✓ All samples are in {{-1, 0, 1}}");
        println!("✓ Empirical variance matches expected variance");
        println!("✓ Distribution is properly centered");
    }

    #[test]
    fn test_cbd_variance_1_0() {
        let mut rng = OsRng;
        let vector_size = 1000;
        let variance = 1.0f32;

        let samples =
            sample_vec_cbd(vector_size, variance, &mut rng).expect("CBD sampling should succeed");

        // Count occurrences
        let mut counts = HashMap::new();
        for &sample in &samples {
            *counts.entry(sample).or_insert(0) += 1;
        }

        println!("\nCBD with variance 1.0 - Value distribution:");
        let mut sorted_keys: Vec<_> = counts.keys().collect();
        sorted_keys.sort();

        for &value in sorted_keys {
            let count = counts[&value];
            let percentage = (count as f64 / vector_size as f64) * 100.0;
            println!("  Value {value}: {count} occurrences ({percentage:.1}%)");
        }

        // For variance 1.0, we expect a wider range including ±2
        let unique_values: std::collections::HashSet<_> = samples.into_iter().collect();
        println!("Unique values with variance 1.0: {unique_values:?}");
    }
}
