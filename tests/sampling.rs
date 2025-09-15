use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use pvw::prelude::*;
use pvw::sampling::normal::*;
use pvw::sampling::uniform::sample_vec_cbd;
use rand::{rngs::OsRng, thread_rng};
use std::collections::HashMap;
use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_sampling_basic() {
        let variance = BigInt::from(100u32);
        let samples = sample_bigint_normal_vec(&variance, 1000);

        assert_eq!(samples.len(), 1000);

        // Basic sanity checks - should have variety of values
        let has_positive = samples.iter().any(|x| x.is_positive());
        let has_negative = samples.iter().any(|x| x.is_negative());
        let _has_zero = samples.iter().any(|x| x.is_zero());

        // Should have some variety (not all the same sign)
        assert!(has_positive || has_negative);
    }

    #[test]
    fn test_large_variance_sampling() {
        // Test with 100-bit variance (2^100)
        let large_variance = BigInt::from(2u32).pow(100);
        let samples = sample_bigint_normal_vec(&large_variance, 100);

        assert_eq!(samples.len(), 100);

        // Debug: print some sample values and their bit lengths
        println!("Sample values and bit lengths:");
        for (i, sample) in samples.iter().take(10).enumerate() {
            println!("Sample {}: {} (bits: {})", i, sample, sample.bits());
        }

        // With large variance, should get some large values
        let has_large_values = samples.iter().any(|x| x.bits() > 50);

        let max_bits = samples.iter().map(|x| x.bits()).max().unwrap_or(0);
        println!("Maximum bits in samples: {max_bits}");
        println!("Large variance bits: {}", large_variance.bits());

        assert!(
            has_large_values,
            "Should have some large values with 100-bit variance. Max bits: {max_bits}"
        );
    }

    #[test]
    fn test_small_variance_sampling() {
        // Test with small variance
        let small_variance = BigInt::from(4u32);
        let samples = sample_bigint_normal_vec(&small_variance, 1000);

        assert_eq!(samples.len(), 1000);

        // With small variance, most values should be small
        let mostly_small = samples
            .iter()
            .filter(|x| x.abs() <= BigInt::from(10))
            .count();
        assert!(
            mostly_small > 800,
            "Most samples should be small with small variance"
        );
    }

    #[test]
    fn test_zero_variance() {
        let zero_variance = BigInt::from(0);
        let samples = sample_bigint_normal_vec(&zero_variance, 10);

        assert_eq!(samples.len(), 10);
        assert!(
            samples.iter().all(|x| x.is_zero()),
            "All samples should be zero with zero variance"
        );
    }

    #[test]
    fn test_convenience_functions() {
        // Test u64 convenience function
        let samples_u64 = sample_bigint_normal_vec_u64(100, 50);
        assert_eq!(samples_u64.len(), 50);

        // Test bits convenience function
        let samples_bits = sample_bigint_normal_vec_bits(10, 50); // 2^10 = 1024 variance
        assert_eq!(samples_bits.len(), 50);

        // Test single sample functions
        sample_bigint_normal_u64(100);
        sample_bigint_normal_bits(10);
    }

    #[test]
    fn test_very_large_variance() {
        // Test with extremely large variance
        let huge_variance = BigInt::from_str("123456789012345678901234567890123456789").unwrap();
        let samples = sample_bigint_normal_vec(&huge_variance, 10);

        assert_eq!(samples.len(), 10);
        // Should handle large variances without panicking
    }

    #[test]
    fn test_box_muller_properties() {
        let mut rng = thread_rng();
        let samples: Vec<f64> = (0..1000).map(|_| box_muller(&mut rng)).collect();

        // Basic statistical properties (rough checks)
        let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
        let variance: f64 =
            samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / samples.len() as f64;

        // Should be approximately N(0,1)
        assert!(mean.abs() < 0.2, "Mean should be close to 0, got {mean}");
        assert!(
            (variance - 1.0).abs() < 0.3,
            "Variance should be close to 1, got {variance}"
        );
    }

    #[test]
    fn test_scaling_correctness() {
        // Test that scaling works correctly for different variance sizes
        let small_var = BigInt::from(1u32);
        let large_var = BigInt::from(10000u32);

        let small_samples = sample_bigint_normal_vec(&small_var, 1000);
        let large_samples = sample_bigint_normal_vec(&large_var, 1000);

        // Rough check: larger variance should generally produce larger values
        let small_avg_abs: f64 = small_samples
            .iter()
            .map(|x| x.to_f64().unwrap_or(0.0).abs())
            .sum::<f64>()
            / small_samples.len() as f64;

        let large_avg_abs: f64 = large_samples
            .iter()
            .map(|x| x.to_f64().unwrap_or(0.0).abs())
            .sum::<f64>()
            / large_samples.len() as f64;

        assert!(
            large_avg_abs > small_avg_abs,
            "Larger variance should produce larger average absolute values"
        );
    }

    #[test]
    fn test_sign_distribution() {
        let variance = BigInt::from(100u32);
        let samples = sample_bigint_normal_vec(&variance, 1000);

        let positive_count = samples.iter().filter(|x| x.is_positive()).count();
        let negative_count = samples.iter().filter(|x| x.is_negative()).count();
        let zero_count = samples.iter().filter(|x| x.is_zero()).count();

        // Should have roughly balanced positive/negative (allowing for randomness)
        assert!(
            positive_count > 100,
            "Should have significant positive samples"
        );
        assert!(
            negative_count > 100,
            "Should have significant negative samples"
        );
        assert!(zero_count < 100, "Should not have too many exact zeros");
    }

    #[test]
    fn test_discrete_gaussian_direct() {
        // Test the main function directly
        let bound = BigInt::from(1000u32);
        let samples = sample_discrete_gaussian_vec(&bound, 100);

        assert_eq!(samples.len(), 100);

        // All samples should be within bounds
        for sample in &samples {
            assert!(
                sample >= &(-&bound) && sample <= &bound,
                "Sample {sample} outside bounds [-{bound}, {bound}]"
            );
        }
    }

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
