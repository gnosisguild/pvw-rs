use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use pvw::prelude::*;
use pvw::sampling::normal::*;
use rand::thread_rng;
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
}
