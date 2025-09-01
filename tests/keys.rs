use fhe_math::rq::Representation;
use pvw::keys::public_key::{GlobalPublicKey, Party};
use pvw::keys::secret_key::SecretKey;
use pvw::params::PvwCrs;
use pvw::params::PvwParameters;
use pvw::params::PvwParametersBuilder;
use rand::thread_rng;
use std::sync::Arc;
use zeroize::Zeroize;

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard moduli suitable for PVW operations
    fn test_moduli() -> Vec<u64> {
        vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64]
    }

    /// Create PVW parameters for testing with moderate security settings
    fn create_test_params() -> Arc<PvwParameters> {
        PvwParametersBuilder::new()
            .set_parties(5)
            .set_dimension(1024)
            .set_l(8)
            .set_moduli(&test_moduli())
            .set_secret_variance(1)
            .set_error_bounds_u32(100, 200)
            .build_arc()
            .unwrap()
    }

    /// Create PVW parameters that satisfy the correctness condition
    fn create_correct_test_params() -> Arc<PvwParameters> {
        let moduli = test_moduli();

        let (variance, bound1, bound2) =
            PvwParameters::suggest_correct_parameters(5, 4, 8, &moduli).unwrap_or((1, 50, 100));

        PvwParametersBuilder::new()
            .set_parties(5)
            .set_dimension(1024)
            .set_l(8)
            .set_moduli(&moduli)
            .set_secret_variance(variance)
            .set_error_bounds_u32(bound1, bound2)
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_party_creation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let party = Party::new(0, &params, &mut rng).unwrap();
        assert_eq!(party.index(), 0);
        assert_eq!(party.secret_key().params.k, params.k);

        // Test invalid index
        let invalid_party = Party::new(params.n, &params, &mut rng);
        assert!(invalid_party.is_err());
    }

    #[test]
    fn test_party_creation_with_correct_parameters() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let party = Party::new(0, &params, &mut rng).unwrap();
        assert!(params.verify_correctness_condition());
        assert_eq!(party.secret_key().params.k, params.k);
    }

    #[test]
    fn test_public_key_generation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let party = Party::new(0, &params, &mut rng).unwrap();
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let pk = party.generate_public_key(&crs, &mut rng).unwrap();

        assert_eq!(pk.dimension(), params.k);
        assert!(pk.validate().is_ok());

        // Test polynomial access
        for i in 0..params.k {
            let poly = pk.get_polynomial(i).unwrap();
            assert!(Arc::ptr_eq(&poly.ctx, &params.context));
        }
    }

    #[test]
    fn test_global_public_key() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let global_pk = GlobalPublicKey::new(crs);

        assert_eq!(global_pk.dimensions(), (params.n, params.k));
        assert_eq!(global_pk.num_public_keys(), 0);
        assert!(!global_pk.is_full());
        assert!(global_pk.validate().is_ok());
    }

    #[test]
    fn test_key_generation_workflow() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create parties
        let party_0 = Party::new(0, &params, &mut rng).unwrap();
        let party_1 = Party::new(1, &params, &mut rng).unwrap();

        // Create CRS and global public key
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        // Generate and add public keys
        global_pk
            .generate_and_add_party(&party_0, &mut rng)
            .unwrap();
        global_pk
            .generate_and_add_party(&party_1, &mut rng)
            .unwrap();

        assert_eq!(global_pk.num_public_keys(), 2);

        // Test retrieving public keys
        let retrieved_pk_0 = global_pk.get_public_key(0).unwrap();
        let retrieved_pk_1 = global_pk.get_public_key(1).unwrap();

        assert!(retrieved_pk_0.validate().is_ok());
        assert!(retrieved_pk_1.validate().is_ok());

        // Test polynomial access
        let party_0_polys = global_pk.get_party_polynomials(0).unwrap();
        assert_eq!(party_0_polys.len(), params.k);
    }

    #[test]
    fn test_batch_key_generation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create multiple parties
        let parties: Vec<Party> = (0..3)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        // Create CRS and global public key
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        // Generate all keys at once
        global_pk.generate_all_party_keys(&parties).unwrap();

        assert_eq!(global_pk.num_public_keys(), 3);
        assert!(!global_pk.is_full()); // 3 out of 5 parties

        // Verify all keys are valid
        for i in 0..3 {
            let pk = global_pk.get_public_key(i).unwrap();
            assert!(pk.validate().is_ok());
        }
    }

    #[test]
    fn test_secret_key_batch_generation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create secret keys directly
        let secret_keys: Vec<SecretKey> = (0..2)
            .map(|_| SecretKey::random(&params, &mut rng).unwrap())
            .collect();

        // Create CRS and global public key
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        // Generate all keys from secret keys
        global_pk.generate_all_keys(&secret_keys).unwrap();

        assert_eq!(global_pk.num_public_keys(), 2);

        // Verify generated keys
        for i in 0..2 {
            let pk = global_pk.get_public_key(i).unwrap();
            assert!(pk.validate().is_ok());
            assert_eq!(pk.dimension(), params.k);
        }
    }

    #[test]
    fn test_public_key_retrieval() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let party = Party::new(0, &params, &mut rng).unwrap();
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        // Add a key
        global_pk.generate_and_add_party(&party, &mut rng).unwrap();

        // Test different retrieval methods
        let pk = global_pk.get_public_key(0).unwrap();
        let polys = global_pk.get_party_polynomials(0).unwrap();

        assert_eq!(pk.dimension(), params.k);
        assert_eq!(polys.len(), params.k);

        // Test out of bounds access
        assert!(global_pk.get_public_key(5).is_none());
        assert!(global_pk.get_party_polynomials(5).is_err());
    }

    #[test]
    fn test_dimension_validation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create mismatched parameters for testing
        let wrong_params = PvwParametersBuilder::new()
            .set_parties(5)
            .set_dimension(8) // Different k
            .set_l(8)
            .set_moduli(&test_moduli())
            .set_secret_variance(1)
            .set_error_bounds_u32(100, 200)
            .build_arc()
            .unwrap();

        let party = Party::new(0, &params, &mut rng).unwrap();
        let wrong_crs = PvwCrs::new(&wrong_params, &mut rng).unwrap();

        // This should fail due to dimension mismatch
        let result = party.generate_public_key(&wrong_crs, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_full_capacity() {
        let small_params = PvwParametersBuilder::new()
            .set_parties(2) // Only 2 parties
            .set_dimension(2)
            .set_l(8)
            .set_moduli(&test_moduli())
            .set_secret_variance(1)
            .set_error_bounds_u32(100, 200)
            .build_arc()
            .unwrap();

        let mut rng = thread_rng();
        let crs = PvwCrs::new(&small_params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        assert!(!global_pk.is_full());

        // Add keys for both parties
        for i in 0..2 {
            let party = Party::new(i, &small_params, &mut rng).unwrap();
            global_pk.generate_and_add_party(&party, &mut rng).unwrap();
        }

        assert!(global_pk.is_full());
        assert_eq!(global_pk.num_public_keys(), 2);
    }

    #[test]
    fn test_secret_key_generation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let sk = SecretKey::random(&params, &mut rng).unwrap();

        assert_eq!(sk.len(), params.k);
        assert!(!sk.is_empty());
        assert!(sk.validate().is_ok());
        assert!(sk.validate_coefficient_bounds().is_ok());

        // Verify coefficient structure
        assert_eq!(sk.secret_coeffs.len(), params.k);
        for coeffs in &sk.secret_coeffs {
            assert_eq!(coeffs.len(), params.l);
        }

        // Ensure the secret key is not the all-zero vector
        let has_nonzero = sk.secret_coeffs.iter().flatten().any(|&c| c != 0);
        assert!(has_nonzero, "Secret key coefficients are all zero");

        println!("✓ Secret key generation test passed");
    }

    #[test]
    fn test_secret_key_with_correct_parameters() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();
        let sk = SecretKey::random(&params, &mut rng).unwrap();

        assert!(sk.validate().is_ok());
        assert!(sk.validate_coefficient_bounds().is_ok());
        assert!(params.verify_correctness_condition());

        println!("✓ Secret key with correct parameters test passed");
    }

    #[test]
    fn test_direct_coefficient_access() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let sk = SecretKey::random(&params, &mut rng).unwrap();

        // Test direct coefficient access
        let coeffs = sk.coefficients();
        assert_eq!(coeffs.len(), params.k);

        for row in coeffs {
            assert_eq!(row.len(), params.l);
            // With CBD variance = 1, coefficients should be in {-2, -1, 0, 1, 2}
            for &coeff in row {
                assert!(
                    coeff.abs() <= 2,
                    "Coefficient {coeff} exceeds expected bound 2 for CBD variance=1"
                );
            }
        }

        // Test individual coefficient access
        let first_poly_coeffs = sk.get_coefficients(0).unwrap();
        assert_eq!(first_poly_coeffs.len(), params.l);
        assert!(sk.get_coefficients(params.k).is_none());

        println!("✓ Direct coefficient access test passed");
    }

    #[test]
    fn test_polynomial_conversion_on_demand() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let sk = SecretKey::random(&params, &mut rng).unwrap();

        // Test converting to polynomials for crypto operations
        let polys = sk.to_polynomials().unwrap();
        assert_eq!(polys.len(), params.k);

        for poly in &polys {
            assert_eq!(*poly.representation(), Representation::Ntt);
            assert!(Arc::ptr_eq(&poly.ctx, &params.context));
        }

        // Test single polynomial conversion
        let single_poly = sk.get_polynomial(0).unwrap();
        assert_eq!(*single_poly.representation(), Representation::Ntt);
        assert!(Arc::ptr_eq(&single_poly.ctx, &params.context));

        println!("✓ Polynomial conversion on-demand test passed");
    }

    #[test]
    fn test_backward_compatibility() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let sk = SecretKey::random(&params, &mut rng).unwrap();

        // Test legacy methods still work
        let coeff_matrix = sk.to_coefficient_matrix().unwrap();
        let as_matrix = sk.as_matrix().unwrap();
        let poly_vector = sk.as_poly_vector().unwrap();

        assert_eq!(coeff_matrix, sk.secret_coeffs);
        assert_eq!(as_matrix, sk.secret_coeffs);
        assert_eq!(poly_vector.len(), params.k);

        // Legacy matrix should match direct coefficient access
        assert_eq!(coeff_matrix, sk.coefficients().to_vec());

        println!("✓ Backward compatibility test passed");
    }

    #[test]
    fn test_mutable_coefficient_access() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let mut sk = SecretKey::random(&params, &mut rng).unwrap();

        // Test mutable access
        let coeffs_mut = sk.coefficients_mut();
        let original_value = coeffs_mut[0][0];
        coeffs_mut[0][0] = 42;
        assert_eq!(sk.secret_coeffs[0][0], 42);

        // Test individual mutable access
        let first_poly_mut = sk.get_coefficients_mut(0).unwrap();
        first_poly_mut[0] = original_value;
        assert_eq!(sk.secret_coeffs[0][0], original_value);

        println!("✓ Mutable coefficient access test passed");
    }

    #[test]
    fn test_custom_secret_variance() {
        let params = PvwParametersBuilder::new()
            .set_parties(3)
            .set_dimension(4)
            .set_l(8)
            .set_moduli(&test_moduli())
            .set_secret_variance(2u32)
            .set_error_bounds_u32(50, 100)
            .build_arc()
            .unwrap();

        let mut rng = thread_rng();
        let sk = SecretKey::random(&params, &mut rng).unwrap();

        assert!(sk.validate().is_ok());
        assert!(sk.validate_coefficient_bounds().is_ok());

        // With variance = 2, coefficients should be in {-4, -3, -2, -1, 0, 1, 2, 3, 4}
        let coeffs = sk.coefficients();
        for row in coeffs {
            for &coeff in row {
                assert!(
                    coeff.abs() <= 4,
                    "Coefficient {coeff} should be in [-4,4] with variance=2"
                );
            }
        }

        println!("✓ Custom secret variance test passed");
    }

    #[test]
    fn test_coefficient_statistics() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let sk = SecretKey::random(&params, &mut rng).unwrap();

        let (min, max, mean) = sk.coefficient_stats();

        // With CBD variance = 1, expect range [-2, 2]
        assert!(min >= -2);
        assert!(max <= 2);
        assert!(mean.abs() < 1.0); // Mean should be close to 0 for random sampling

        println!("✓ Coefficient statistics test passed - min: {min}, max: {max}, mean: {mean:.3}");
    }

    #[test]
    fn test_from_coefficients_constructor() {
        let params = create_test_params();

        // Create test coefficients - need k=1024 vectors, each with l=8 coefficients
        let mut test_coeffs = Vec::with_capacity(params.k);
        for i in 0..params.k {
            let pattern = match i % 4 {
                0 => vec![1, -1, 0, 1],
                1 => vec![0, 1, -1, 0],
                2 => vec![-1, 0, 1, -1],
                3 => vec![1, 0, 0, -1],
                _ => vec![0, 0, 0, 0], // This should never happen with % 4
            };
            let coeffs = pattern.into_iter().cycle().take(params.l).collect();
            test_coeffs.push(coeffs);
        }

        let sk = SecretKey::from_coefficients(params.clone(), test_coeffs.clone()).unwrap();

        assert_eq!(sk.secret_coeffs, test_coeffs);
        assert!(sk.validate().is_ok());
        assert!(sk.validate_coefficient_bounds().is_ok());

        println!("✓ From coefficients constructor test passed");
    }

    #[test]
    fn test_serialization() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let sk = SecretKey::random(&params, &mut rng).unwrap();

        // Test serialization
        let serialized = sk.serialize_coefficients();
        assert_eq!(serialized, sk.secret_coeffs);

        // Test round-trip
        let sk2 = SecretKey::from_coefficients(params, serialized).unwrap();
        assert_eq!(sk.secret_coeffs, sk2.secret_coeffs);

        println!("✓ Serialization test passed");
    }

    #[test]
    fn test_zeroize_implementation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let mut sk = SecretKey::random(&params, &mut rng).unwrap();

        // Verify we have non-zero coefficients initially
        let has_nonzero = sk
            .secret_coeffs
            .iter()
            .any(|row| row.iter().any(|&coeff| coeff != 0));
        assert!(
            has_nonzero,
            "Secret key should have some non-zero coefficients"
        );

        // Zeroize the secret key
        sk.zeroize();

        // Verify coefficients are zeroed
        assert!(sk.secret_coeffs.is_empty());

        println!("✓ Zeroize implementation test passed");
    }

    #[test]
    fn test_multiple_key_generation_produces_different_keys() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let sk1 = SecretKey::random(&params, &mut rng).unwrap();
        let sk2 = SecretKey::random(&params, &mut rng).unwrap();

        // Keys should be different (with very high probability)
        assert_ne!(
            sk1.secret_coeffs, sk2.secret_coeffs,
            "Two randomly generated keys should be different"
        );

        println!("✓ Multiple key generation test passed");
    }

    #[test]
    fn test_empty_parameters_edge_case() {
        // Test that parameters with k=0 are properly rejected
        let result = PvwParametersBuilder::new()
            .set_parties(3)
            .set_dimension(0) // k=0 should be rejected
            .set_l(8)
            .set_moduli(&test_moduli())
            .set_secret_variance(1)
            .set_error_bounds_u32(100, 200)
            .build_arc();

        // Parameters with k=0 should be rejected
        assert!(result.is_err(), "Parameters with k=0 should be invalid");

        // Test valid minimal parameters instead
        let minimal_params = PvwParametersBuilder::new()
            .set_parties(3)
            .set_dimension(1) // k=1 is minimal valid value
            .set_l(8)
            .set_moduli(&test_moduli())
            .set_secret_variance(1)
            .set_error_bounds_u32(100, 200)
            .build_arc()
            .unwrap();

        let mut rng = thread_rng();
        let sk = SecretKey::random(&minimal_params, &mut rng).unwrap();

        assert_eq!(sk.len(), 1);
        assert!(!sk.is_empty());
        assert!(sk.validate().is_ok());
        assert_eq!(sk.secret_coeffs.len(), 1);
        assert_eq!(sk.secret_coeffs[0].len(), minimal_params.l);

        println!("✓ Empty parameters edge case test passed");
    }

    #[test]
    fn test_parameter_variance_integration() {
        let test_variances = [1, 2, 3];

        for variance in test_variances {
            let params = PvwParametersBuilder::new()
                .set_parties(3)
                .set_dimension(2)
                .set_l(8)
                .set_moduli(&test_moduli())
                .set_secret_variance(variance)
                .set_error_bounds_u32(50, 100)
                .build_arc()
                .unwrap();

            let mut rng = thread_rng();
            let sk = SecretKey::random(&params, &mut rng).unwrap();

            assert!(sk.validate().is_ok());
            assert!(sk.validate_coefficient_bounds().is_ok());

            // Verify coefficients respect the variance bound
            let max_expected = 2 * variance as i64;
            let (min, max, mean) = sk.coefficient_stats();

            assert!(
                min >= -max_expected,
                "Min coefficient {min} should be >= -{max_expected} for variance {variance}"
            );
            assert!(
                max <= max_expected,
                "Max coefficient {max} should be <= {max_expected} for variance {variance}"
            );

            println!("✓ Variance {variance} test passed - bounds: [{min}, {max}], mean: {mean:.3}");
        }
    }
}
