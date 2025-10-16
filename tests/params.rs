use fhe_math::rq::Poly;
use fhe_math::rq::Representation;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::One;
use num_traits::Signed;
use num_traits::Zero;
use pvw::keys::secret_key::SecretKey;
use pvw::params::PvwCrs;
use pvw::params::PvwParameters;
use pvw::params::PvwParametersBuilder;
use rand::thread_rng;
use std::sync::Arc;

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
            .set_parties(3)
            .set_dimension(4)
            .set_l(8)
            .set_moduli(&test_moduli())
            .set_secret_variance(0.5) // Updated to f32
            .set_error_bounds_u32(100, 200)
            .build_arc()
            .unwrap()
    }

    /// Create PVW parameters that satisfy the correctness condition
    fn create_correct_test_params() -> Arc<PvwParameters> {
        let moduli = test_moduli();
        let variance = 0.5f32; // Use f32 variance

        let (bound1, bound2) =
            PvwParameters::suggest_error_bounds(30, 64, 32, &moduli, variance).unwrap_or((50, 100));

        PvwParametersBuilder::new()
            .set_parties(30)
            .set_dimension(64)
            .set_l(32)
            .set_moduli(&moduli)
            .set_secret_variance(variance)
            .set_error_bounds_u32(bound1, bound2)
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_crs_creation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();

        assert_eq!(crs.dimensions(), (params.k, params.k));
        assert_eq!(crs.len(), params.k * params.k);
        assert!(!crs.is_empty());
        assert!(crs.validate().is_ok());

        // Verify all polynomials are in NTT form and use correct context
        for poly in crs.iter() {
            assert_eq!(*poly.representation(), Representation::Ntt);
            assert!(Arc::ptr_eq(&poly.ctx, &params.context));
        }
    }

    #[test]
    fn test_crs_with_correct_parameters() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();

        assert_eq!(crs.dimensions(), (params.k, params.k));
        assert!(crs.validate().is_ok());
        assert!(params.verify_correctness_condition());
    }

    #[test]
    fn test_deterministic_generation() {
        let params = create_test_params();

        let seed = [42u8; 32];

        let crs1 = PvwCrs::new_deterministic(&params, seed).unwrap();
        let crs2 = PvwCrs::new_deterministic(&params, seed).unwrap();

        // Same seed should produce identical CRS structure
        assert_eq!(crs1.dimensions(), crs2.dimensions());
        assert!(crs1.validate().is_ok());
        assert!(crs2.validate().is_ok());

        // Same seed should produce identical CRS
        let (rows, cols) = crs1.matrix.dim();
        for i in 0..rows {
            for j in 0..cols {
                let p1 = &crs1.matrix[(i, j)];
                let p2 = &crs2.matrix[(i, j)];

                assert_eq!(p1, p2, "Same seed produced different CRSs");
            }
        }

        // Different seed should produce different CRS
        let crs3 = PvwCrs::new_deterministic(&params, [1u8; 32]).unwrap();
        let mut any_diff = false;

        'outer: for i in 0..rows {
            for j in 0..cols {
                let p1: &Poly = &crs1.matrix[(i, j)];
                let p2: &Poly = &crs3.matrix[(i, j)];
                if p1 != p2 {
                    any_diff = true;
                    break 'outer;
                }
            }
        }

        assert!(
            any_diff,
            "Different seeds produced identical CRS (all entries equal)"
        );
    }

    #[test]
    fn test_crs_from_tag() {
        let params = create_test_params();

        let crs1 = PvwCrs::new_from_tag(&params, "test_tag").unwrap();
        let crs2 = PvwCrs::new_from_tag(&params, "test_tag").unwrap();

        // Same tag should produce same structure
        assert_eq!(crs1.dimensions(), crs2.dimensions());
        assert!(crs1.validate().is_ok());
        assert!(crs2.validate().is_ok());

        // Same seed should produce identical CRS
        let (rows, cols) = crs1.matrix.dim();
        for i in 0..rows {
            for j in 0..cols {
                let p1 = &crs1.matrix[(i, j)];
                let p2 = &crs2.matrix[(i, j)];

                assert_eq!(p1, p2, "Same seed produced different CRSs");
            }
        }

        // Different tags should produce different CRS
        let crs3 = PvwCrs::new_from_tag(&params, "different_tag").unwrap();

        let mut any_diff = false;
        'outer: for i in 0..rows {
            for j in 0..cols {
                let p1: &Poly = &crs1.matrix[(i, j)];
                let p2: &Poly = &crs3.matrix[(i, j)];
                if p1 != p2 {
                    any_diff = true;
                    break 'outer;
                }
            }
        }
        assert!(
            any_diff,
            "Different seeds produced identical CRS (all entries equal)"
        );
    }

    #[test]
    fn test_validation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        assert!(crs.validate().is_ok());

        // Test that all polynomials have correct context and representation
        for poly in crs.iter() {
            assert!(Arc::ptr_eq(&poly.ctx, &params.context));
            assert_eq!(*poly.representation(), Representation::Ntt);
        }
    }

    #[test]
    fn test_matrix_vector_operations() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let sk = SecretKey::random(&params, &mut rng).unwrap();

        // Test matrix-vector multiplication for key generation
        let pk_polys = crs.multiply_by_secret_key(&sk).unwrap();
        assert_eq!(pk_polys.len(), params.k);

        // Verify all result polynomials are in NTT form
        for poly in &pk_polys {
            assert_eq!(*poly.representation(), Representation::Ntt);
            assert!(Arc::ptr_eq(&poly.ctx, &params.context));
        }
    }

    #[test]
    fn test_randomness_multiplication() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();

        // Create randomness vector
        let mut randomness = Vec::with_capacity(params.k);
        for _ in 0..params.k {
            let poly = Poly::random(&params.context, Representation::Ntt, &mut rng);
            randomness.push(poly);
        }

        // Test matrix-vector multiplication for encryption
        let c1_polys = crs.multiply_by_randomness(&randomness).unwrap();
        assert_eq!(c1_polys.len(), params.k);

        // Verify all result polynomials are in NTT form
        for poly in &c1_polys {
            assert_eq!(*poly.representation(), Representation::Ntt);
            assert!(Arc::ptr_eq(&poly.ctx, &params.context));
        }
    }

    #[test]
    fn test_element_access() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let mut crs = PvwCrs::new(&params, &mut rng).unwrap();

        // Test element access
        assert!(crs.get(0, 0).is_some());
        assert!(crs.get(params.k, 0).is_none());
        assert!(crs.get(0, params.k).is_none());

        // Test mutable access
        assert!(crs.get_mut(0, 0).is_some());
        assert!(crs.get_mut(params.k, 0).is_none());
    }

    #[test]
    fn test_different_parameter_sizes() {
        let test_cases = vec![(1, 8), (2, 8), (4, 16), (128, 8), (1024, 8)];

        let mut rng = thread_rng();

        for (k, l) in test_cases {
            let params = PvwParametersBuilder::new()
                .set_parties(3)
                .set_dimension(k)
                .set_l(l)
                .set_moduli(&test_moduli())
                .set_secret_variance(0.5) // Updated to f32
                .set_error_bounds_u32(50, 100)
                .build_arc()
                .unwrap();

            let crs = PvwCrs::new(&params, &mut rng).unwrap();

            assert_eq!(crs.dimensions(), (k, k));
            assert!(crs.validate().is_ok());
        }
    }

    #[test]
    fn test_correctness_condition_integration() {
        let moduli = test_moduli();
        let variance = 0.5f32;

        // Test with parameters that satisfy correctness condition
        if let Ok((bound1, bound2)) =
            PvwParameters::suggest_error_bounds(3, 4, 8, &moduli, variance)
        {
            let good_params = PvwParametersBuilder::new()
                .set_parties(3)
                .set_dimension(4)
                .set_l(8)
                .set_moduli(&moduli)
                .set_secret_variance(variance)
                .set_error_bounds_u32(bound1, bound2)
                .build_arc()
                .unwrap();

            assert!(good_params.verify_correctness_condition());

            let mut rng = thread_rng();
            let _crs = PvwCrs::new(&good_params, &mut rng).unwrap();
        }

        // Test with parameters that may not satisfy correctness condition
        let questionable_params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(8)
            .set_l(8)
            .set_moduli(&moduli)
            .set_secret_variance(3.0) // Higher variance
            .set_error_bounds_u32(1000, 2000)
            .build_arc()
            .unwrap();

        let mut rng = thread_rng();
        let _crs = PvwCrs::new(&questionable_params, &mut rng).unwrap();
    }

    #[test]
    fn test_pvw_parameters_with_custom_moduli() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        // Try different parameter combinations with different variances
        let test_cases = [
            (3, 8, 8, 0.5f32),      // Small parameters, ternary secrets
            (10, 128, 16, 1.0f32),  // Medium parameters, wider range
            (50, 2048, 32, 0.5f32), // Larger parameters, ternary secrets
        ];

        for (n, k, l, variance) in test_cases {
            println!("\n=== Testing parameters: n={n}, k={k}, l={l}, variance={variance} ===");

            // Get suggested correct parameters
            match PvwParameters::suggest_error_bounds(n, k, l, &moduli, variance) {
                Ok((error_bound_1, error_bound_2)) => {
                    println!(
                        "Suggested error bounds found: bound1={error_bound_1}, bound2={error_bound_2}"
                    );

                    // Create parameters with suggested bounds
                    match PvwParameters::new_with_u32_bounds(
                        n,
                        k,
                        l,
                        &moduli,
                        variance,
                        error_bound_1,
                        error_bound_2,
                    ) {
                        Ok(params) => {
                            println!(
                                "Parameters created successfully with Delta = {}",
                                params.delta()
                            );

                            // Verify they satisfy the correctness condition
                            match params.verify_parameters() {
                                Ok(true) => println!("✓ All parameter checks passed!"),
                                Ok(false) => println!("✗ Parameter verification failed"),
                                Err(e) => println!("✗ Verification error: {e}"),
                            }
                        }
                        Err(e) => println!("✗ Failed to create parameters: {e}"),
                    }
                }
                Err(e) => println!("✗ Could not find suitable error bounds: {e}"),
            }
        }
    }

    #[test]
    fn test_variance_types() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        // Test different variance values
        let variances = [0.5f32, 1.0f32, 2.0f32];

        for variance in variances {
            println!("\nTesting variance: {variance}");

            if let Ok((bound1, bound2)) =
                PvwParameters::suggest_error_bounds(5, 32, 8, &moduli, variance)
            {
                let params =
                    PvwParameters::new_with_u32_bounds(5, 32, 8, &moduli, variance, bound1, bound2)
                        .unwrap();

                println!("  Created parameters with variance {variance}");
                println!("  Error bounds: ({bound1}, {bound2})");
                println!(
                    "  Correctness satisfied: {}",
                    params.verify_correctness_condition()
                );

                // Test secret key generation to verify the variance is working
                let mut rng = thread_rng();
                let sk = SecretKey::random(&Arc::new(params), &mut rng).unwrap();
                println!("  Secret key generated successfully");

                // Check a few coefficients to see the range (for debugging)
                if let Ok(coeffs) = sk.get_polynomial(0) {
                    let mut temp_poly = coeffs.clone();
                    temp_poly.change_representation(Representation::PowerBasis);
                    let coeff_vec: Vec<num_bigint::BigUint> = (&temp_poly).into();
                    println!(
                        "  First few secret coefficients: {:?}",
                        &coeff_vec[0..4.min(coeff_vec.len())]
                    );
                }
            } else {
                println!("  Could not find suitable error bounds for variance {variance}");
            }
        }
    }

    #[test]
    fn example_usage() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        // Method 1: Using builder pattern with custom parameters
        let params1 = PvwParameters::builder()
            .set_parties(5)
            .set_dimension(128)
            .set_l(16)
            .set_moduli(&moduli)
            .set_secret_variance(1.0) // Updated to f32
            .set_error_bounds_u32(500, 1000)
            .build();

        match params1 {
            Ok(p) => {
                println!("Method 1 - Parameters created with Delta = {}", p.delta());
                if p.verify_correctness_condition() {
                    println!("✓ Correctness condition satisfied");
                } else {
                    println!("✗ Correctness condition NOT satisfied");
                }
            }
            Err(e) => println!("Method 1 failed: {e}"),
        }

        // Method 2: Using direct constructor
        let params2 = PvwParameters::new_with_u32_bounds(
            3,       // n (parties)
            64,      // k (LWE dimension)
            8,       // l (redundancy parameter)
            &moduli, // specified moduli
            0.5,     // secret_variance (f32)
            200,     // error_bound_1
            400,     // error_bound_2
        );

        match params2 {
            Ok(p) => {
                println!("Method 2 - Parameters created with Delta = {}", p.delta());
                if p.verify_correctness_condition() {
                    println!("✓ Correctness condition satisfied");
                } else {
                    println!("✗ Correctness condition NOT satisfied");
                }
            }
            Err(e) => println!("Method 2 failed: {e}"),
        }

        // Method 3: Get suggested error bounds first
        let variance = 0.5f32;
        if let Ok((bound1, bound2)) =
            PvwParameters::suggest_error_bounds(5, 128, 16, &moduli, variance)
        {
            let params3 =
                PvwParameters::new_with_u32_bounds(5, 128, 16, &moduli, variance, bound1, bound2);

            match params3 {
                Ok(p) => {
                    println!("Method 3 - Correct parameters created with suggested bounds");
                    println!("Delta = {}", p.delta());
                    assert!(
                        p.verify_correctness_condition(),
                        "Should satisfy correctness condition"
                    );
                }
                Err(e) => println!("Method 3 failed: {e}"),
            }
        }
    }

    #[test]
    fn test_bigints_to_poly_basic() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 0.5, 100, 200)
            .expect("Failed to create parameters");

        // Test case 1: Zero polynomial
        let zero_coeffs = vec![BigInt::zero(); params.l];
        let zero_poly = params
            .bigints_to_poly(&zero_coeffs)
            .expect("Failed to convert zero coefficients");

        // Convert back to BigUint and verify
        let recovered_zero: Vec<BigUint> = (&zero_poly).into();
        for (i, coeff) in recovered_zero.iter().enumerate() {
            assert_eq!(
                *coeff,
                BigUint::zero(),
                "Zero coefficient {i} should remain zero"
            );
        }
        println!("✓ Zero polynomial test passed");

        // Test case 2: Simple positive values
        let simple_coeffs: Vec<BigInt> = (1..=params.l).map(BigInt::from).collect();
        let simple_poly = params
            .bigints_to_poly(&simple_coeffs)
            .expect("Failed to convert simple coefficients");

        let recovered_simple: Vec<BigUint> = (&simple_poly).into();
        for (i, (original, recovered)) in simple_coeffs
            .iter()
            .zip(recovered_simple.iter())
            .enumerate()
        {
            let expected = original.to_biguint().unwrap();
            assert_eq!(*recovered, expected, "Simple coefficient {i} mismatch");
        }
        println!("✓ Simple positive values test passed");

        // Test case 3: Large values (within modulus range)
        let delta = params.delta().clone();
        let large_coeffs: Vec<BigInt> = (0..params.l)
            .map(|i| BigInt::from(delta.clone()) * BigInt::from(i + 1))
            .collect();

        let large_poly = params
            .bigints_to_poly(&large_coeffs)
            .expect("Failed to convert large coefficients");

        let recovered_large: Vec<BigUint> = (&large_poly).into();
        for (i, (original, recovered)) in
            large_coeffs.iter().zip(recovered_large.iter()).enumerate()
        {
            let expected_reduced = (original % BigInt::from(params.q_total()))
                .to_biguint()
                .unwrap();
            assert_eq!(
                *recovered, expected_reduced,
                "Large coefficient {i} mismatch"
            );
        }
        println!("✓ Large values test passed");
    }

    #[test]
    fn test_bigints_to_poly_negative_values() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 0.5, 100, 200)
            .expect("Failed to create parameters");

        // Test negative values
        let negative_coeffs: Vec<BigInt> = (1..=params.l).map(|i| -BigInt::from(i * 100)).collect();

        let negative_poly = params
            .bigints_to_poly(&negative_coeffs)
            .expect("Failed to convert negative coefficients");

        let recovered_negative: Vec<BigUint> = (&negative_poly).into();
        let q_total = BigInt::from(params.q_total());

        for (i, (original, recovered)) in negative_coeffs
            .iter()
            .zip(recovered_negative.iter())
            .enumerate()
        {
            // For negative values, expect: (original % q_total + q_total) % q_total
            let mut expected = original % &q_total;
            if expected.is_negative() {
                expected += &q_total;
            }
            let expected_biguint = expected.to_biguint().unwrap();

            assert_eq!(
                *recovered, expected_biguint,
                "Negative coefficient {i} mismatch"
            );
        }
        println!("✓ Negative values test passed");
    }

    #[test]
    fn test_bigints_to_poly_round_trip() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 0.5, 100, 200)
            .expect("Failed to create parameters");

        // Test round-trip: BigInt → Poly → BigUint → BigInt
        let original_coeffs: Vec<BigInt> = vec![
            BigInt::from(42),
            -BigInt::from(123),
            BigInt::from(params.delta().clone()) / BigInt::from(2),
            BigInt::zero(),
            BigInt::one(),
            -BigInt::one(),
            BigInt::from(999999),
            -BigInt::from(888888),
        ];

        // Convert to polynomial
        let poly = params
            .bigints_to_poly(&original_coeffs)
            .expect("Failed to convert to polynomial");

        // Convert back to BigUint
        let recovered_biguints: Vec<BigUint> = (&poly).into();

        // Convert back to BigInt and verify
        let q_total_bigint = BigInt::from(params.q_total());
        for (i, (original, recovered_biguint)) in original_coeffs
            .iter()
            .zip(recovered_biguints.iter())
            .enumerate()
        {
            let recovered_bigint = BigInt::from(recovered_biguint.clone());

            // Calculate expected value after modular reduction
            let mut expected = original % &q_total_bigint;
            if expected.is_negative() {
                expected += &q_total_bigint;
            }

            assert_eq!(
                recovered_bigint, expected,
                "Round-trip failed for coefficient {i}: original={original}, expected={expected}, got={recovered_bigint}"
            );
        }
        println!("✓ Round-trip conversion test passed");
    }

    #[test]
    fn test_bigints_to_poly_gadget_polynomial() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 0.5, 100, 200)
            .expect("Failed to create parameters");

        // Test the gadget polynomial specifically
        let gadget_poly = params
            .gadget_polynomial()
            .expect("Failed to create gadget polynomial");

        // Ensure we're in PowerBasis representation for lifting
        let mut poly_for_lifting = gadget_poly.clone();
        poly_for_lifting.change_representation(Representation::PowerBasis);

        // Use fhe.rs lift function to properly reconstruct coefficients
        let gadget_coeffs: Vec<BigUint> = (&poly_for_lifting).into();

        println!("Gadget coefficients after CRT lift:");
        for (i, coeff) in gadget_coeffs.iter().enumerate() {
            println!("  coeff[{i}] = {coeff}");
        }

        // Verify gadget structure: [1, Δ, Δ², ..., Δ^(ℓ-1)]
        let mut expected_delta_power = BigUint::one();
        for (i, coeff) in gadget_coeffs.iter().enumerate() {
            assert_eq!(
                *coeff, expected_delta_power,
                "Gadget coefficient {i} should be Delta^{i} = {expected_delta_power}, got {coeff}"
            );

            if i < params.l - 1 {
                expected_delta_power *= params.delta();
            }
        }
        println!("✓ Gadget polynomial conversion test passed");
    }

    #[test]
    fn test_bigints_to_poly_error_cases() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 0.5, 100, 200)
            .expect("Failed to create parameters");

        // Test wrong number of coefficients
        let wrong_size_coeffs = vec![BigInt::from(1), BigInt::from(2)]; // Only 2 coeffs, need 8
        let result = params.bigints_to_poly(&wrong_size_coeffs);
        assert!(
            result.is_err(),
            "Should fail with wrong number of coefficients"
        );
        println!("✓ Wrong size error handling test passed");

        // Test empty coefficients
        let empty_coeffs: Vec<BigInt> = vec![];
        let result = params.bigints_to_poly(&empty_coeffs);
        assert!(result.is_err(), "Should fail with empty coefficients");
        println!("✓ Empty coefficients error handling test passed");
    }

    #[test]
    fn test_bigints_to_poly_performance() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 0.5, 100, 200)
            .expect("Failed to create parameters");

        // Create test coefficients
        let test_coeffs: Vec<BigInt> = (0..params.l)
            .map(|i| BigInt::from(i * 12345 + 67890))
            .collect();

        // Time multiple conversions
        let start_time = std::time::Instant::now();
        let num_iterations = 100;

        for _ in 0..num_iterations {
            let _poly = params
                .bigints_to_poly(&test_coeffs)
                .expect("Failed to convert coefficients");
        }

        let elapsed = start_time.elapsed();
        let avg_time = elapsed / num_iterations;

        println!(
            "✓ Performance test: {num_iterations} conversions in {elapsed:?}, avg {avg_time:?} per conversion"
        );

        // Should be reasonably fast (less than 1ms per conversion for small polynomials)
        assert!(avg_time.as_millis() < 10, "Conversion should be fast");
    }

    #[test]
    fn test_compare_with_fhe_direct_conversion() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 0.5, 100, 200)
            .expect("Failed to create parameters");

        // Test values that should work with both approaches
        let test_values_u64: Vec<u64> = (1..=params.l as u64).collect();
        let test_values_i64: Vec<i64> = test_values_u64.iter().map(|&v| v as i64).collect();

        // Method 1: Direct fhe.rs conversion from i64
        let direct_poly = Poly::from_coefficients(&test_values_i64, &params.context)
            .expect("Failed direct fhe.rs conversion");
        let direct_recovered: Vec<BigUint> = (&direct_poly).into();

        // Method 2: Our BigInt conversion
        let bigint_coeffs: Vec<BigInt> = test_values_i64.iter().map(|&v| BigInt::from(v)).collect();
        let bigint_poly = params
            .bigints_to_poly(&bigint_coeffs)
            .expect("Failed BigInt conversion");
        let bigint_recovered: Vec<BigUint> = (&bigint_poly).into();

        // Compare results
        for (i, (direct, bigint)) in direct_recovered
            .iter()
            .zip(bigint_recovered.iter())
            .enumerate()
        {
            assert_eq!(
                *direct, *bigint,
                "Coefficient {i} differs between direct and BigInt conversion"
            );
        }
        println!("✓ Comparison with direct fhe.rs conversion test passed");
    }
}
