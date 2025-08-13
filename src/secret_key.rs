use crate::params::{PvwError, PvwParameters, Result};
use fhe_math::rq::{Poly, Representation};
use fhe_util::sample_vec_cbd;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PVW Secret Key using coefficient representation
///
/// Stores secret key coefficients directly from CBD sampling for efficiency.
/// Polynomials are created on-demand for cryptographic operations.
#[derive(Debug, Clone)]
pub struct SecretKey {
    pub params: Arc<PvwParameters>,
    /// Secret key coefficients directly from sampling (k × l matrix)
    pub secret_coeffs: Vec<Vec<i64>>,
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        // Zero out coefficient data
        for row in &mut self.secret_coeffs {
            row.zeroize();
        }
        self.secret_coeffs.clear();
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    /// Generate random secret key using CBD distribution
    ///
    /// Uses the variance specified in the PVW parameters to sample coefficients
    /// from a centered binomial distribution. Stores coefficients directly
    /// to avoid conversion overhead during frequent operations.
    ///
    /// # Arguments
    /// * `params` - PVW parameters specifying dimensions and variance
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// A new SecretKey with randomly sampled coefficients
    pub fn random<R: RngCore + CryptoRng>(
        params: &Arc<PvwParameters>,
        rng: &mut R,
    ) -> Result<Self> {
        let mut secret_coeffs = Vec::with_capacity(params.k);

        for _ in 0..params.k {
            // Sample coefficients using CBD with configured variance
            let coeffs = sample_vec_cbd(params.l, params.secret_variance as usize, rng)
                .map_err(|e| PvwError::SamplingError(format!("CBD sampling failed: {e}")))?;

            secret_coeffs.push(coeffs);
        }

        Ok(Self {
            params: params.clone(),
            secret_coeffs,
        })
    }

    /// Convert coefficients to polynomials when needed for crypto operations
    ///
    /// Creates polynomials in NTT form for efficient ring operations.
    /// This is done on-demand to avoid storing redundant representations.
    ///
    /// # Returns
    /// Vector of polynomials in NTT representation
    pub fn to_polynomials(&self) -> Result<Vec<Poly>> {
        let mut polys = Vec::with_capacity(self.params.k);

        for coeffs in &self.secret_coeffs {
            let mut poly = Poly::from_coefficients(coeffs, &self.params.context).map_err(|e| {
                PvwError::SamplingError(format!("Failed to create polynomial: {e:?}"))
            })?;

            poly.change_representation(Representation::Ntt);
            polys.push(poly);
        }

        Ok(polys)
    }

    /// Get a single polynomial at index for crypto operations
    ///
    /// Converts the coefficient vector at the specified index into a polynomial
    /// in NTT representation. More efficient than converting all polynomials
    /// when only one is needed.
    ///
    /// # Arguments
    /// * `index` - Index of the polynomial to convert (0 <= index < k)
    ///
    /// # Returns
    /// Polynomial in NTT representation, or error if index is out of bounds
    pub fn get_polynomial(&self, index: usize) -> Result<Poly> {
        if index >= self.secret_coeffs.len() {
            return Err(PvwError::InvalidParameters(format!(
                "Index {} out of bounds for {} polynomials",
                index,
                self.secret_coeffs.len()
            )));
        }

        let mut poly = Poly::from_coefficients(&self.secret_coeffs[index], &self.params.context)
            .map_err(|e| PvwError::SamplingError(format!("Failed to create polynomial: {e:?}")))?;

        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Direct access to coefficient matrix
    ///
    /// Provides access to the raw coefficient representation without
    /// polynomial conversion overhead. Useful for operations that work
    /// directly with coefficient vectors.
    ///
    /// # Returns
    /// Reference to the k × l coefficient matrix
    pub fn coefficients(&self) -> &[Vec<i64>] {
        &self.secret_coeffs
    }

    /// Mutable access to coefficient matrix
    ///
    /// Allows direct modification of secret key coefficients.
    /// Use with caution as this bypasses validation.
    ///
    /// # Returns
    /// Mutable reference to the k × l coefficient matrix
    pub fn coefficients_mut(&mut self) -> &mut [Vec<i64>] {
        &mut self.secret_coeffs
    }

    /// Get coefficients for a specific polynomial
    ///
    /// # Arguments
    /// * `index` - Index of the polynomial (0 <= index < k)
    ///
    /// # Returns
    /// Reference to coefficient vector, or None if index is out of bounds
    pub fn get_coefficients(&self, index: usize) -> Option<&[i64]> {
        self.secret_coeffs.get(index).map(|v| v.as_slice())
    }

    /// Get mutable coefficients for a specific polynomial
    ///
    /// # Arguments
    /// * `index` - Index of the polynomial (0 <= index < k)
    ///
    /// # Returns
    /// Mutable reference to coefficient vector, or None if index is out of bounds
    pub fn get_coefficients_mut(&mut self, index: usize) -> Option<&mut Vec<i64>> {
        self.secret_coeffs.get_mut(index)
    }

    /// Legacy methods for backward compatibility
    pub fn to_coefficient_matrix(&self) -> Result<Vec<Vec<i64>>> {
        Ok(self.secret_coeffs.clone())
    }

    pub fn as_matrix(&self) -> Result<Vec<Vec<i64>>> {
        self.to_coefficient_matrix()
    }

    pub fn as_matrix_mut(&mut self) -> Result<Vec<Vec<i64>>> {
        Ok(self.secret_coeffs.clone())
    }

    /// Legacy polynomial access (creates polynomials on demand)
    pub fn as_poly_vector(&self) -> Result<Vec<Poly>> {
        self.to_polynomials()
    }

    /// Get the number of secret polynomials (should equal k)
    pub fn len(&self) -> usize {
        self.secret_coeffs.len()
    }

    /// Check if secret key is empty
    pub fn is_empty(&self) -> bool {
        self.secret_coeffs.is_empty()
    }

    /// Validate secret key structure against parameters
    ///
    /// Ensures the secret key dimensions match the PVW parameters
    /// and that all coefficient vectors have the correct length.
    ///
    /// # Returns
    /// Ok(()) if structure is valid, Err with details if invalid
    pub fn validate(&self) -> Result<()> {
        if self.secret_coeffs.len() != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Secret key has {} polynomials but k={}",
                self.secret_coeffs.len(),
                self.params.k
            )));
        }

        // Verify all coefficient vectors have correct length
        for (i, coeffs) in self.secret_coeffs.iter().enumerate() {
            if coeffs.len() != self.params.l {
                return Err(PvwError::InvalidParameters(format!(
                    "Secret key polynomial {} has {} coefficients but l={}",
                    i,
                    coeffs.len(),
                    self.params.l
                )));
            }
        }

        Ok(())
    }

    /// Check if coefficients are within expected CBD bounds
    ///
    /// Validates that all coefficients fall within the expected range
    /// for the configured CBD variance. This helps detect incorrect parameter usage.
    ///
    /// # Returns
    /// Ok(()) if all coefficients are within bounds, Err with details if not
    pub fn validate_coefficient_bounds(&self) -> Result<()> {
        let max_bound = 2 * self.params.secret_variance as i64;

        for (poly_idx, coeffs) in self.secret_coeffs.iter().enumerate() {
            for (coeff_idx, &coeff) in coeffs.iter().enumerate() {
                if coeff.abs() > max_bound {
                    return Err(PvwError::InvalidParameters(format!(
                        "Coefficient at polynomial {} index {} is {} but should be in [-{}, {}] for variance {}",
                        poly_idx, coeff_idx, coeff, max_bound, max_bound, self.params.secret_variance
                    )));
                }
            }
        }

        Ok(())
    }

    /// Create secret key from existing coefficients
    ///
    /// Used for testing, deserialization, or when coefficients are
    /// generated externally. Validates the coefficient structure.
    ///
    /// # Arguments
    /// * `params` - PVW parameters that match the coefficient dimensions
    /// * `coefficients` - Pre-generated k × l coefficient matrix
    ///
    /// # Returns
    /// SecretKey with the provided coefficients, or error if invalid
    pub fn from_coefficients(
        params: Arc<PvwParameters>,
        coefficients: Vec<Vec<i64>>,
    ) -> Result<Self> {
        let sk = Self {
            params,
            secret_coeffs: coefficients,
        };

        sk.validate()?;
        Ok(sk)
    }

    /// Serialize coefficients for storage or transmission
    ///
    /// Creates a copy of the coefficient matrix suitable for serialization.
    /// The result can be used with `from_coefficients` to reconstruct the key.
    ///
    /// # Returns
    /// Cloned coefficient matrix
    pub fn serialize_coefficients(&self) -> Vec<Vec<i64>> {
        self.secret_coeffs.clone()
    }

    /// Get coefficient statistics for debugging and analysis
    ///
    /// Computes basic statistics over all coefficients in the secret key.
    /// Useful for verifying the distribution properties and detecting anomalies.
    ///
    /// # Returns
    /// Tuple of (minimum, maximum, mean) coefficient values
    pub fn coefficient_stats(&self) -> (i64, i64, f64) {
        let all_coeffs: Vec<i64> = self.secret_coeffs.iter().flatten().copied().collect();

        if all_coeffs.is_empty() {
            return (0, 0, 0.0);
        }

        let min = *all_coeffs.iter().min().unwrap();
        let max = *all_coeffs.iter().max().unwrap();
        let mean = all_coeffs.iter().sum::<i64>() as f64 / all_coeffs.len() as f64;

        (min, max, mean)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PvwParametersBuilder;
    use rand::thread_rng;

    /// Standard moduli suitable for PVW operations
    fn test_moduli() -> Vec<u64> {
        vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64]
    }

    /// Create PVW parameters for testing with moderate security settings
    fn create_test_params() -> Arc<PvwParameters> {
        PvwParametersBuilder::new()
            .set_parties(20)
            .set_dimension(4)
            .set_l(8)
            .set_moduli(&test_moduli())
            .set_secret_variance(1)
            .set_error_bounds_u32(1000, 2000)
            .build_arc()
            .unwrap()
    }

    /// Create PVW parameters that satisfy the correctness condition
    fn create_correct_test_params() -> Arc<PvwParameters> {
        let moduli = test_moduli();

        let (variance, bound1, bound2) =
            PvwParameters::suggest_correct_parameters(3, 4, 8, &moduli).unwrap_or((1, 50, 100));

        PvwParametersBuilder::new()
            .set_parties(20)
            .set_dimension(2048)
            .set_l(8)
            .set_moduli(&moduli)
            .set_secret_variance(variance)
            .set_error_bounds_u32(bound1, bound2)
            .build_arc()
            .unwrap()
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

        // Create test coefficients
        let test_coeffs = vec![
            vec![1, -1, 0, 1]
                .into_iter()
                .cycle()
                .take(params.l)
                .collect(),
            vec![0, 1, -1, 0]
                .into_iter()
                .cycle()
                .take(params.l)
                .collect(),
            vec![-1, 0, 1, -1]
                .into_iter()
                .cycle()
                .take(params.l)
                .collect(),
            vec![1, 0, 0, -1]
                .into_iter()
                .cycle()
                .take(params.l)
                .collect(),
        ];

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
