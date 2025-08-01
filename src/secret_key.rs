use crate::params::{PvwError, PvwParameters, Result};
use fhe_math::rq::{Poly, Representation};
use fhe_util::sample_vec_cbd;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PVW Secret Key using coefficient representation
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
    /// Stores coefficients directly from sampling (no conversion overhead)
    pub fn random<R: RngCore + CryptoRng>(
        params: &Arc<PvwParameters>,
        rng: &mut R,
    ) -> Result<Self> {
        let mut secret_coeffs = Vec::with_capacity(params.k);

        for _ in 0..params.k {
            // Sample coefficients directly - no polynomial conversion needed
            let coeffs = sample_vec_cbd(params.l, params.secret_variance as usize, rng)
                .map_err(|e| {
                    PvwError::SamplingError(format!("CBD sampling failed: {}", e))
                })?;
            
            secret_coeffs.push(coeffs);
        }

        Ok(Self {
            params: params.clone(),
            secret_coeffs,
        })
    }

    /// Convert coefficients to polynomials when needed for crypto operations
    /// Creates polynomials in NTT form for efficient operations
    pub fn to_polynomials(&self) -> Result<Vec<Poly>> {
        let mut polys = Vec::with_capacity(self.params.k);

        for coeffs in &self.secret_coeffs {
            let mut poly = Poly::from_coefficients(coeffs, &self.params.context)
                .map_err(|e| {
                    PvwError::SamplingError(format!("Failed to create polynomial: {:?}", e))
                })?;
            
            poly.change_representation(Representation::Ntt);
            polys.push(poly);
        }

        Ok(polys)
    }

    /// Get a single polynomial at index (for crypto operations)
    pub fn get_polynomial(&self, index: usize) -> Result<Poly> {
        if index >= self.secret_coeffs.len() {
            return Err(PvwError::InvalidParameters(format!(
                "Index {} out of bounds for {} polynomials", index, self.secret_coeffs.len()
            )));
        }

        let mut poly = Poly::from_coefficients(&self.secret_coeffs[index], &self.params.context)
            .map_err(|e| {
                PvwError::SamplingError(format!("Failed to create polynomial: {:?}", e))
            })?;
        
        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Direct access to coefficient matrix (no conversion needed)
    pub fn coefficients(&self) -> &[Vec<i64>] {
        &self.secret_coeffs
    }

    /// Mutable access to coefficient matrix
    pub fn coefficients_mut(&mut self) -> &mut [Vec<i64>] {
        &mut self.secret_coeffs
    }

    /// Get coefficients for a specific polynomial
    pub fn get_coefficients(&self, index: usize) -> Option<&[i64]> {
        self.secret_coeffs.get(index).map(|v| v.as_slice())
    }

    /// Get mutable coefficients for a specific polynomial
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

    /// Validate secret key structure
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
                    i, coeffs.len(), self.params.l
                )));
            }
        }

        Ok(())
    }

    /// Check if coefficients are within expected CBD bounds
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

    /// Create secret key from existing coefficients (for testing/deserialization)
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

    /// Serialize coefficients (for storage/transmission)
    pub fn serialize_coefficients(&self) -> Vec<Vec<i64>> {
        self.secret_coeffs.clone()
    }

    /// Get coefficient statistics (for debugging)
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

    /// Standard NTT-friendly moduli for testing
    fn test_moduli() -> Vec<u64> {
        vec![
            0x1FFFFFFEA0001u64, // 562949951979521
            0x1FFFFFFE88001u64, // 562949951881217
            0x1FFFFFFE48001u64, // 562949951619073
        ]
    }

    fn create_test_params() -> Arc<PvwParameters> {
        PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(4)
            .set_l(32)
            .set_moduli(&test_moduli())
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
    }

    #[test]
    fn test_direct_coefficient_access() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let sk = SecretKey::random(&params, &mut rng).unwrap();

        // Test direct coefficient access (no conversion overhead)
        let coeffs = sk.coefficients();
        assert_eq!(coeffs.len(), params.k);

        for row in coeffs {
            assert_eq!(row.len(), params.l);
            // With CBD variance = 1, coefficients should be in {-2, -1, 0, 1, 2}
            for &coeff in row {
                assert!(
                    coeff.abs() <= 2,
                    "Coefficient {} exceeds expected bound 2 for CBD variance=1",
                    coeff
                );
            }
        }

        // Test individual coefficient access
        let first_poly_coeffs = sk.get_coefficients(0).unwrap();
        assert_eq!(first_poly_coeffs.len(), params.l);
        assert!(sk.get_coefficients(params.k).is_none());
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
    }

    #[test]
    fn test_custom_secret_variance() {
        let params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(4)
            .set_l(32)
            .set_moduli(&test_moduli())
            .set_secret_variance(2u32)
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
                    "Coefficient {} should be in [-4,4] with variance=2",
                    coeff
                );
            }
        }
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
    }

    #[test]
    fn test_from_coefficients_constructor() {
        let params = create_test_params();
        
        // Create test coefficients
        let test_coeffs = vec![
            vec![1, -1, 0, 1].into_iter().cycle().take(params.l).collect(),
            vec![0, 1, -1, 0].into_iter().cycle().take(params.l).collect(),
            vec![-1, 0, 1, -1].into_iter().cycle().take(params.l).collect(),
            vec![1, 0, 0, -1].into_iter().cycle().take(params.l).collect(),
        ];

        let sk = SecretKey::from_coefficients(params.clone(), test_coeffs.clone()).unwrap();

        assert_eq!(sk.secret_coeffs, test_coeffs);
        assert!(sk.validate().is_ok());
        assert!(sk.validate_coefficient_bounds().is_ok());
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
    }

    #[test]
    fn test_zeroize_implementation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let mut sk = SecretKey::random(&params, &mut rng).unwrap();

        // Verify we have non-zero coefficients initially
        let has_nonzero = sk.secret_coeffs
            .iter()
            .any(|row| row.iter().any(|&coeff| coeff != 0));
        assert!(has_nonzero, "Secret key should have some non-zero coefficients");

        // Zeroize the secret key
        sk.zeroize();

        // Verify coefficients are zeroed
        assert!(sk.secret_coeffs.is_empty());
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
    }

    #[test]
    fn test_empty_parameters_edge_case() {
        let params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(0)
            .set_l(32)
            .set_moduli(&test_moduli())
            .build_arc()
            .unwrap();

        let mut rng = thread_rng();
        let sk = SecretKey::random(&params, &mut rng).unwrap();

        assert_eq!(sk.len(), 0);
        assert!(sk.is_empty());
        assert!(sk.validate().is_ok());
        assert_eq!(sk.secret_coeffs.len(), 0);
    }
}
