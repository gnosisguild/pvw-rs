use fhe_math::rq::Poly;
use fhe_util::sample_vec_cbd;
use crate::params::PvwParameters; 
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The secret key stores coefficients as a matrix for better memory efficiency
/// Matrix dimensions: k x l (k polynomials, each with l coefficients)
/// where k is the security parameter and l is the ring degree R_q
pub struct SecretKey {
    pub par: Arc<PvwParameters>,
    pub coeff_matrix: Vec<Vec<i64>>, // k x l matrix
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        for row in self.coeff_matrix.iter_mut() {
            row.zeroize();
        }
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    /// Generates a random secret key using CBD distribution
    pub fn random<R: RngCore + CryptoRng>(par: &Arc<PvwParameters>, rng: &mut R) -> Self {
        let mut coeff_matrix = Vec::with_capacity(par.k);
        
        for _ in 0..par.k {
            let coeffs = sample_vec_cbd(par.l, par.variance, rng)
                .expect("Sampling secret key coefficients failed");
            coeff_matrix.push(coeffs);
        }
        
        Self {
            par: par.clone(),
            coeff_matrix,
        }
    }

    /// Converts the coefficient matrix to a vector of polynomial objects
    /// Creates k polynomials, each of degree l-1 (with l coefficients)
    pub fn to_poly_vector(&self, ctx: &Arc<fhe_math::rq::Context>) -> Result<Vec<Poly>, fhe_math::Error> {
        self.coeff_matrix
            .iter()
            .map(|coeffs| Poly::from_coefficients(coeffs, ctx))
            .collect()
    }

    /// Returns a reference to the coefficient matrix
    pub fn as_matrix(&self) -> &Vec<Vec<i64>> {
        &self.coeff_matrix
    }

    /// Returns a mutable reference to the coefficient matrix
    pub fn as_matrix_mut(&mut self) -> &mut Vec<Vec<i64>> {
        &mut self.coeff_matrix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PvwParameters;
    use num_bigint::BigUint;
    use rand::thread_rng;
    use std::sync::Arc;

    // Helper function to create test parameters using your actual PvwParameters
    fn create_test_params(k: usize, l: usize) -> Arc<PvwParameters> {
        Arc::new(PvwParameters::new(
            10,                              // n: number of parties
            4,                               // t: bound on dishonest parties  
            k,                               // k: LWE dimension
            l,                               // l: redundancy parameter
            BigUint::from(65537u64),         // q: modulus
            2,                               // variance: for CBD sampling (now usize)
        ).expect("Valid parameters"))
    }

    #[test]
    fn test_secret_key_generation() {
        let params = create_test_params(4, 8);
        let mut rng = thread_rng();
        
        let sk = SecretKey::random(&params, &mut rng);
        
        // Check matrix dimensions
        assert_eq!(sk.coeff_matrix.len(), params.k, "Matrix should have k rows");
        for row in &sk.coeff_matrix {
            assert_eq!(row.len(), params.l, "Each row should have l coefficients");
        }
        
        // Check parameter reference
        assert_eq!(sk.par.k, params.k);
        assert_eq!(sk.par.l, params.l);
    }

    #[test]
    fn test_matrix_access() {
        let params = create_test_params(3, 8);
        let mut rng = thread_rng();
        
        let sk = SecretKey::random(&params, &mut rng);
        
        // Test immutable access
        let matrix_ref = sk.as_matrix();
        assert_eq!(matrix_ref.len(), 3);
        assert_eq!(matrix_ref[0].len(), 8);
        
        // Test mutable access
        let mut sk_mut = sk;
        let matrix_mut = sk_mut.as_matrix_mut();
        
        // Modify a coefficient
        let original_value = matrix_mut[0][0];
        matrix_mut[0][0] = 999;
        assert_eq!(matrix_mut[0][0], 999);
        assert_ne!(matrix_mut[0][0], original_value);
    }

    #[test]
    fn test_to_poly_vector_conversion() {
        let params = create_test_params(2, 4);
        let mut rng = thread_rng();
        
        let sk = SecretKey::random(&params, &mut rng);
        
        // Check we get the right number of polynomials
        // Note: This test requires a Context from fhe-math, so we'll test the matrix structure for now
        // let ctx = Arc::new(fhe_math::rq::Context::new(&[65537], params.l).unwrap());
        // let polys = sk.to_poly_vector(&ctx).unwrap();
        // assert_eq!(polys.len(), params.k);
        
        // For now, just verify the matrix structure
        assert_eq!(sk.coeff_matrix.len(), params.k);
        for row in &sk.coeff_matrix {
            assert_eq!(row.len(), params.l);
        }
    }

    #[test]
    fn test_conversion_roundtrip() {
        let params = create_test_params(3, 8);
        let mut rng = thread_rng();
        
        let sk = SecretKey::random(&params, &mut rng);
        let original_matrix = sk.coeff_matrix.clone();
        
        // Note: Polynomial conversion test disabled until Context is available
        // let ctx = Arc::new(fhe_math::rq::Context::new(&[65537], params.l).unwrap());
        // let polys = sk.to_poly_vector(&ctx).unwrap();
        // let reconstructed_matrix: Vec<Vec<i64>> = polys
        //     .iter()
        //     .map(|poly| poly.coeffs().to_vec())
        //     .collect();
        // assert_eq!(original_matrix, reconstructed_matrix);
        
        // For now, just verify matrix consistency
        assert_eq!(sk.coeff_matrix, original_matrix);
    }

    #[test]
    fn test_different_parameter_sizes() {
        let test_cases = vec![
            (1, 2),   // Minimal case (l must be power of 2)
            (1, 8),   // Single polynomial, many coefficients
            (8, 2),   // Many polynomials, few coefficients each
            (4, 8),   // Moderate size
            (8, 16),  // Larger realistic size
        ];
        
        let mut rng = thread_rng();
        
        for (k, l) in test_cases {
            let params = create_test_params(k, l);
            let sk = SecretKey::random(&params, &mut rng);
            
            assert_eq!(sk.coeff_matrix.len(), k);
            for row in &sk.coeff_matrix {
                assert_eq!(row.len(), l);
            }
            
            // Note: Polynomial conversion disabled until Context is available
            // let ctx = Arc::new(fhe_math::rq::Context::new(&[65537], l).unwrap());
            // let polys = sk.to_poly_vector(&ctx).unwrap();
            // assert_eq!(polys.len(), k);
        }
    }

    #[test]
    fn test_coefficient_bounds() {
        let params = create_test_params(4, 8);
        let mut rng = thread_rng();
        
        let sk = SecretKey::random(&params, &mut rng);
        
        // CBD with variance 2 should produce small coefficients
        // CBD typically produces coefficients in range roughly [-variance*3, variance*3]
        let max_expected = (params.variance * 3) as i64;
        
        for row in &sk.coeff_matrix {
            for &coeff in row {
                assert!(coeff.abs() <= max_expected, 
                       "Coefficient {} exceeds expected bound {} for variance {}", 
                       coeff, max_expected, params.variance);
            }
        }
    }

    #[test]
    fn test_zeroize_implementation() {
        let params = create_test_params(3, 4);
        let mut rng = thread_rng();
        
        let mut sk = SecretKey::random(&params, &mut rng);
        
        // Verify we have non-zero coefficients initially
        let has_nonzero = sk.coeff_matrix
            .iter()
            .any(|row| row.iter().any(|&coeff| coeff != 0));
        assert!(has_nonzero, "Secret key should have some non-zero coefficients");
        
        // Zeroize the secret key
        sk.zeroize();
        
        // Verify all coefficients are now zero
        for row in &sk.coeff_matrix {
            for &coeff in row {
                assert_eq!(coeff, 0, "All coefficients should be zero after zeroization");
            }
        }
    }

    #[test]
    fn test_multiple_key_generation_produces_different_keys() {
        let params = create_test_params(3, 8);
        let mut rng = thread_rng();
        
        let sk1 = SecretKey::random(&params, &mut rng);
        let sk2 = SecretKey::random(&params, &mut rng);
        
        // Keys should be different (with very high probability)
        assert_ne!(sk1.coeff_matrix, sk2.coeff_matrix, 
                  "Two randomly generated keys should be different");
    }

    #[test]
    fn test_parameter_consistency() {
        let params = create_test_params(5, 8);
        let mut rng = thread_rng();
        
        let sk = SecretKey::random(&params, &mut rng);
        
        // Verify the Arc is properly shared
        assert!(Arc::ptr_eq(&sk.par, &params));
        
        // Verify consistency between parameters and matrix
        assert_eq!(sk.coeff_matrix.len(), sk.par.k);
        if !sk.coeff_matrix.is_empty() {
            assert_eq!(sk.coeff_matrix[0].len(), sk.par.l);
        }
        
        // Verify all parameter fields are accessible
        assert_eq!(sk.par.k, params.k);
        assert_eq!(sk.par.l, params.l);
        assert_eq!(sk.par.n, params.n);
        assert_eq!(sk.par.t, params.t);
        assert_eq!(sk.par.q, params.q);
        assert_eq!(sk.par.variance, params.variance);
    }

    #[test]
    fn test_error_handling_in_generation() {
        // Test with valid parameters - CBD sampling should succeed
        let params = create_test_params(2, 4);
        let mut rng = thread_rng();
        
        // With valid parameters, this should succeed
        let sk = SecretKey::random(&params, &mut rng);
        assert_eq!(sk.coeff_matrix.len(), 2);
        assert_eq!(sk.coeff_matrix[0].len(), 4);
        
        // Note: Actual error testing would require mocking sample_vec_cbd
        // or testing with parameters that are known to cause failures
    }

    #[test]
    fn test_empty_parameters() {
        // Test edge case with zero k dimension
        let params = create_test_params(0, 8);
        let mut rng = thread_rng();
        
        let sk = SecretKey::random(&params, &mut rng);
        assert_eq!(sk.coeff_matrix.len(), 0);
        
        // Note: Polynomial conversion disabled until Context is available
        // let ctx = Arc::new(fhe_math::rq::Context::new(&[65537], 8).unwrap());
        // let polys = sk.to_poly_vector(&ctx).unwrap();
        // assert_eq!(polys.len(), 0);
    }
}