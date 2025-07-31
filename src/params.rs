use crate::normal::sample_discrete_gaussian_vec;
use fhe_math::rq::{Context, Poly, Representation};
use fhe_util::sample_vec_cbd;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::{One, Zero, ToPrimitive};
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use thiserror::Error;

/// PVW-specific errors
#[derive(Error, Debug)]
pub enum PvwError {
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    #[error("Sampling error: {0}")]
    SamplingError(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
}

pub type Result<T> = std::result::Result<T, PvwError>;

/// PVW Parameters using fhe.rs Context with u32 secret variance
#[derive(Debug, Clone)]
pub struct PvwParameters {
    /// Number of parties
    pub n: usize,
    /// Security threshold (t < n/2)
    pub t: usize,
    /// LWE dimension
    pub k: usize,
    /// Redundancy parameter ℓ (number of coefficients)
    pub l: usize,
    /// Secret key variance (always 1 for minimal coefficients)
    pub secret_variance: u32,
    /// First error bound (for key generation): 2^94 - 1
    pub error_bound_1: BigInt,
    /// Second error bound (for encryption): 2^114 - 1
    pub error_bound_2: BigInt,
    /// fhe.rs Context for efficient polynomial operations
    pub context: Arc<Context>,
}

/// Builder for PVW parameters following fhe.rs patterns
#[derive(Debug, Default)]
pub struct PvwParametersBuilder {
    n: Option<usize>,
    k: Option<usize>,
    l: Option<usize>,
    moduli: Option<Vec<u64>>,
    secret_variance: Option<u32>,
}

impl PvwParametersBuilder {
    /// Create a new parameter builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the number of parties
    pub fn set_parties(mut self, n: usize) -> Self {
        self.n = Some(n);
        self
    }

    /// Set the LWE dimension
    pub fn set_dimension(mut self, k: usize) -> Self {
        self.k = Some(k);
        self
    }

    /// Set the redundancy parameter ℓ (number of coefficients)
    pub fn set_l(mut self, l: usize) -> Self {
        self.l = Some(l);
        self
    }

    /// Set the RNS moduli chain
    pub fn set_moduli(mut self, moduli: &[u64]) -> Self {
        self.moduli = Some(moduli.to_vec());
        self
    }

    /// Set the secret key variance (defaults to 1 if not set)
    pub fn set_secret_variance(mut self, variance: u32) -> Self {
        self.secret_variance = Some(variance);
        self
    }

    /// Build the parameters with automatic variance calculation
    pub fn build(self) -> Result<PvwParameters> {
        let n = self
            .n
            .ok_or_else(|| PvwError::InvalidParameters("n not set".to_string()))?;
        let k = self
            .k
            .ok_or_else(|| PvwError::InvalidParameters("k not set".to_string()))?;
        let l = self
            .l
            .ok_or_else(|| PvwError::InvalidParameters("l not set".to_string()))?;
        let moduli = self
            .moduli
            .ok_or_else(|| PvwError::InvalidParameters("moduli not set".to_string()))?;

        // Validate l is power of 2 (for NTT efficiency)
        if l == 0 || (l & (l - 1)) != 0 {
            return Err(PvwError::InvalidParameters(
                "l must be power of 2".to_string(),
            ));
        }

        // Fixed bounds based on your specification:
        
        // 1. Secret key variance (defaults to 1 for minimal coefficients)
        let secret_variance = self.secret_variance.unwrap_or(1u32);

        // 2. Error 1 bound: 2^94 - 1
        let error_bound_1 = BigInt::from(2u128.pow(94)) - BigInt::from(1u32);

        // 3. Error 2 bound: 2^114 - 1  
        let error_bound_2 = BigInt::from(2u128.pow(114)) - BigInt::from(1u32);

        // Set t < n/2 (honest majority)
        let t = (n - 1) / 2;

        // Create fhe.rs Context
        let context = Context::new_arc(&moduli, l)
            .map_err(|e| PvwError::InvalidParameters(format!("Context creation failed: {}", e)))?;

        Ok(PvwParameters {
            n,
            t,
            k,
            l,
            secret_variance,
            error_bound_1,
            error_bound_2,
            context,
        })
    }

    /// Build with Arc wrapper (following fhe.rs pattern)
    pub fn build_arc(self) -> Result<Arc<PvwParameters>> {
        Ok(Arc::new(self.build()?))
    }
}

impl PvwParameters {
    /// Sample secret key polynomial with variance = 1 (CBD with minimal coefficients)
    pub fn sample_secret_polynomial<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Poly> {
        // Convert u32 variance to usize for sample_vec_cbd
        let coeffs = sample_vec_cbd(self.l, self.secret_variance as usize, rng).map_err(|e| {
            PvwError::SamplingError(format!("CBD sampling failed: {}", e))
        })?;

        let mut poly = Poly::from_coefficients(&coeffs, &self.context).map_err(|e| {
            PvwError::SamplingError(format!("Failed to create polynomial: {:?}", e))
        })?;

        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Sample error polynomial (level 1) using discrete Gaussian sampling
    pub fn sample_error_1<R: RngCore + CryptoRng>(&self, _rng: &mut R) -> Result<Poly> {
        // Use discrete Gaussian sampling with bound - returns Vec<BigInt>
        let coeffs_bigint = sample_discrete_gaussian_vec(&self.error_bound_1, self.l);
        
        // Convert BigInt coefficients to i64 for polynomial creation
        let coeffs_i64: Vec<i64> = coeffs_bigint
            .iter()
            .map(|c| c.to_i64().unwrap_or(0)) // Handle conversion, defaulting to 0 if too large
            .collect();

        let mut poly = Poly::from_coefficients(&coeffs_i64, &self.context).map_err(|e| {
            PvwError::SamplingError(format!("Failed to create error polynomial: {:?}", e))
        })?;

        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Sample error polynomial (level 2) using discrete Gaussian sampling
    pub fn sample_error_2<R: RngCore + CryptoRng>(&self, _rng: &mut R) -> Result<Poly> {
        // Use discrete Gaussian sampling with bound - returns Vec<BigInt>
        let coeffs_bigint = sample_discrete_gaussian_vec(&self.error_bound_2, self.l);
        
        // Convert BigInt coefficients to i64 for polynomial creation
        let coeffs_i64: Vec<i64> = coeffs_bigint
            .iter()
            .map(|c| c.to_i64().unwrap_or(0)) // Handle conversion, defaulting to 0 if too large
            .collect();

        let mut poly = Poly::from_coefficients(&coeffs_i64, &self.context).map_err(|e| {
            PvwError::SamplingError(format!("Failed to create error polynomial: {:?}", e))
        })?;

        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Compute total modulus Q = ∏ moduli
    pub fn q_total(&self) -> BigUint {
        self.context
            .moduli
            .iter()
            .map(|&m| BigUint::from(m))
            .fold(BigUint::one(), |acc, m| acc * m)
    }

    /// Compute delta = ⌊Q^(1/ℓ)⌋ for gadget vector
    pub fn delta(&self) -> BigUint {
        self.q_total().nth_root(self.l as u32)
    }

    /// Create gadget polynomial g(X) = 1 + Δ·X + Δ²·X² + ... + Δ^(ℓ-1)·X^(ℓ-1)
    pub fn gadget_polynomial(&self) -> Result<Poly> {
        let delta = self.delta();
        let q_total = self.q_total();
        let mut coefficients = Vec::with_capacity(self.l);

        let mut delta_power = BigUint::one();
        for _i in 0..self.l {
            let coeff_big = &delta_power % &q_total;
            delta_power = (&delta_power * &delta) % &q_total;
            coefficients.push(coeff_big);
        }
        
        // Convert to i64 coefficients
        let i64_coeffs: Vec<i64> = coefficients
            .iter()
            .map(|c| {
                let c_u64 = c.iter_u64_digits().next().unwrap_or(0);
                c_u64 as i64
            })
            .collect();

        let mut poly = Poly::from_coefficients(&i64_coeffs, &self.context).map_err(|e| {
            PvwError::InvalidParameters(format!("Failed to create gadget polynomial: {:?}", e))
        })?;

        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Legacy gadget vector method for backward compatibility
    pub fn gadget_vector(&self) -> Result<Vec<BigUint>> {
        let mut g = Vec::with_capacity(self.l);
        let delta = self.delta();
        let q_total = self.q_total();

        for i in 0..self.l {
            let power = self.l - 1 - i;
            let delta_power = if power == 0 {
                BigUint::one()
            } else {
                let delta_pow = delta.pow(power as u32);
                &delta_pow % &q_total
            };
            g.push(delta_power);
        }
        Ok(g)
    }

    /// Get the useful parts of the fhe.rs Context
    /// Access the moduli
    pub fn moduli(&self) -> &[u64] {
        &self.context.moduli
    }

    /// Access the RNS context (useful for CRT operations)
    pub fn rns_context(&self) -> &Arc<fhe_math::rns::RnsContext> {
        &self.context.rns
    }

    /// Access NTT operators (for efficient polynomial multiplication)
    pub fn ntt_operators(&self) -> &[fhe_math::ntt::NttOperator] {
        &self.context.ops
    }

    /// Convert scalar to constant polynomial
    pub fn scalar_to_polynomial(&self, scalar: i64) -> Result<Poly> {
        let mut coeffs = vec![0i64; self.l];
        coeffs[0] = scalar; // Place scalar in constant term

        let mut poly = Poly::from_coefficients(&coeffs, &self.context).map_err(|e| {
            PvwError::InvalidParameters(format!("Failed to create scalar polynomial: {:?}", e))
        })?;
        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard NTT-friendly moduli for testing
    fn test_moduli() -> Vec<u64> {
        vec![
            0x1FFFFFFEA0001u64, // 562949951979521
            0x1FFFFFFE88001u64, // 562949951881217
            0x1FFFFFFE48001u64, // 562949951619073
        ]
    }

    #[test]
    fn test_parameter_builder() {
        // Test with multiple NTT-friendly moduli for RNS
        let moduli = test_moduli();  // Use the helper function
        
        let params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(4)
            .set_l(32)  // Start with smaller degree
            .set_moduli(&moduli)  // Use the moduli from helper function
            .build()
            .unwrap();

        assert_eq!(params.n, 10);
        assert_eq!(params.k, 4);
        assert_eq!(params.l, 32);
        assert_eq!(params.secret_variance, 1u32);  // Default value
        assert_eq!(params.context.moduli.len(), 3);  // Should have 3 moduli
        
        // Bounds should be fixed values
        let expected_bound_1 = BigInt::from(2u128.pow(94)) - BigInt::from(1u32);
        let expected_bound_2 = BigInt::from(2u128.pow(114)) - BigInt::from(1u32);
        assert_eq!(params.error_bound_1, expected_bound_1);
        assert_eq!(params.error_bound_2, expected_bound_2);
        assert!(params.error_bound_2 > params.error_bound_1);  // Error 2 > Error 1
    }

    #[test]
    fn test_custom_secret_variance() {
        let moduli = test_moduli();
        
        let params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(4)
            .set_l(32)
            .set_moduli(&moduli)
            .set_secret_variance(2u32)  // Custom variance
            .build()
            .unwrap();

        assert_eq!(params.secret_variance, 2u32);  // Should use custom value
    }

    #[test]
    fn test_large_variance_parameters() {
        let params = PvwParametersBuilder::new()
            .set_parties(1000)
            .set_dimension(4)
            .set_l(64)  // Keep 64 for this test
            .set_moduli(&test_moduli())  // Use RNS moduli
            .build_arc()
            .unwrap();

        assert_eq!(params.l, 64);
        assert_eq!(params.secret_variance, 1u32);  // Default value
        assert_eq!(params.context.moduli.len(), 3);  // Should have 3 moduli
        
        // Test fixed bounds
        let expected_bound_1 = BigInt::from(2u128.pow(94)) - BigInt::from(1u32);
        let expected_bound_2 = BigInt::from(2u128.pow(114)) - BigInt::from(1u32);
        assert_eq!(params.error_bound_1, expected_bound_1);
        assert_eq!(params.error_bound_2, expected_bound_2);
    }

    #[test]
    fn test_fhe_rs_context_integration() {
        let params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(4)
            .set_l(32)  // Smaller degree
            .set_moduli(&test_moduli())  // Use RNS moduli
            .build_arc()
            .unwrap();

        // Verify we can use fhe.rs Context features we need
        assert_eq!(params.context.degree, 32);
        assert_eq!(params.context.moduli.len(), 3);  // Should have 3 moduli
        assert!(params.context.ops.len() > 0); // Should have NTT operators
        
        // Test that we can access the moduli through the public interface
        assert_eq!(params.moduli().len(), 3);
        assert_eq!(params.ntt_operators().len(), 3);
        
        // Verify the moduli values match what we set
        let expected_moduli = test_moduli();
        for (i, &expected) in expected_moduli.iter().enumerate() {
            assert_eq!(params.moduli()[i], expected);
        }
    }

    #[test]
    fn test_gadget_polynomial_creation() {
        let params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(4)
            .set_l(32)  // Smaller degree
            .set_moduli(&test_moduli())  // Use RNS moduli
            .build_arc()
            .unwrap();

        let gadget = params.gadget_polynomial().unwrap();

        // Should be in NTT form and use correct context
        assert_eq!(*gadget.representation(), Representation::Ntt);
        assert!(Arc::ptr_eq(&gadget.ctx, &params.context));
    }

    #[test]
    fn test_error_bound_values() {
        // Test that bounds are set correctly
        let bound_94 = BigInt::from(2u128.pow(94)) - BigInt::from(1u32);
        let bound_114 = BigInt::from(2u128.pow(114)) - BigInt::from(1u32);
        
        assert!(bound_114 > bound_94);  // Larger bound should be larger
        assert!(bound_94 > BigInt::from(0));
        assert!(bound_114 > BigInt::from(0));
        
        // Test that the bounds are very large
        assert!(bound_94.bits() >= 94);
        assert!(bound_114.bits() >= 114);
    }

    #[test]
    fn test_legacy_methods() {
        let params = PvwParametersBuilder::new()
            .set_parties(10)
            .set_dimension(4)
            .set_l(32)  // Smaller degree
            .set_moduli(&test_moduli())  // Use RNS moduli
            .build_arc()
            .unwrap();

        // Test backward compatibility methods
        let delta = params.delta();
        let gadget_vector = params.gadget_vector().unwrap();

        assert!(delta > BigUint::one());
        assert_eq!(gadget_vector.len(), params.l);
        
        // Test RNS features
        let q_total = params.q_total();
        assert!(q_total > BigUint::zero());
        println!("Total modulus Q: {}", q_total);
    }
}