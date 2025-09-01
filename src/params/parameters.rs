use crate::sampling::normal::sample_discrete_gaussian_vec;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Context, Poly, Representation};
use fhe_util::sample_vec_cbd;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::{One, Signed, ToPrimitive, Zero};
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

/// PVW Parameters using fhe.rs Context and polynomial representation
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
    /// Secret key variance
    pub secret_variance: u32,
    /// First error bound
    pub error_bound_1: BigInt,
    /// Second error bound (for encryption)
    pub error_bound_2: BigInt,
    /// fhe.rs Context for efficient polynomial operations
    pub context: Arc<Context>,
    /// Delta = ⌊Q^(1/ℓ)⌋ (cached for efficiency)
    pub delta: BigUint,
    /// Delta^(ℓ-1) (cached for efficiency)
    pub delta_power_l_minus_1: BigUint,
}

/// Builder for PVW parameters following fhe.rs patterns
#[derive(Debug, Default)]
pub struct PvwParametersBuilder {
    n: Option<usize>,
    k: Option<usize>,
    l: Option<usize>,
    moduli: Option<Vec<u64>>,
    secret_variance: Option<u32>,
    error_bound_1: Option<BigInt>,
    error_bound_2: Option<BigInt>,
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

    /// Set the secret key variance
    pub fn set_secret_variance(mut self, variance: u32) -> Self {
        self.secret_variance = Some(variance);
        self
    }

    /// Set the first error bound (for level 1 errors)
    pub fn set_error_bound_1(mut self, bound: BigInt) -> Self {
        self.error_bound_1 = Some(bound);
        self
    }

    /// Set the second error bound (for encryption errors)
    pub fn set_error_bound_2(mut self, bound: BigInt) -> Self {
        self.error_bound_2 = Some(bound);
        self
    }

    /// Set both error bounds at once
    pub fn set_error_bounds(mut self, bound_1: BigInt, bound_2: BigInt) -> Self {
        self.error_bound_1 = Some(bound_1);
        self.error_bound_2 = Some(bound_2);
        self
    }

    /// Set error bounds from u32 values (convenience method)
    pub fn set_error_bounds_u32(mut self, bound_1: u32, bound_2: u32) -> Self {
        self.error_bound_1 = Some(BigInt::from(bound_1));
        self.error_bound_2 = Some(BigInt::from(bound_2));
        self
    }

    /// Build the parameters with proper PVW delta calculation
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

        // Validate basic parameters
        if n == 0 {
            return Err(PvwError::InvalidParameters("n must be > 0".to_string()));
        }
        if k == 0 {
            return Err(PvwError::InvalidParameters("k must be > 0".to_string()));
        }

        // Validate l is power of 2 and >= 8 (fhe.rs requirement)
        if l < 8 || (l & (l - 1)) != 0 {
            return Err(PvwError::InvalidParameters(
                "l must be power of 2 and >= 8 (fhe.rs Context requirement)".to_string(),
            ));
        }

        // Create fhe.rs Context
        let context = Context::new_arc(&moduli, l)
            .map_err(|e| PvwError::InvalidParameters(format!("Context creation failed: {e}")))?;

        // Compute delta = ⌊Q^(1/ℓ)⌋
        let q_total = moduli
            .iter()
            .map(|&m| BigUint::from(m))
            .fold(BigUint::one(), |acc, m| acc * m);

        let delta = q_total.nth_root(l as u32);

        // Compute Delta^(ℓ-1) for gadget operations
        let delta_power_l_minus_1 = if l > 1 {
            delta.pow((l - 1) as u32)
        } else {
            BigUint::one()
        };

        // Use provided parameters or defaults
        let secret_variance = self.secret_variance.unwrap_or(1u32);
        let error_bound_1 = self.error_bound_1.unwrap_or_else(|| BigInt::from(100u32));
        let error_bound_2 = self.error_bound_2.unwrap_or_else(|| BigInt::from(200u32));
        let t = (n - 1) / 2;

        // Validate error bounds are positive
        if error_bound_1 <= BigInt::zero() {
            return Err(PvwError::InvalidParameters(
                "error_bound_1 must be positive".to_string(),
            ));
        }
        if error_bound_2 <= BigInt::zero() {
            return Err(PvwError::InvalidParameters(
                "error_bound_2 must be positive".to_string(),
            ));
        }

        Ok(PvwParameters {
            n,
            t,
            k,
            l,
            secret_variance,
            error_bound_1,
            error_bound_2,
            context,
            delta,
            delta_power_l_minus_1,
        })
    }

    /// Build with Arc wrapper (following fhe.rs pattern)
    pub fn build_arc(self) -> Result<Arc<PvwParameters>> {
        Ok(Arc::new(self.build()?))
    }
}

impl PvwParameters {
    /// Create a new PVW parameter builder (convenience method)
    pub fn builder() -> PvwParametersBuilder {
        PvwParametersBuilder::new()
    }

    /// Create parameters with all required fields set (convenience constructor)
    pub fn new(
        n: usize,
        k: usize,
        l: usize,
        moduli: &[u64],
        secret_variance: u32,
        error_bound_1: BigInt,
        error_bound_2: BigInt,
    ) -> Result<Self> {
        Self::builder()
            .set_parties(n)
            .set_dimension(k)
            .set_l(l)
            .set_moduli(moduli)
            .set_secret_variance(secret_variance)
            .set_error_bound_1(error_bound_1)
            .set_error_bound_2(error_bound_2)
            .build()
    }

    /// Create parameters with u32 error bounds (convenience constructor)
    pub fn new_with_u32_bounds(
        n: usize,
        k: usize,
        l: usize,
        moduli: &[u64],
        secret_variance: u32,
        error_bound_1: u32,
        error_bound_2: u32,
    ) -> Result<Self> {
        Self::new(
            n,
            k,
            l,
            moduli,
            secret_variance,
            BigInt::from(error_bound_1),
            BigInt::from(error_bound_2),
        )
    }

    /// Sample secret key polynomial with variance = secret_variance (CBD with coefficients)
    pub fn sample_secret_polynomial<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Poly> {
        let coeffs = sample_vec_cbd(self.l, self.secret_variance as usize, rng)
            .map_err(|e| PvwError::SamplingError(format!("CBD sampling failed: {e}")))?;

        let mut poly = Poly::from_coefficients(&coeffs, &self.context)
            .map_err(|e| PvwError::SamplingError(format!("Failed to create polynomial: {e:?}")))?;

        poly.change_representation(Representation::Ntt);
        Ok(poly)
    }

    /// Sample error polynomial (level 1) using discrete Gaussian sampling
    pub fn sample_error_1<R: RngCore + CryptoRng>(&self, _rng: &mut R) -> Result<Poly> {
        let coeffs_bigint = sample_discrete_gaussian_vec(&self.error_bound_1, self.l);
        let mut poly = self.bigints_to_poly(&coeffs_bigint)?;

        if self.l >= 8 {
            poly.change_representation(fhe_math::rq::Representation::Ntt);
        }

        Ok(poly)
    }

    /// Sample error polynomial (level 2) using discrete Gaussian sampling
    pub fn sample_error_2<R: RngCore + CryptoRng>(&self, _rng: &mut R) -> Result<Poly> {
        let coeffs_bigint = sample_discrete_gaussian_vec(&self.error_bound_2, self.l);
        let mut poly = self.bigints_to_poly(&coeffs_bigint)?;

        if self.l >= 8 {
            poly.change_representation(fhe_math::rq::Representation::Ntt);
        }

        Ok(poly)
    }

    /// Create PVW gadget polynomial: g(X) = 1 + Δ·X + Δ²·X² + ... + Δ^(ℓ-1)·X^(ℓ-1)
    /// Returns a polynomial with coefficients [1, Δ, Δ², ..., Δ^(ℓ-1)]
    pub fn gadget_polynomial(&self) -> Result<Poly> {
        let mut coefficients_bigint = Vec::with_capacity(self.l);

        // Create coefficients: [1, Δ, Δ², ..., Δ^(ℓ-1)] for X^0, X^1, X^2, ...
        let mut delta_power = BigUint::one();
        for i in 0..self.l {
            coefficients_bigint.push(BigInt::from(delta_power.clone()));

            // Compute next power for next iteration
            if i < self.l - 1 {
                delta_power *= &self.delta;
            }
        }

        let mut poly = self.bigints_to_poly(&coefficients_bigint)?;
        if self.l >= 8 {
            poly.change_representation(fhe_math::rq::Representation::Ntt);
        }

        Ok(poly)
    }

    /// Create gadget vector: [1, Δ, Δ², ..., Δ^(ℓ-1)] - polynomial coefficient order
    pub fn gadget_vector(&self) -> Vec<BigUint> {
        let mut g = Vec::with_capacity(self.l);

        let mut delta_power = BigUint::one();
        for i in 0..self.l {
            g.push(delta_power.clone());

            if i < self.l - 1 {
                delta_power *= &self.delta;
            }
        }

        g
    }

    /// Create gadget element g() as vector [Δ^(ℓ-1), Δ^(ℓ-2), ..., Δ, 1]
    /// This is used for encryption operations and is different from polynomial coefficients
    pub fn gadget_element(&self) -> Vec<BigUint> {
        let mut g = Vec::with_capacity(self.l);

        for i in 0..self.l {
            let power = (self.l - 1 - i) as u32; // ell-1, ell-2, ..., 1, 0
            let value = if power == 0 {
                BigUint::one()
            } else {
                self.delta.pow(power)
            };
            g.push(value);
        }

        g
    }

    /// Encode scalar using PVW gadget: scalar * g(X) where g(X) = 1 + Δ·X + Δ²·X² + ...
    /// Returns polynomial with coefficients [scalar*1, scalar*Δ, scalar*Δ², ...]
    pub fn encode_scalar(&self, scalar: i64) -> Result<Poly> {
        // Create polynomial representation of scalar * g(X)
        let mut coefficients_bigint = Vec::with_capacity(self.l);

        // The coefficients are: [scalar*1, scalar*Δ, scalar*Δ², ..., scalar*Δ^(ℓ-1)]
        let mut delta_power = BigUint::one();
        for i in 0..self.l {
            let coeff = BigInt::from(scalar) * BigInt::from(delta_power.clone());
            coefficients_bigint.push(coeff);

            if i < self.l - 1 {
                delta_power *= &self.delta;
            }
        }

        let mut poly = self.bigints_to_poly(&coefficients_bigint)?;
        if self.l >= 8 {
            poly.change_representation(fhe_math::rq::Representation::Ntt);
        }

        Ok(poly)
    }

    /// Access delta value
    pub fn delta(&self) -> &BigUint {
        &self.delta
    }

    /// Access delta^(ℓ-1)
    pub fn delta_power_l_minus_1(&self) -> &BigUint {
        &self.delta_power_l_minus_1
    }

    /// Compute total modulus Q = ∏ moduli
    pub fn q_total(&self) -> BigUint {
        self.context
            .moduli
            .iter()
            .map(|&m| BigUint::from(m))
            .fold(BigUint::one(), |acc, m| acc * m)
    }

    /// Access the moduli
    pub fn moduli(&self) -> &[u64] {
        &self.context.moduli
    }

    /// Access the RNS context
    pub fn rns_context(&self) -> &Arc<fhe_math::rns::RnsContext> {
        &self.context.rns
    }

    /// Access NTT operators
    pub fn ntt_operators(&self) -> &[fhe_math::ntt::NttOperator] {
        &self.context.ops
    }

    /// Convert scalar to constant polynomial
    pub fn scalar_to_polynomial(&self, scalar: i64) -> Result<Poly> {
        let mut coeffs = vec![0i64; self.l];
        coeffs[0] = scalar;

        let poly = Poly::from_coefficients(&coeffs, &self.context).map_err(|e| {
            PvwError::InvalidParameters(format!("Failed to create scalar polynomial: {e:?}"))
        })?;

        // Note: from_coefficients creates in PowerBasis, convert to NTT if needed
        let mut result = poly;
        result.change_representation(Representation::Ntt);
        Ok(result)
    }

    /// Convert a vector of BigInt coefficients into a Poly using proper RNS reduction
    /// Handles multi-modulus structure with correct modular arithmetic
    pub fn bigints_to_poly(&self, bigints: &[BigInt]) -> Result<Poly> {
        if bigints.len() != self.l {
            return Err(PvwError::InvalidParameters(format!(
                "Expected {} coefficients, got {}",
                self.l,
                bigints.len()
            )));
        }

        // Get moduli from context
        let moduli = self.context.moduli();
        let d = self.l;

        // Create a matrix: rows = moduli, cols = coefficients
        // Shape: (num_moduli, degree)
        let mut coeffs_rns = vec![0u64; moduli.len() * d];

        for (col, coeff) in bigints.iter().enumerate() {
            for (row, &modulus) in moduli.iter().enumerate() {
                // Reduce coefficient mod q_i
                let mut reduced = coeff % BigInt::from(modulus);
                if reduced.is_negative() {
                    reduced += BigInt::from(modulus);
                }
                let u64_value = reduced.to_u64().ok_or_else(|| {
                    PvwError::InvalidParameters(format!(
                        "Residue doesn't fit in u64 for coefficient {col}, modulus {modulus}"
                    ))
                })?;

                coeffs_rns[row * d + col] = u64_value;
            }
        }

        // Convert flat vector into Array2<u64> with shape (num_moduli, degree)
        let coeff_matrix =
            ndarray::Array2::from_shape_vec((moduli.len(), d), coeffs_rns).map_err(|_| {
                PvwError::InvalidParameters("Failed to create coefficient matrix".to_string())
            })?;

        // Use fhe.rs public API to create polynomial from Array2
        let poly = Poly::try_convert_from(
            coeff_matrix,
            &self.context,
            false, // disallow variable time operations
            Representation::PowerBasis,
        )
        .map_err(|e| {
            PvwError::InvalidParameters(format!(
                "Failed to create polynomial from RNS coefficients: {e:?}"
            ))
        })?;

        Ok(poly)
    }

    /// Verify PVW parameter correctness including security condition
    pub fn verify_parameters(&self) -> Result<bool> {
        // Check delta computation
        let q_total = self.q_total();
        let expected_delta = q_total.nth_root(self.l as u32);
        if self.delta != expected_delta {
            return Ok(false);
        }

        // Check gadget vector properties
        let gadget_vec = self.gadget_vector();
        if gadget_vec.len() != self.l {
            return Ok(false);
        }

        if gadget_vec[0] != BigUint::one() {
            return Ok(false);
        }

        // Check that last element is Delta^(ℓ-1)
        if gadget_vec[gadget_vec.len() - 1] != self.delta_power_l_minus_1 {
            return Ok(false);
        }

        // Check PVW correctness condition
        if !self.verify_correctness_condition() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify the PVW correctness condition:
    /// delta_power_l_minus_1 > error_bound_1 * (24 * sqrt(l^2*k*n) + 31.8*k*l) + error_bound_2 * (2.37 * sqrt(n*l) + 1.7*n)
    ///
    /// Note we are using this temporarily. For our case, we will have different conditions as we
    /// are not using the same protocol for the zk proofs.
    pub fn verify_correctness_condition(&self) -> bool {
        use std::f64;

        let n = self.n as f64;
        let k = self.k as f64;
        let l = self.l as f64;

        // Convert error bounds to f64 for calculation
        let error_bound_1_f64 = self.error_bound_1.to_f64().unwrap_or(f64::INFINITY);
        let error_bound_2_f64 = self.error_bound_2.to_f64().unwrap_or(f64::INFINITY);

        // Calculate the first sqrt term: sqrt(l^2*k*n)
        let first_sqrt_term = if l * l * k * n > 0.0 {
            (l * l * k * n).sqrt()
        } else {
            f64::INFINITY
        };

        let first_term = error_bound_1_f64 * (24.0 * first_sqrt_term + 31.8 * k * l);

        // Calculate the second term: error_bound_2 * (2.37/sqrt(n*l) + 1.7*n)

        let second_sqrt_term = if n * l > 0.0 {
            (n * l).sqrt()
        } else {
            f64::INFINITY
        };
        let second_term = error_bound_2_f64 * (2.37 * second_sqrt_term + 1.7 * n);

        // Total bound
        let total_bound = first_term + second_term;

        // Convert delta_power_l_minus_1 to f64 for comparison
        let delta_power_f64 = self.delta_power_l_minus_1.to_f64().unwrap_or(0.0);

        delta_power_f64 > total_bound
    }

    /// Get suggested parameters that satisfy the correctness condition
    pub fn suggest_correct_parameters(
        n: usize,
        k: usize,
        l: usize,
        moduli: &[u64],
    ) -> Result<(u32, u32, u32)> {
        // Create a temporary parameter set to compute delta
        let temp_params = Self::builder()
            .set_parties(n)
            .set_dimension(k)
            .set_l(l)
            .set_moduli(moduli)
            .set_secret_variance(1)
            .set_error_bounds_u32(1, 1) // Minimal bounds for computation
            .build()?;

        let delta_power_f64 = temp_params.delta_power_l_minus_1.to_f64().unwrap_or(0.0);

        // Calculate the coefficients
        let n_f64 = n as f64;
        let k_f64 = k as f64;
        let l_f64 = l as f64;

        let coeff1 = 24.0 * (l_f64 * l_f64 * k_f64 * n_f64).sqrt() + 31.8 * k_f64 * l_f64;
        let coeff2 = 2.37 * (n_f64 * l_f64).sqrt() + 1.7 * n_f64 * l_f64;

        // Start with small bounds and check if they work
        for error_bound_1 in [100, 200, 500, 1000, 2000, 5000].into_iter().rev() {
            for error_bound_2 in [100, 200, 500, 1000, 2000, 5000].into_iter().rev() {
                let total_bound = error_bound_1 as f64 * coeff1 + error_bound_2 as f64 * coeff2;
                if delta_power_f64 > total_bound {
                    // Add safety margin
                    return Ok((1, error_bound_1, error_bound_2));
                }
            }
        }

        Err(PvwError::InvalidParameters(
            "Cannot find suitable error bounds for given parameters".to_string(),
        ))
    }
}

// Example usage with the specified moduli
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pvw_parameters_with_custom_moduli() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        // Try different parameter combinations
        let test_cases = [
            (3, 8, 8),      // Small parameters
            (10, 128, 16),  // Medium parameters
            (50, 2048, 32), // Larger parameters
        ];

        for (n, k, l) in test_cases {
            println!("\n=== Testing parameters: n={n}, k={k}, l={l} ===");

            // Get suggested correct parameters
            match PvwParameters::suggest_correct_parameters(n, k, l, &moduli) {
                Ok((secret_variance, error_bound_1, error_bound_2)) => {
                    println!(
                        "Suggested parameters found: variance={secret_variance}, bound1={error_bound_1}, bound2={error_bound_2}"
                    );

                    // Create parameters with suggested bounds
                    match PvwParameters::new_with_u32_bounds(
                        n,
                        k,
                        l,
                        &moduli,
                        secret_variance,
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
                Err(e) => println!("✗ Could not find suitable parameters: {e}"),
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
            .set_secret_variance(2)
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
            1,       // secret_variance
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

        // Method 3: Get suggested correct parameters first
        if let Ok((variance, bound1, bound2)) =
            PvwParameters::suggest_correct_parameters(5, 128, 16, &moduli)
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
}

#[cfg(test)]
mod bigint_conversion_tests {
    use super::*;
    use num_traits::{One, Zero};

    #[test]
    fn test_bigints_to_poly_basic() {
        let moduli = [0xffffee001, 0xffffc4001, 0x1ffffe0001];

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 1, 100, 200)
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

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 1, 100, 200)
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

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 1, 100, 200)
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

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 1, 100, 200)
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

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 1, 100, 200)
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

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 1, 100, 200)
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

        let params = PvwParameters::new_with_u32_bounds(3, 64, 8, &moduli, 1, 100, 200)
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
