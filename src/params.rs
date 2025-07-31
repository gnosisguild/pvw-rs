use fhe_math::rq::Context;
use num_bigint::BigUint;
use num_traits::One;
use std::sync::Arc;
use thiserror::Error;

/// PVW-specific errors
#[derive(Error, Debug)]
pub enum PvwError {
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
}

pub type Result<T> = std::result::Result<T, PvwError>;

/// PVW scheme parameters following section 2.5
#[derive(Debug, Clone)]
pub struct PvwParameters {
    /// Number of parties (n in the paper)
    pub n: usize,
    /// Bound on dishonest parties (t < n/2 in the paper)
    pub t: usize,
    /// Dimension of the LWE secrets and noise vectors (k in the paper)
    pub k: usize,
    /// Redundancy parameter (ℓ in the paper)
    pub l: usize,
    /// Modulus for LWE (q in the paper)
    pub q: BigUint,
    /// Variance for secret and noise sampling (used with CBD)
    pub variance: usize,
}

impl PvwParameters {
    /// Create new PVW parameters
    pub fn new(
        n: usize,
        t: usize,
        k: usize,
        l: usize,
        q: BigUint,
        variance: usize,
    ) -> Result<Self> {
        if l == 0 {
            return Err(PvwError::InvalidParameters("l must be > 0".to_string()));
        }
        if (l & (l - 1)) != 0 {
            return Err(PvwError::InvalidParameters(
                "l must be a power of 2".to_string(),
            ));
        }
        if q < BigUint::from(2u32) {
            return Err(PvwError::InvalidParameters("q must be ≥ 2".to_string()));
        }

        Ok(Self {
            n,
            t,
            k,
            l,
            q,
            variance,
        })
    }

    /// Compute the "gadget vector" parameter delta
    /// From paper: Δ = ⌊q^(1/l)⌋
    pub fn delta(&self) -> BigUint {
        self.q.nth_root(self.l as u32)
    }

    /// Create the gadget vector g = (Δ^(l-1), ..., Δ, 1) ∈ Z_q^l
    pub fn gadget_vector(&self) -> Result<Vec<BigUint>> {
        let mut g = Vec::with_capacity(self.l);
        for i in 0..self.l {
            let power = self.l - 1 - i;
            let delta_power = if power == 0 {
                BigUint::one()
            } else {
                let delta_pow = self.delta().pow(power as u32);
                &delta_pow % &self.q
            };
            g.push(delta_power);
        }
        Ok(g)
    }
    /// Create a Context for fhe-math operations that matches these parameters
    pub fn create_context(&self) -> std::result::Result<Arc<Context>, Box<dyn std::error::Error>> {
        // Handle modulus conversion from BigUint to u64 vector
        let moduli = if self.q <= BigUint::from(u64::MAX) {
            // Single modulus case - fits in u64
            vec![self.q.to_u64_digits()[0]]
        } else {
            // Large modulus case - need CRT representation
            return Err(format!(
                "Modulus {} too large for single u64. CRT representation needed.",
                self.q
            )
            .into()); // This now works with Box<dyn std::error::Error>
        };

        // Create context with our parameters
        Context::new_arc(&moduli, self.l).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    // /// Generate the Common Reference String (CRS) random matrix A ← R_q^(k×k)
    // pub fn generate_crs<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Array2<BigUint> {
    //     let mut matrix = Array2::from_elem((self.k, self.k), BigUint::zero());
    //     for elem in matrix.iter_mut() {
    //         *elem = rng.gen_biguint_below(&self.q);
    //     }
    //     matrix
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;

    #[test]
    fn test_invalid_parameters() {
        let params = PvwParameters::new(3, 1, 4, 3, BigUint::from(1u64), 1);
        assert!(params.is_err(), "q < 2 should fail");

        let params = PvwParameters::new(3, 1, 4, 3, BigUint::from(16u64), 1);
        assert!(params.is_err(), "l=3 (not power of 2) should fail");

        let params = PvwParameters::new(3, 1, 4, 4, BigUint::from(16u64), 1);
        assert!(params.is_ok(), "l=4 (power of 2) should work");
    }

    #[test]
    fn test_delta_computation() -> Result<()> {
        // Test case 1: Simple values
        // For q = 16, l = 2: Δ = floor(16^(1/2)) = floor(4.0) = 4
        let params1 = PvwParameters::new(3, 1, 4, 2, BigUint::from(16u64), 1)?;
        let delta1 = params1.delta();
        assert_eq!(
            delta1,
            BigUint::from(4u64),
            "For q=16, l=2: delta should be 4"
        );

        // Test case 2: Another simple case
        // For q = 20, l = 4: Δ = floor(20^(1/4)) = floor(2.114...) = 2
        let params2 = PvwParameters::new(3, 1, 4, 4, BigUint::from(20u64), 1)?;
        let delta2 = params2.delta();
        assert_eq!(
            delta2,
            BigUint::from(2u64),
            "For q=20, l=4: delta should be 2"
        );

        // Test case 3: Non-perfect power
        // For q = 100, l = 2: Δ = floor(100^(1/2)) = floor(10.0) = 10
        let params3 = PvwParameters::new(3, 1, 4, 2, BigUint::from(100u64), 1)?;
        let delta3 = params3.delta();
        assert_eq!(
            delta3,
            BigUint::from(10u64),
            "For q=100, l=2: delta should be 10"
        );

        // Test case 4: Large prime (like in the original code)
        // For q = 65537, l = 8: Δ = floor(65537^(1/8)) ≈ floor(4.00...) = 4
        let params4 = PvwParameters::new(3, 1, 4, 8, BigUint::from(65537u64), 1)?;
        let delta4 = params4.delta();

        // Manual verification: 4^8 = 65536, 5^8 = 390625
        // So 65537^(1/8) should be just slightly above 4
        assert_eq!(
            delta4,
            BigUint::from(4u64),
            "For q=65537, l=8: delta should be 4"
        );

        // Debug output for manual verification (comment out for CI/CD)
        println!("✓ Delta computation tests passed");
        println!("  q=16, l=2 → Δ={}", delta1);
        println!("  q=20, l=4 → Δ={}", delta2);
        println!("  q=100, l=2 → Δ={}", delta3);
        println!("  q=65537, l=8 → Δ={}", delta4);

        Ok(())
    }

    #[test]
    fn test_gadget_vector_structure() -> Result<()> {
        // Test with q=20, l=4, Δ=2
        // Expected gadget vector: g = (2^3, 2^2, 2^1, 2^0) = (8, 4, 2, 1)
        let params = PvwParameters::new(3, 1, 4, 4, BigUint::from(20u64), 1)?;
        let gadget = params.gadget_vector()?;
        let delta = params.delta();

        println!(
            "Testing gadget vector for q={}, l={}, Δ={}",
            params.q, params.l, &delta
        );
        println!("Gadget vector: {:?}", gadget);

        // Check length
        assert_eq!(gadget.len(), params.l, "Gadget vector should have length l");

        // Check specific values for this test case
        assert_eq!(
            gadget[0],
            BigUint::from(8u64),
            "g[0] should be Δ^(l-1) = 2^3 = 8"
        );
        assert_eq!(
            gadget[1],
            BigUint::from(4u64),
            "g[1] should be Δ^(l-2) = 2^2 = 4"
        );
        assert_eq!(
            gadget[2],
            BigUint::from(2u64),
            "g[2] should be Δ^(l-3) = 2^1 = 2"
        );
        assert_eq!(
            gadget[3],
            BigUint::from(1u64),
            "g[3] should be Δ^(l-4) = 2^0 = 1"
        );

        // General property: last element should always be 1
        assert_eq!(
            gadget[params.l - 1],
            BigUint::from(1u64),
            "Last element should always be 1"
        );

        // Check that elements follow the decreasing power pattern
        for i in 0..params.l - 1 {
            let current_power = params.l - 1 - i;

            // Verify that gadget[i] = delta^current_power
            let expected = delta.pow(current_power as u32);
            assert_eq!(
                gadget[i], expected,
                "gadget[{}] should be Δ^{} = {}^{} = {}",
                i, current_power, &delta, current_power, expected
            );

            // Verify decreasing pattern: gadget[i+1] = gadget[i] / delta (when possible)
            if &gadget[i] % &delta == BigUint::zero() && i < params.l - 1 {
                assert_eq!(
                    gadget[i + 1],
                    &gadget[i] / &delta,
                    "gadget[{}] should be gadget[{}] / Δ",
                    i + 1,
                    i
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_gadget_vector_large_example() -> Result<()> {
        // Test with the parameters from the original implementation
        // q=65537, l=8, Δ=4
        // Expected: g = (4^7, 4^6, 4^5, 4^4, 4^3, 4^2, 4^1, 4^0)
        //              = (16384, 4096, 1024, 256, 64, 16, 4, 1)
        let params = PvwParameters::new(3, 1, 4, 8, BigUint::from(65537u64), 1)?;
        let gadget = params.gadget_vector()?;
        let delta = params.delta();

        println!(
            "Testing large gadget vector for q={}, l={}, Δ={}",
            params.q, params.l, &delta
        );
        println!("Gadget vector: {:?}", gadget);

        // Manual verification of expected values
        let expected = vec![
            BigUint::from(16384u64),
            BigUint::from(4096u64),
            BigUint::from(1024u64),
            BigUint::from(256u64),
            BigUint::from(64u64),
            BigUint::from(16u64),
            BigUint::from(4u64),
            BigUint::from(1u64),
        ];

        assert_eq!(gadget.len(), 8, "Should have 8 elements");
        assert_eq!(delta, BigUint::from(4u64), "Delta should be 4");

        for (i, (actual, expected_val)) in gadget.iter().zip(expected.iter()).enumerate() {
            assert_eq!(
                actual, expected_val,
                "gadget[{}] should be {} but got {}",
                i, expected_val, actual
            );
        }

        // Verify mathematical properties
        assert_eq!(gadget[7], BigUint::from(1u64), "Last element should be 1");
        assert_eq!(
            gadget[6],
            BigUint::from(4u64),
            "Second-to-last should be Δ = 4"
        );
        assert_eq!(
            gadget[0],
            BigUint::from(16384u64),
            "First element should be Δ^7 = 4^7 = 16384"
        );

        // Check that each element is delta times the next element
        for i in 0..gadget.len() - 1 {
            assert_eq!(
                gadget[i],
                &gadget[i + 1] * &delta,
                "gadget[{}] should be gadget[{}] * Δ",
                i,
                i + 1
            );
        }

        Ok(())
    }

    #[test]
    fn test_trbfv_sized_modulus() -> Result<()> {
        // Test with TRBFV-sized modulus (CRT product of ~49-bit primes)
        // Q = 0x1FFFFFFEA0001 × 0x1FFFFFFE88001 × 0x1FFFFFFE48001
        // Q ≈ 1.78 × 10^44 (146 bits)

        // Create the full CRT modulus from TRBFV parameters
        let mod1 = BigUint::from(0x1FFFFFFEA0001u64);
        let mod2 = BigUint::from(0x1FFFFFFE88001u64);
        let mod3 = BigUint::from(0x1FFFFFFE48001u64);
        let q_full = &mod1 * &mod2 * &mod3;

        // Use this massive modulus for PVW parameters
        let params = PvwParameters::new(3, 1, 4, 8, q_full, 1)?;

        // Test that delta computation works with very large modulus
        let delta = params.delta();

        println!("Testing TRBFV-sized modulus:");
        println!("  Q bits: ~146");
        println!("  Q = {}", params.q);
        println!("  Δ = {}", &delta);

        // Verify delta is reasonable (should be much smaller than q)
        assert!(&delta < &params.q, "Delta should be less than q");
        assert!(delta > BigUint::one(), "Delta should be greater than 1");

        // Test gadget vector computation with large modulus
        let gadget = params.gadget_vector()?;

        println!("  Gadget vector length: {}", gadget.len());
        println!("  First element: {}", &gadget[0]);
        println!("  Second element: {}", &gadget[1]);
        println!("  Third element: {}", &gadget[2]);
        println!("  Fourth element: {}", &gadget[3]);
        println!("  Fifth element: {}", &gadget[4]);
        println!("  Sixth element: {}", &gadget[5]);
        println!("  Seventh element: {}", &gadget[6]);
        println!("  Eighth (Last) element: {}", &gadget[7]);

        // Verify basic properties still hold
        assert_eq!(gadget.len(), params.l, "Gadget vector should have length l");
        assert_eq!(
            gadget[params.l - 1],
            BigUint::one(),
            "Last element should be 1"
        );

        // Verify decreasing pattern holds for large modulus
        for i in 0..params.l - 1 {
            if &gadget[i] % &delta == BigUint::zero() {
                assert_eq!(
                    gadget[i + 1],
                    &gadget[i] / &delta,
                    "Decreasing pattern should hold for large modulus"
                );
            }
        }

        Ok(())
    }
}
