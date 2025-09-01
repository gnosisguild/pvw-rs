use super::params::{PvwError, PvwParameters, Result};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::Serialize;
use ndarray::Array2;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::sync::Arc;

/// Common Reference String for PVW encryption
/// Contains a k × k matrix of polynomials in R_q used for multi-party encryption
#[derive(Debug, Clone)]
pub struct PvwCrs {
    /// k × k matrix of polynomials in R_q
    pub matrix: Array2<Poly>,
    /// PVW parameters used to generate this CRS
    pub params: Arc<PvwParameters>,
}

impl PvwCrs {
    /// Generate a new random CRS matrix
    ///
    /// Creates a k×k matrix of random polynomials for use in PVW encryption.
    /// All polynomials are generated in NTT representation for efficiency.
    pub fn new<R: RngCore + CryptoRng>(params: &Arc<PvwParameters>, rng: &mut R) -> Result<Self> {
        let mut matrix = Array2::from_elem(
            (params.k, params.k),
            Poly::zero(&params.context, Representation::Ntt),
        );

        // Generate each matrix element with independent randomness
        for elem in matrix.iter_mut() {
            *elem = Poly::random(&params.context, Representation::Ntt, rng);
        }

        Ok(Self {
            matrix,
            params: params.clone(),
        })
    }

    /// Generate CRS deterministically from a master seed
    ///
    /// Creates a CRS that can be reproduced by all parties using the same seed.
    /// Essential for PVSS where all participants need the same reference string.
    pub fn new_deterministic(
        params: &Arc<PvwParameters>,
        seed: <ChaCha8Rng as SeedableRng>::Seed,
    ) -> Result<Self> {
        let mut matrix = Array2::from_elem(
            (params.k, params.k),
            Poly::zero(&params.context, Representation::Ntt),
        );

        // Create master RNG from the seed
        let mut master_rng = ChaCha8Rng::from_seed(seed);

        // Generate each matrix element with independent randomness
        for elem in matrix.iter_mut() {
            let element_seed = master_rng.gen::<[u8; 32]>();
            *elem = Poly::random_from_seed(&params.context, Representation::Ntt, element_seed);
        }

        Ok(Self {
            matrix,
            params: params.clone(),
        })
    }

    /// Generate CRS deterministically from a string tag
    ///
    /// Creates a deterministic CRS that all parties can derive from a known string.
    /// Useful for PVSS where all participants need the same reference string.
    /// TODO: operate over bytes instead of strings when hashing
    pub fn new_from_tag(params: &Arc<PvwParameters>, tag: &str) -> Result<Self> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Create deterministic seed from tag
        let mut hasher = DefaultHasher::new();
        (tag.to_string() + "CRS").hash(&mut hasher);
        let seed_u64 = hasher.finish();

        // Expand to 32-byte seed
        let mut seed = [0u8; 32];
        for (i, chunk) in seed_u64.to_le_bytes().iter().cycle().take(32).enumerate() {
            seed[i] = *chunk;
        }

        Self::new_deterministic(params, seed)
    }

    /// Get the polynomial at position (i, j) in the CRS matrix
    pub fn get(&self, i: usize, j: usize) -> Option<&Poly> {
        self.matrix.get((i, j))
    }

    /// Get a mutable reference to the polynomial at position (i, j)
    pub fn get_mut(&mut self, i: usize, j: usize) -> Option<&mut Poly> {
        self.matrix.get_mut((i, j))
    }

    /// Get the dimensions of the CRS matrix
    pub fn dimensions(&self) -> (usize, usize) {
        (self.params.k, self.params.k)
    }

    /// Validate that the CRS matrix has the correct dimensions and structure
    pub fn validate(&self) -> Result<()> {
        let (rows, cols) = self.matrix.dim();
        if rows != self.params.k || cols != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "CRS matrix dimensions {}×{} don't match parameter k={}",
                rows, cols, self.params.k
            )));
        }

        // Verify all polynomials use the correct context and are in NTT form
        for poly in self.matrix.iter() {
            if !Arc::ptr_eq(&poly.ctx, &self.params.context) {
                return Err(PvwError::InvalidParameters(
                    "CRS polynomial context mismatch".to_string(),
                ));
            }
            if *poly.representation() != Representation::Ntt {
                return Err(PvwError::InvalidParameters(
                    "CRS polynomial not in NTT representation".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Matrix-vector multiplication: A * secret_key
    ///
    /// Computes the product of the CRS matrix with a secret key vector.
    /// Used in PVW public key generation: pk = sk * A + noise.
    pub fn multiply_by_secret_key(
        &self,
        secret_key: &crate::secret_key::SecretKey,
    ) -> Result<Vec<Poly>> {
        if secret_key.len() != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Secret key length {} doesn't match CRS dimension k={}",
                secret_key.len(),
                self.params.k
            )));
        }

        let mut result = Vec::with_capacity(self.params.k);

        // Compute result[i] = sum_j(secret_key[j] * A[j][i])
        for i in 0..self.params.k {
            let mut sum = Poly::zero(&self.params.context, Representation::Ntt);

            for j in 0..self.params.k {
                let sk_poly = secret_key.get_polynomial(j)?;
                let crs_poly = self
                    .get(j, i)
                    .ok_or_else(|| PvwError::InvalidParameters("Invalid CRS index".to_string()))?;

                let product = &sk_poly * crs_poly;
                sum = &sum + &product;
            }

            result.push(sum);
        }

        Ok(result)
    }

    /// Matrix-vector multiplication: A * randomness_vector
    ///
    /// Computes the product of the CRS matrix with a randomness vector.
    /// Used in PVW encryption: c1 = A * r + e1.
    pub fn multiply_by_randomness(&self, randomness: &[Poly]) -> Result<Vec<Poly>> {
        if randomness.len() != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Randomness vector length {} doesn't match CRS dimension k={}",
                randomness.len(),
                self.params.k
            )));
        }

        let mut result = Vec::with_capacity(self.params.k);

        // Compute result[i] = sum_j(A[i][j] * randomness[j])
        for i in 0..self.params.k {
            let mut sum = Poly::zero(&self.params.context, Representation::Ntt);

            for (j, randomness_poly) in randomness.iter().enumerate().take(self.params.k) {
                let crs_poly = self
                    .get(i, j)
                    .ok_or_else(|| PvwError::InvalidParameters("Invalid CRS index".to_string()))?;

                let product = crs_poly * randomness_poly;
                sum = &sum + &product;
            }

            result.push(sum);
        }

        Ok(result)
    }

    /// Get an iterator over all polynomials in the matrix
    pub fn iter(&self) -> impl Iterator<Item = &Poly> {
        self.matrix.iter()
    }

    /// Get a mutable iterator over all polynomials in the matrix
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Poly> {
        self.matrix.iter_mut()
    }

    /// Get the total number of polynomials in the CRS (k²)
    pub fn len(&self) -> usize {
        self.params.k * self.params.k
    }

    /// Check if the CRS is empty (k = 0)
    pub fn is_empty(&self) -> bool {
        self.params.k == 0
    }
}

impl Serialize for PvwCrs {
    /// Serialize the CRS to bytes
    ///
    /// Serializes the entire k×k matrix of polynomials in row-major order.
    /// The format includes dimension information for validation during deserialization.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize matrix dimensions first for validation during deserialization
        bytes.extend_from_slice(&(self.params.k as u32).to_le_bytes());

        // Serialize each polynomial in row-major order
        for poly in self.matrix.iter() {
            let poly_bytes = poly.to_bytes();
            // Store length prefix for each polynomial
            bytes.extend_from_slice(&(poly_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&poly_bytes);
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PvwParametersBuilder;
    use crate::secret_key::SecretKey;
    use rand::thread_rng;

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
            .set_secret_variance(1)
            .set_error_bounds_u32(100, 200)
            .build_arc()
            .unwrap()
    }

    /// Create PVW parameters that satisfy the correctness condition
    fn create_correct_test_params() -> Arc<PvwParameters> {
        let moduli = test_moduli();

        let (variance, bound1, bound2) =
            PvwParameters::suggest_correct_parameters(30, 64, 32, &moduli).unwrap_or((1, 50, 100));

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
    fn test_serialization() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();

        // Test serialization doesn't panic
        let bytes = crs.to_bytes();
        assert!(!bytes.is_empty());

        // Should start with the dimension
        let k_bytes = (params.k as u32).to_le_bytes();
        assert_eq!(&bytes[0..4], &k_bytes);
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
                .set_secret_variance(1)
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

        // Test with parameters that satisfy correctness condition
        if let Ok((variance, bound1, bound2)) =
            PvwParameters::suggest_correct_parameters(3, 4, 8, &moduli)
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
            .set_secret_variance(3)
            .set_error_bounds_u32(1000, 2000)
            .build_arc()
            .unwrap();

        let mut rng = thread_rng();
        let _crs = PvwCrs::new(&questionable_params, &mut rng).unwrap();
    }
}
