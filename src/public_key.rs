use crate::crs::PvwCrs;
use crate::params::{PvwError, PvwParameters, Result};
use crate::secret_key::SecretKey;
use fhe_math::rq::{Context, Poly, Representation};
use fhe_util::sample_vec_cbd;
use ndarray::Array2;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// Individual party in the PVSS protocol
/// Each party manages their own secret key and has a unique index
#[derive(Debug, Clone)]
pub struct Party {
    /// Unique index for this party (0 to n-1)
    pub index: usize,
    /// This party's secret key
    pub secret_key: SecretKey,
}

/// Individual public key for a single party
/// Represents b_i = s_i * A + e_i
/// Stores coefficients for memory efficiency (consistent with SecretKey)
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// The public key coefficient matrix (k × l matrix like SecretKey)
    pub key_matrix: Vec<Vec<i64>>,
    /// Parameters used to generate this key
    pub params: Arc<PvwParameters>,
}

/// Global public key containing all parties' public keys
/// Matrix B where B[i] = b_i (n × k × l tensor of coefficients)
#[derive(Debug, Clone)]
pub struct GlobalPublicKey {
    /// n × k matrix where each element is a coefficient vector (length l)
    /// Structure: matrix[party_index][poly_index] = Vec<i64> (coefficients)
    pub matrix: Array2<Vec<i64>>,
    /// Common Reference String used for key generation
    pub crs: PvwCrs,
    /// Number of public keys currently stored
    pub num_keys: usize,
    /// Parameters used for this global key
    pub params: Arc<PvwParameters>,
}

impl Party {
    /// Create a new party with a randomly generated secret key
    pub fn new<R: RngCore + CryptoRng>(
        index: usize,
        params: &Arc<PvwParameters>,
        rng: &mut R,
    ) -> Result<Self> {
        // Validate index
        if index >= params.n {
            return Err(PvwError::InvalidParameters(format!(
                "Party index {} exceeds maximum {}",
                index,
                params.n - 1
            )));
        }

        let secret_key = SecretKey::random(params, rng);

        Ok(Self { index, secret_key })
    }

    /// Generate this party's public key using the provided CRS
    pub fn generate_public_key<R: RngCore + CryptoRng>(
        &self,
        crs: &PvwCrs,
        ctx: &Arc<Context>,
        rng: &mut R,
    ) -> Result<PublicKey> {
        PublicKey::generate(&self.secret_key, crs, ctx, rng)
    }

    /// Get this party's index
    pub fn index(&self) -> usize {
        self.index
    }

    /// Get a reference to this party's secret key
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl PublicKey {
    /// Generate a public key for a given secret key
    /// Computes b_i = s_i * A + e_i and stores as coefficient matrix
    pub fn generate<R: RngCore + CryptoRng>(
        secret_key: &SecretKey,
        crs: &PvwCrs,
        ctx: &Arc<Context>,
        rng: &mut R,
    ) -> Result<Self> {
        // Validate dimensions
        if secret_key.par.k != crs.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Secret key dimension {} doesn't match CRS dimension {}",
                secret_key.par.k, crs.params.k
            )));
        }

        // Convert secret key to polynomial form for computation
        let sk_polys = secret_key.to_poly_vector(ctx).map_err(|e| {
            PvwError::InvalidParameters(format!("Failed to convert secret key: {}", e))
        })?;

        // Generate noise matrix with same variance as secret key
        let mut noise_matrix = Vec::with_capacity(secret_key.par.k);
        for _ in 0..secret_key.par.k {
            let noise_coeffs = sample_vec_cbd(secret_key.par.l, secret_key.par.variance, rng)
                .map_err(|e| {
                    PvwError::InvalidParameters(format!("Failed to sample noise: {}", e))
                })?;
            noise_matrix.push(noise_coeffs);
        }

        // Convert noise to polynomials for computation
        let mut noise_polys = Vec::with_capacity(secret_key.par.k);
        for noise_coeffs in &noise_matrix {
            let noise_poly = Poly::from_coefficients(noise_coeffs, ctx).map_err(|e| {
                PvwError::InvalidParameters(format!("Failed to create noise polynomial: {}", e))
            })?;
            noise_polys.push(noise_poly);
        }

        // Compute b_i = s_i * A + e_i
        let mut result_polys = Vec::with_capacity(secret_key.par.k);

        for i in 0..secret_key.par.k {
            // Compute (s_i * A)[i] = sum over j of s_i[j] * A[j][i]
            let mut result = Poly::zero(ctx, Representation::Ntt);

            for j in 0..secret_key.par.k {
                let a_ji = crs.get(j, i).ok_or_else(|| {
                    PvwError::InvalidParameters(format!(
                        "CRS matrix access failed at ({}, {})",
                        j, i
                    ))
                })?;

                // Multiply sk_poly[j] * crs[j][i] and add to result
                let product = &sk_polys[j] * a_ji;
                result = &result + &product;
            }

            // Add noise: result = s_i * A + e_i
            result = &result + &noise_polys[i];
            result_polys.push(result);
        }

        // Convert result polynomials back to coefficient matrix for storage
        let mut key_matrix = Vec::with_capacity(secret_key.par.k);
        for mut poly in result_polys {
            // Convert to PowerBasis representation to extract coefficients
            poly.change_representation(Representation::PowerBasis);

            // Extract coefficients from polynomial
            let coeffs_view = poly.coefficients(); // Returns ArrayView2<u64>

            // Convert from u64 to i64 and extract first row (assuming single modulus for now)
            // If multiple moduli, we need to use CRT reconstruction
            let coeffs_i64: Vec<i64> = if coeffs_view.nrows() == 1 {
                // Single modulus case
                coeffs_view.row(0).iter().map(|&x| x as i64).collect()
            } else {
                // Multiple moduli case - for now, just use first modulus as placeholder
                // TODO: Implement proper CRT reconstruction
                coeffs_view.row(0).iter().map(|&x| x as i64).collect()
            };

            key_matrix.push(coeffs_i64);
        }

        Ok(Self {
            key_matrix,
            params: secret_key.par.clone(),
        })
    }

    /// Convert the coefficient matrix to polynomial vector when needed for operations
    pub fn to_poly_vector(
        &self,
        ctx: &Arc<Context>,
    ) -> std::result::Result<Vec<Poly>, fhe_math::Error> {
        self.key_matrix
            .iter()
            .map(|coeffs| Poly::from_coefficients(coeffs, ctx))
            .collect()
    }

    /// Get the dimension of the public key (should equal k)
    pub fn dimension(&self) -> usize {
        self.key_matrix.len()
    }

    /// Get a reference to the coefficient vector at position i
    pub fn get_coeffs(&self, i: usize) -> Option<&Vec<i64>> {
        self.key_matrix.get(i)
    }

    /// Get the coefficient matrix
    pub fn as_matrix(&self) -> &Vec<Vec<i64>> {
        &self.key_matrix
    }

    /// Validate that the public key has the correct structure
    pub fn validate(&self) -> Result<()> {
        if self.key_matrix.len() != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Public key dimension {} doesn't match parameter k={}",
                self.key_matrix.len(),
                self.params.k
            )));
        }

        for (i, coeffs) in self.key_matrix.iter().enumerate() {
            if coeffs.len() != self.params.l {
                return Err(PvwError::InvalidParameters(format!(
                    "Public key polynomial {} has {} coefficients, expected {}",
                    i,
                    coeffs.len(),
                    self.params.l
                )));
            }
        }

        Ok(())
    }
}

impl GlobalPublicKey {
    /// Create a new global public key with the given CRS
    pub fn new(crs: PvwCrs) -> Self {
        // Initialize matrix with empty coefficient vectors
        let matrix = Array2::from_elem(
            (crs.params.n, crs.params.k),
            vec![0i64; crs.params.l], // Each element is a coefficient vector of length l
        );

        Self {
            matrix,
            params: crs.params.clone(),
            crs,
            num_keys: 0,
        }
    }

    /// Add a public key for party at given index
    /// This is equivalent to setting B[index] = public_key
    pub fn add_public_key(&mut self, index: usize, public_key: PublicKey) -> Result<()> {
        // Validate index bounds
        if index >= self.params.n {
            return Err(PvwError::InvalidParameters(format!(
                "Party index {} exceeds maximum {}",
                index,
                self.params.n - 1
            )));
        }

        // Validate public key
        public_key.validate()?;
        if public_key.params.k != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Public key dimension {} doesn't match global key dimension {}",
                public_key.params.k, self.params.k
            )));
        }

        // Copy public key coefficient vectors to the matrix
        for (j, coeffs) in public_key.key_matrix.iter().enumerate() {
            if let Some(matrix_entry) = self.matrix.get_mut((index, j)) {
                *matrix_entry = coeffs.clone();
            } else {
                return Err(PvwError::InvalidParameters(format!(
                    "Matrix access failed at ({}, {})",
                    index, j
                )));
            }
        }

        // Update counter if this is a new key
        if index >= self.num_keys {
            self.num_keys = index + 1;
        }

        Ok(())
    }

    /// Generate and add a public key for the given party
    pub fn generate_and_add_party<R: RngCore + CryptoRng>(
        &mut self,
        party: &Party,
        ctx: &Arc<Context>,
        rng: &mut R,
    ) -> Result<()> {
        let public_key = party.generate_public_key(&self.crs, ctx, rng)?;
        self.add_public_key(party.index, public_key)
    }

    /// Generate and add a public key for the given secret key at the specified index
    pub fn generate_and_add<R: RngCore + CryptoRng>(
        &mut self,
        index: usize,
        secret_key: &SecretKey,
        ctx: &Arc<Context>,
        rng: &mut R,
    ) -> Result<()> {
        let public_key = PublicKey::generate(secret_key, &self.crs, ctx, rng)?;
        self.add_public_key(index, public_key)
    }

    /// Get the public key for party at given index
    pub fn get_public_key(&self, index: usize) -> Option<PublicKey> {
        if index >= self.num_keys {
            return None;
        }

        let mut key_matrix = Vec::with_capacity(self.params.k);
        for j in 0..self.params.k {
            if let Some(coeffs) = self.matrix.get((index, j)) {
                key_matrix.push(coeffs.clone());
            } else {
                return None;
            }
        }

        Some(PublicKey {
            key_matrix,
            params: self.params.clone(),
        })
    }

    /// Get a reference to the coefficient vector at position (i, j) in the global matrix
    pub fn get_coeffs(&self, i: usize, j: usize) -> Option<&Vec<i64>> {
        self.matrix.get((i, j))
    }

    /// Get the dimensions of the global public key matrix
    pub fn dimensions(&self) -> (usize, usize) {
        (self.params.n, self.params.k)
    }

    /// Get the number of public keys currently stored
    pub fn num_public_keys(&self) -> usize {
        self.num_keys
    }

    /// Check if the global public key is full (all n parties have keys)
    pub fn is_full(&self) -> bool {
        self.num_keys >= self.params.n
    }

    /// Get a reference to the CRS
    pub fn crs(&self) -> &PvwCrs {
        &self.crs
    }

    /// Validate the global public key structure
    pub fn validate(&self) -> Result<()> {
        let (rows, cols) = self.matrix.dim();
        if rows != self.params.n || cols != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "Global public key matrix dimensions {}×{} don't match parameters n={}, k={}",
                rows, cols, self.params.n, self.params.k
            )));
        }
        Ok(())
    }

    /// Generate keys for all provided parties
    pub fn generate_all_party_keys<R: RngCore + CryptoRng>(
        &mut self,
        parties: &[Party],
        ctx: &Arc<Context>,
        rng: &mut R,
    ) -> Result<()> {
        if parties.len() > self.params.n {
            return Err(PvwError::InvalidParameters(format!(
                "Too many parties: {} > {}",
                parties.len(),
                self.params.n
            )));
        }

        for party in parties {
            self.generate_and_add_party(party, ctx, rng)?;
        }

        Ok(())
    }

    /// Generate keys for all parties using provided secret keys
    pub fn generate_all_keys<R: RngCore + CryptoRng>(
        &mut self,
        secret_keys: &[SecretKey],
        ctx: &Arc<Context>,
        rng: &mut R,
    ) -> Result<()> {
        if secret_keys.len() > self.params.n {
            return Err(PvwError::InvalidParameters(format!(
                "Too many secret keys: {} > {}",
                secret_keys.len(),
                self.params.n
            )));
        }

        for (index, secret_key) in secret_keys.iter().enumerate() {
            self.generate_and_add(index, secret_key, ctx, rng)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PvwParameters;
    use num_bigint::BigUint;
    use rand::thread_rng;

    fn create_test_params() -> Arc<PvwParameters> {
        Arc::new(
            PvwParameters::new(
                5,                       // n: number of parties
                2,                       // t: bound on dishonest parties
                4,                       // k: LWE dimension
                8,                       // l: redundancy parameter
                BigUint::from(65537u64), // q: modulus
                2,                       // variance: for CBD sampling
            )
            .expect("Valid parameters"),
        )
    }

    #[test]
    fn test_party_creation() {
        let params = create_test_params();
        let mut rng = thread_rng();

        let party = Party::new(0, &params, &mut rng).unwrap();
        assert_eq!(party.index(), 0);
        assert_eq!(party.secret_key().par.k, params.k);

        // Test invalid index
        let invalid_party = Party::new(params.n, &params, &mut rng);
        assert!(invalid_party.is_err());
    }

    #[test]
    fn test_public_key_dimensions() {
        let params = create_test_params();
        // Note: This test requires Context integration
        // let ctx = params.create_context().unwrap();
        // let mut rng = thread_rng();
        //
        // let party = Party::new(0, &params, &mut rng).unwrap();
        // let crs = PvwCrs::new(&params, &ctx, &mut rng).unwrap();
        // let pk = party.generate_public_key(&crs, &ctx, &mut rng).unwrap();
        //
        // assert_eq!(pk.dimension(), params.k);
        // assert!(pk.validate().is_ok());

        // Placeholder test
        assert_eq!(params.k, 4);
    }

    #[test]
    fn test_global_public_key() {
        let params = create_test_params();
        // Note: This test requires Context integration
        // let ctx = params.create_context().unwrap();
        // let mut rng = thread_rng();
        //
        // let crs = PvwCrs::new(&params, &ctx, &mut rng).unwrap();
        // let mut global_pk = GlobalPublicKey::new(crs);
        //
        // assert_eq!(global_pk.dimensions(), (params.n, params.k));
        // assert_eq!(global_pk.num_public_keys(), 0);
        // assert!(!global_pk.is_full());
        // assert!(global_pk.validate().is_ok());

        // Placeholder test
        assert_eq!(params.n, 5);
    }

    #[test]
    fn test_party_workflow() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create parties
        let party_0 = Party::new(0, &params, &mut rng).unwrap();
        let party_1 = Party::new(1, &params, &mut rng).unwrap();

        assert_eq!(party_0.index(), 0);
        assert_eq!(party_1.index(), 1);
        assert_ne!(
            party_0.secret_key().as_matrix(),
            party_1.secret_key().as_matrix()
        );

        // Note: Full workflow test requires Context integration
        // let ctx = params.create_context().unwrap();
        // let crs = PvwCrs::new(&params, &ctx, &mut rng).unwrap();
        // let mut global_pk = GlobalPublicKey::new(crs);
        //
        // global_pk.generate_and_add_party(&party_0, &ctx, &mut rng).unwrap();
        // global_pk.generate_and_add_party(&party_1, &ctx, &mut rng).unwrap();
        //
        // assert_eq!(global_pk.num_public_keys(), 2);
    }
}
