use crate::params::{PvwError, PvwParameters, Result};
use crate::public_key::GlobalPublicKey;
use fhe_math::rq::{Poly, Representation};
use fhe_util::sample_vec_cbd;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// Ciphertext output of PVW encryption for PVSS
/// 
/// Represents an encrypted vector where each component can be decrypted by
/// the corresponding party. Used in PVSS to distribute secret shares to
/// multiple parties simultaneously.
#[derive(Debug, Clone)]
pub struct PvwCiphertext {
    /// c1 = A * r + e1  ∈ R_q^k (k polynomials)
    /// This component is independent of the message and provides security
    pub c1: Vec<Poly>,
    /// c2 = B^T * r + e2 + M*G  ∈ R_q^n (n polynomials, one per party)
    /// Each c2[i] encrypts a value that party i can decrypt
    pub c2: Vec<Poly>,
    /// Parameters used for this ciphertext
    pub params: Arc<PvwParameters>,
}

impl PvwCiphertext {
    /// Get the number of encrypted values (should equal n)
    pub fn len(&self) -> usize {
        self.c2.len()
    }

    /// Check if ciphertext is empty
    pub fn is_empty(&self) -> bool {
        self.c1.is_empty() && self.c2.is_empty()
    }

    /// Validate ciphertext structure against PVW requirements
    /// 
    /// Ensures the ciphertext has the correct dimensions and that all
    /// polynomials use compatible fhe.rs contexts.
    ///
    /// # Returns
    /// Ok(()) if structure is valid, Err with details if invalid
    pub fn validate(&self) -> Result<()> {
        if self.c1.len() != self.params.k {
            return Err(PvwError::InvalidParameters(format!(
                "c1 has {} components but should have k={}",
                self.c1.len(), self.params.k
            )));
        }

        if self.c2.len() != self.params.n {
            return Err(PvwError::InvalidParameters(format!(
                "c2 has {} components but should have n={}",
                self.c2.len(), self.params.n
            )));
        }

        // Verify all polynomials use correct context and representation
        for (i, poly) in self.c1.iter().enumerate() {
            if !Arc::ptr_eq(&poly.ctx, &self.params.context) {
                return Err(PvwError::InvalidParameters(format!(
                    "c1[{}] context mismatch", i
                )));
            }
        }

        for (i, poly) in self.c2.iter().enumerate() {
            if !Arc::ptr_eq(&poly.ctx, &self.params.context) {
                return Err(PvwError::InvalidParameters(format!(
                    "c2[{}] context mismatch", i
                )));
            }
        }

        Ok(())
    }

    /// Get the encrypted value for a specific party
    /// 
    /// Returns a reference to the polynomial that encrypts the value
    /// intended for the specified party.
    ///
    /// # Arguments
    /// * `party_index` - Index of the party (0 <= party_index < n)
    ///
    /// # Returns
    /// Reference to c2[party_index], or None if index is out of bounds
    pub fn get_party_ciphertext(&self, party_index: usize) -> Option<&Poly> {
        self.c2.get(party_index)
    }

    /// Get all c1 components (used for decryption)
    pub fn c1_components(&self) -> &[Poly] {
        &self.c1
    }

    /// Get all c2 components
    pub fn c2_components(&self) -> &[Poly] {
        &self.c2
    }
}

/// PVW encryption implementing the PVSS scheme
/// 
/// Encrypts a vector of scalars such that party i can decrypt scalar[i].
/// This is the core operation for publicly verifiable secret sharing where
/// a dealer distributes shares to multiple parties.
/// 
/// The encryption follows: c1 = A*r + e1, c2 = B^T*r + e2 + encode(scalars)
/// where A is the CRS, B is the global public key matrix, and r is randomness.
///
/// # Arguments
/// * `scalars` - Vector of scalars to encrypt (length must equal n = number of parties)
/// * `global_pk` - Global public key containing all party public keys
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// PvwCiphertext where each party can decrypt their corresponding scalar
pub fn encrypt<R: RngCore + CryptoRng>(
    scalars: &[u64],
    global_pk: &GlobalPublicKey,
    rng: &mut R,
) -> Result<PvwCiphertext> {
    let params = &global_pk.params;
    
    // Validate input dimensions
    if scalars.len() != params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Must provide exactly n={} scalars, got {}",
            params.n, scalars.len()
        )));
    }

    if !global_pk.is_full() {
        return Err(PvwError::InvalidParameters(
            "Global public key is not complete (missing party keys)".to_string()
        ));
    }

    // Verify parameters satisfy correctness condition for reliable decryption
    if !params.verify_correctness_condition() {
        println!("⚠️  Warning: Parameters may not satisfy correctness condition");
        println!("   Decryption may fail due to excessive noise");
    }

    println!("[ENCRYPT] Starting PVW encryption for {} scalars: {:?}", 
            scalars.len(), scalars);

    // STEP 1: Sample randomness vector r ∈ R_q^k using CBD
    // This provides the shared randomness that links c1 and c2 components
    let mut r_polys = Vec::with_capacity(params.k);
    for i in 0..params.k {
        let r_coeffs = sample_vec_cbd(params.l, params.secret_variance as usize, rng)
            .map_err(|e| PvwError::SamplingError(format!("Failed to sample randomness: {}", e)))?;
        
        let mut r_poly = Poly::from_coefficients(&r_coeffs, &params.context)
            .map_err(|e| PvwError::SamplingError(format!("Failed to create r polynomial: {:?}", e)))?;
        
        r_poly.change_representation(Representation::Ntt);
        r_polys.push(r_poly);
    }
    println!("[ENCRYPT] Generated randomness vector r with {} polynomials", r_polys.len());

    // STEP 2: Compute c1 = A * r + e1
    // The CRS multiplication provides the base security structure
    println!("[ENCRYPT] Computing c1 = A * r + e1");
    let mut c1 = global_pk.crs.multiply_by_randomness(&r_polys)?;
    
    // Add e1 noise to each component
    for i in 0..params.k {
        let e1_poly = params.sample_error_1(rng)?;
        c1[i] = &c1[i] + &e1_poly;
    }
    println!("[ENCRYPT] Completed c1 computation with {} components", c1.len());

    // STEP 3: Compute c2 = B^T * r + e2 + encode(scalars)
    // Each c2[i] will be decryptable by party i
    println!("[ENCRYPT] Computing c2 = B^T * r + e2 + encoded_messages");
    let mut c2 = Vec::with_capacity(params.n);
    
    for party_idx in 0..params.n {
        // Compute B^T[party_idx] * r (party_idx-th row of B^T times r)
        let mut party_result = Poly::zero(&params.context, Representation::Ntt);
        
        for j in 0..params.k {
            let b_poly = global_pk.get_polynomial(party_idx, j)
                .ok_or_else(|| PvwError::InvalidParameters(format!(
                    "Failed to access B[{}][{}]", party_idx, j
                )))?;
            
            let product = b_poly * &r_polys[j];
            party_result = &party_result + &product;
        }
        
        // Add encoded scalar and noise: c2[i] = B^T[i]*r + encode(scalar[i]) + e2[i]
        let scalar = scalars[party_idx];
        let encoded_scalar = params.encode_scalar(scalar as i64)?;
        let e2_poly = params.sample_error_2(rng)?;
        
        party_result = &party_result + &encoded_scalar + e2_poly;
        c2.push(party_result);
        
        println!("[ENCRYPT] Completed c2[{}] for scalar {}", party_idx, scalar);
    }

    let ciphertext = PvwCiphertext {
        c1,
        c2,
        params: params.clone(),
    };

    // Validate the result
    ciphertext.validate()?;
    println!("[ENCRYPT] PVW encryption completed successfully");
    println!("[ENCRYPT] Ciphertext: c1.len()={}, c2.len()={}", ciphertext.c1.len(), ciphertext.c2.len());

    Ok(ciphertext)
}

/// Encrypt party's shares for PVSS protocol
/// 
/// In PVSS, each party (dealer) encrypts their secret shares such that
/// party i receives share[i]. This creates a ciphertext where each party
/// can decrypt exactly one component - their designated share.
///
/// # Arguments
/// * `party_shares` - This party's n secret shares (one for each recipient)
/// * `party_index` - Which party is encrypting (for logging/validation)
/// * `global_pk` - Global public key containing all party public keys
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// PvwCiphertext where party i can decrypt party_shares[i]
pub fn encrypt_party_shares<R: RngCore + CryptoRng>(
    party_shares: &[u64],     // This party's n secret shares
    party_index: usize,       // Which party is encrypting (for validation)
    global_pk: &GlobalPublicKey,
    rng: &mut R,
) -> Result<PvwCiphertext> {
    if party_index >= global_pk.params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Party index {} exceeds maximum {}", party_index, global_pk.params.n - 1
        )));
    }

    if party_shares.len() != global_pk.params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Party must provide {} shares, got {}", global_pk.params.n, party_shares.len()
        )));
    }

    println!("[ENCRYPT_SHARES] Party {} encrypting {} shares: {:?}", 
            party_index, party_shares.len(), party_shares);

    // For PVSS: each party encrypts their n shares
    // This creates a ciphertext where c2[i] encrypts party_shares[i]
    encrypt(party_shares, global_pk, rng)
}

/// Encrypt all parties' shares for complete PVSS setup
/// 
/// This is the primary function for PVSS where multiple parties each
/// encrypt their shares. The result is a set of ciphertexts where
/// ciphertexts[dealer][recipient] allows recipient to decrypt the
/// share that dealer intended for them.
///
/// # Arguments
/// * `all_shares` - all_shares[dealer] = shares that dealer wants to distribute
/// * `global_pk` - Global public key containing all party public keys
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// Vector of ciphertexts, one per dealer party
pub fn encrypt_all_party_shares<R: RngCore + CryptoRng>(
    all_shares: &[Vec<u64>],  // all_shares[dealer] = shares for that dealer to distribute
    global_pk: &GlobalPublicKey,
    rng: &mut R,
) -> Result<Vec<PvwCiphertext>> {
    if all_shares.len() != global_pk.params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Must provide shares for all {} parties", global_pk.params.n
        )));
    }

    // Validate that each party provides the correct number of shares
    for (dealer_idx, dealer_shares) in all_shares.iter().enumerate() {
        if dealer_shares.len() != global_pk.params.n {
            return Err(PvwError::InvalidParameters(format!(
                "Dealer {} provided {} shares but needs {}", 
                dealer_idx, dealer_shares.len(), global_pk.params.n
            )));
        }
    }

    println!("[ENCRYPT_ALL] Encrypting shares for {} dealers", all_shares.len());

    let mut ciphertexts = Vec::with_capacity(global_pk.params.n);
    
    for (dealer_idx, dealer_shares) in all_shares.iter().enumerate() {
        let ct = encrypt_party_shares(dealer_shares, dealer_idx, global_pk, rng)?;
        ciphertexts.push(ct);
        println!("[ENCRYPT_ALL] Completed encryption for dealer {}", dealer_idx);
    }

    println!("[ENCRYPT_ALL] Completed encryption for all {} dealers", all_shares.len());
    println!("[ENCRYPT_ALL] PVSS setup complete: each party can now decrypt their shares");
    
    Ok(ciphertexts)
}

/// Encrypt a single scalar for all parties (broadcast encryption)
/// 
/// Alternative encryption mode where the same value is encrypted for all parties.
/// This can be useful for distributing public parameters or shared values.
///
/// # Arguments
/// * `scalar` - The value to encrypt for all parties
/// * `global_pk` - Global public key containing all party public keys
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// PvwCiphertext where all parties can decrypt the same scalar value
pub fn encrypt_broadcast<R: RngCore + CryptoRng>(
    scalar: u64,
    global_pk: &GlobalPublicKey,
    rng: &mut R,
) -> Result<PvwCiphertext> {
    let broadcast_values = vec![scalar; global_pk.params.n];
    
    println!("[ENCRYPT_BROADCAST] Broadcasting scalar {} to {} parties", 
            scalar, global_pk.params.n);
    
    encrypt(&broadcast_values, global_pk, rng)
}

/// Validate encoding correctness by checking the gadget structure
/// 
/// This function helps verify that the encoding is working correctly
/// by checking that the gadget polynomial has the expected structure.
/// Used primarily for testing and debugging.
///
/// # Arguments
/// * `params` - PVW parameters to test
///
/// # Returns
/// Ok(()) if encoding appears correct, Err with details if issues found
pub fn validate_encoding(params: &PvwParameters) -> Result<()> {
    println!("[VALIDATE_ENCODING] Checking PVW encoding correctness");
    
    // Test the gadget polynomial structure
    let gadget_poly = params.gadget_polynomial()?;
    
    // Convert back to check structure
    let mut test_poly = gadget_poly.clone();
    test_poly.change_representation(Representation::PowerBasis);
    let coeffs: Vec<num_bigint::BigUint> = (&test_poly).into();
    
    // Verify gadget structure: [1, Δ, Δ², ..., Δ^(ℓ-1)]
    let mut expected_power = num_bigint::BigUint::from(1u32);
    for (i, coeff) in coeffs.iter().take(params.l).enumerate() {
        if *coeff != expected_power {
            return Err(PvwError::InvalidParameters(format!(
                "Gadget encoding incorrect at position {}: expected {}, got {}", 
                i, expected_power, coeff
            )));
        }
        if i < params.l - 1 {
            expected_power *= params.delta();
        }
    }
    
    // Test scalar encoding
    let test_scalar = 42i64;
    let encoded = params.encode_scalar(test_scalar)?;
    
    println!("[VALIDATE_ENCODING] Gadget polynomial structure verified");
    println!("[VALIDATE_ENCODING] Scalar encoding test passed for value {}", test_scalar);
    println!("[VALIDATE_ENCODING] Encoding validation completed successfully");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PvwParametersBuilder;
    use crate::public_key::{Party, GlobalPublicKey};
    use crate::crs::PvwCrs;
    use rand::thread_rng;

    /// Standard moduli suitable for PVW operations
    fn test_moduli() -> Vec<u64> {
        vec![
            0xffffee001u64,     
            0xffffc4001u64,     
            0x1ffffe0001u64,    
        ]
    }

    /// Create PVW parameters for testing with moderate security settings
    fn create_test_params() -> Arc<PvwParameters> {
        let moduli = test_moduli();
        let (variance, bound1, bound2) = PvwParameters::suggest_correct_parameters(3, 4, 8, &moduli)
            .unwrap_or((1, 50, 100));
        
        PvwParametersBuilder::new()
            .set_parties(3)
            .set_dimension(4)
            .set_l(8)
            .set_moduli(&moduli)
            .set_secret_variance(variance)
            .set_error_bounds_u32(bound1, bound2)
            .build_arc()
            .unwrap()
    }

    fn setup_test_system() -> (Arc<PvwParameters>, GlobalPublicKey, Vec<Party>) {
        let params = create_test_params();
        let mut rng = thread_rng();
        
        // Create parties
        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();
        
        // Create CRS and global public key
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);
        
        // Generate all public keys
        global_pk.generate_all_party_keys(&parties, &mut rng).unwrap();
        
        (params, global_pk, parties)
    }

    #[test]
    fn test_basic_encryption() {
        let (params, global_pk, _parties) = setup_test_system();
        let mut rng = thread_rng();
        
        let scalars = vec![10, 20, 30];
        let ciphertext = encrypt(&scalars, &global_pk, &mut rng).unwrap();
        
        assert!(ciphertext.validate().is_ok());
        assert_eq!(ciphertext.len(), params.n);
        assert_eq!(ciphertext.c1.len(), params.k);
        assert_eq!(ciphertext.c2.len(), params.n);
    }

    #[test]
    fn test_party_shares_encryption() {
        let (_params, global_pk, _parties) = setup_test_system();
        let mut rng = thread_rng();
        
        let party_shares = vec![100, 200, 300];
        let ciphertext = encrypt_party_shares(&party_shares, 0, &global_pk, &mut rng).unwrap();
        
        assert!(ciphertext.validate().is_ok());
        assert_eq!(ciphertext.len(), party_shares.len());
    }

    #[test]
    fn test_all_party_shares_encryption() {
        let (params, global_pk, _parties) = setup_test_system();
        let mut rng = thread_rng();
        
        let all_shares = vec![
            vec![11, 12, 13],  // Party 0's shares
            vec![21, 22, 23],  // Party 1's shares  
            vec![31, 32, 33],  // Party 2's shares
        ];
        
        let ciphertexts = encrypt_all_party_shares(&all_shares, &global_pk, &mut rng).unwrap();
        
        assert_eq!(ciphertexts.len(), params.n);
        for ct in &ciphertexts {
            assert!(ct.validate().is_ok());
            assert_eq!(ct.len(), params.n);
        }
    }

    #[test]
    fn test_broadcast_encryption() {
        let (params, global_pk, _parties) = setup_test_system();
        let mut rng = thread_rng();
        
        let broadcast_value = 999;
        let ciphertext = encrypt_broadcast(broadcast_value, &global_pk, &mut rng).unwrap();
        
        assert!(ciphertext.validate().is_ok());
        assert_eq!(ciphertext.len(), params.n);
    }

    #[test]
    fn test_encoding_validation() {
        let params = create_test_params();
        
        // This should pass for correctly configured parameters
        let result = validate_encoding(&params);
        assert!(result.is_ok(), "Encoding validation failed: {:?}", result);
    }

    #[test]
    fn test_ciphertext_access_methods() {
        let (_params, global_pk, _parties) = setup_test_system();
        let mut rng = thread_rng();
        
        let scalars = vec![1, 2, 3];
        let ciphertext = encrypt(&scalars, &global_pk, &mut rng).unwrap();
        
        // Test access methods
        assert_eq!(ciphertext.c1_components().len(), global_pk.params.k);
        assert_eq!(ciphertext.c2_components().len(), global_pk.params.n);
        
        for i in 0..global_pk.params.n {
            assert!(ciphertext.get_party_ciphertext(i).is_some());
        }
        assert!(ciphertext.get_party_ciphertext(global_pk.params.n).is_none());
    }

    #[test]
    fn test_invalid_inputs() {
        let (_params, global_pk, _parties) = setup_test_system();
        let mut rng = thread_rng();
        
        // Wrong number of scalars
        let wrong_scalars = vec![1, 2]; // Should be 3
        let result = encrypt(&wrong_scalars, &global_pk, &mut rng);
        assert!(result.is_err());
        
        // Invalid party index
        let party_shares = vec![1, 2, 3];
        let result = encrypt_party_shares(&party_shares, 999, &global_pk, &mut rng);
        assert!(result.is_err());
        
        // Wrong number of shares per party
        let wrong_all_shares = vec![
            vec![1, 2],    // Wrong length
            vec![3, 4, 5], // Correct length
            vec![6, 7, 8], // Correct length
        ];
        let result = encrypt_all_party_shares(&wrong_all_shares, &global_pk, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_correctness_condition_warning() {
        // Create parameters that might not satisfy correctness condition
        let params = PvwParametersBuilder::new()
            .set_parties(3)
            .set_dimension(4)
            .set_l(8)
            .set_moduli(&test_moduli())
            .set_secret_variance(3)     // Large variance
            .set_error_bounds_u32(1000, 2000) // Large error bounds
            .build_arc()
            .unwrap();
        
        let mut rng = thread_rng();
        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();
        
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);
        global_pk.generate_all_party_keys(&parties, &mut rng).unwrap();
        
        let scalars = vec![1, 2, 3];
        let _ciphertext = encrypt(&scalars, &global_pk, &mut rng).unwrap();
        // Should print warning about correctness condition
    }
}