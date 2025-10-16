use fhe_math::rq::Representation;
use num_bigint::BigInt;
use num_traits::Signed;
use pvw::crypto::{encrypt_all_party_shares, encrypt_broadcast, encrypt_party_shares};
use pvw::keys::public_key::{GlobalPublicKey, Party};
use pvw::params::PvwCrs;
use pvw::params::PvwParametersBuilder;
use pvw::prelude::*;
use rand::thread_rng;
use std::sync::Arc;

/// Validate encoding correctness by checking the gadget structure
///
/// This function helps verify that the encoding is working correctly
/// by checking that the gadget polynomial has the expected structure.
/// Used primarily for testing and debugging.
pub fn validate_encoding(params: &PvwParameters) -> Result<()> {
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
                "Gadget encoding incorrect at position {i}: expected {expected_power}, got {coeff}"
            )));
        }
        if i < params.l - 1 {
            expected_power *= params.delta();
        }
    }

    // Test scalar encoding
    let test_scalar = 42i64;
    let _encoded = params.encode_scalar(test_scalar)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard moduli suitable for PVW operations
    fn test_moduli() -> Vec<u64> {
        vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64]
    }

    /// Create PVW parameters for testing with moderate security settings
    fn create_test_params() -> Arc<PvwParameters> {
        let moduli = test_moduli();
        let (bound1, bound2) =
            PvwParameters::suggest_error_bounds(3, 4, 8, &moduli, 0.5).unwrap_or((50, 100));

        PvwParametersBuilder::new()
            .set_parties(3)
            .set_dimension(4)
            .set_l(8)
            .set_moduli(&moduli)
            .set_secret_variance(0.5)
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
        global_pk.generate_all_party_keys(&parties).unwrap();

        (params, global_pk, parties)
    }

    #[test]
    fn test_basic_encryption() {
        let (params, global_pk, _parties) = setup_test_system();

        let scalars = vec![10, 20, 30];
        let ciphertext = encrypt(&scalars, &global_pk).unwrap();

        assert!(ciphertext.validate().is_ok());
        assert_eq!(ciphertext.len(), params.n);
        assert_eq!(ciphertext.c1.len(), params.k);
        assert_eq!(ciphertext.c2.len(), params.n);
    }

    #[test]
    fn test_party_shares_encryption() {
        let (_params, global_pk, _parties) = setup_test_system();

        let party_shares = vec![10000, 20000, 30000];
        let ciphertext = encrypt_party_shares(&party_shares, 0, &global_pk).unwrap();

        assert!(ciphertext.validate().is_ok());
        assert_eq!(ciphertext.len(), party_shares.len());

        //Testing a different index
        let ciphertext = encrypt_party_shares(&party_shares, 1, &global_pk).unwrap();

        assert!(ciphertext.validate().is_ok());
        assert_eq!(ciphertext.len(), party_shares.len());
    }

    #[test]
    fn test_all_party_shares_encryption() {
        let (params, global_pk, _parties) = setup_test_system();

        let all_shares = vec![
            vec![11, 12, 13], // Party 0's shares
            vec![21, 22, 23], // Party 1's shares
            vec![31, 32, 33], // Party 2's shares
        ];

        let ciphertexts = encrypt_all_party_shares(&all_shares, &global_pk).unwrap();

        assert_eq!(ciphertexts.len(), params.n);
        for ct in &ciphertexts {
            assert!(ct.validate().is_ok());
            assert_eq!(ct.len(), params.n);
        }
    }

    #[test]
    fn test_broadcast_encryption() {
        let (params, global_pk, _parties) = setup_test_system();

        let broadcast_value = 999;
        let ciphertext = encrypt_broadcast(broadcast_value, &global_pk).unwrap();

        assert!(ciphertext.validate().is_ok());
        assert_eq!(ciphertext.len(), params.n);
    }

    #[test]
    fn test_encoding_validation() {
        let params = create_test_params();

        // This should pass for correctly configured parameters
        let result = validate_encoding(&params);
        assert!(result.is_ok(), "Encoding validation failed: {result:?}");
    }

    #[test]
    fn test_ciphertext_access_methods() {
        let (_params, global_pk, _parties) = setup_test_system();

        let scalars = vec![1, 2, 3];
        let ciphertext = encrypt(&scalars, &global_pk).unwrap();

        // Test access methods
        assert_eq!(ciphertext.c1_components().len(), global_pk.params.k);
        assert_eq!(ciphertext.c2_components().len(), global_pk.params.n);

        for i in 0..global_pk.params.n {
            assert!(ciphertext.get_party_ciphertext(i).is_some());
        }
        assert!(
            ciphertext
                .get_party_ciphertext(global_pk.params.n)
                .is_none()
        );
    }

    #[test]
    fn test_invalid_inputs() {
        let (_params, global_pk, _parties) = setup_test_system();

        // Wrong number of scalars
        let wrong_scalars = vec![1, 2]; // Should be 3
        let result = encrypt(&wrong_scalars, &global_pk);
        assert!(result.is_err());

        let wrong_scalars2 = vec![1, 2, 3, 4]; // Should be 3
        let result2 = encrypt(&wrong_scalars2, &global_pk);
        assert!(result2.is_err());

        // Invalid party index
        let party_shares = vec![1, 2, 3];
        let result = encrypt_party_shares(&party_shares, 999, &global_pk);
        assert!(result.is_err());

        // Wrong number of shares per party
        let wrong_all_shares = vec![
            vec![1, 2],    // Wrong length
            vec![3, 4, 5], // Correct length
            vec![6, 7, 8], // Correct length
        ];
        let result = encrypt_all_party_shares(&wrong_all_shares, &global_pk);
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
            .set_secret_variance(3.0) // Large variance
            .set_error_bounds_u32(1000, 2000) // Large error bounds
            .build_arc()
            .unwrap();

        let mut rng = thread_rng();
        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);
        global_pk.generate_all_party_keys(&parties).unwrap();

        let scalars = vec![1, 2, 3];
        let _ciphertext = encrypt(&scalars, &global_pk).unwrap();
        // Should print warning about correctness condition
    }

    #[test]
    fn test_decryption_l16() {
        // Test with l=16 parameters
        let moduli = vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64];
        let num_parties = 10;

        let (bound1, bound2) =
            PvwParameters::suggest_error_bounds(num_parties, 4, 16, &moduli, 0.5)
                .expect("Should find parameters for l=16");

        let params = PvwParametersBuilder::new()
            .set_parties(num_parties)
            .set_dimension(4)
            .set_l(16)
            .set_moduli(&moduli)
            .set_secret_variance(0.5)
            .set_error_bounds_u32(bound1, bound2)
            .build_arc()
            .expect("Should create parameters");

        let mut rng = thread_rng();

        // Create parties and global public key
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let mut parties = Vec::new();
        for i in 0..num_parties {
            let party = Party::new(i, &params, &mut rng).unwrap();
            global_pk.generate_and_add_party(&party, &mut rng).unwrap();
            parties.push(party);
        }

        // Create test vectors (smaller values for reliability)
        let all_party_vectors: Vec<Vec<u64>> = (0..num_parties)
            .map(|dealer_id| {
                (1..=num_parties)
                    .map(|j| (dealer_id * 100 + j) as u64)
                    .collect()
            })
            .collect();

        // Encrypt
        let all_ciphertexts = encrypt_all_party_shares(&all_party_vectors, &global_pk).unwrap();

        let mut total_correct = 0;
        let mut total_values = 0;

        for (party_idx, party) in parties.iter().enumerate() {
            let decrypted_shares =
                decrypt_party_shares(&all_ciphertexts, &party.secret_key, party_idx).unwrap();

            for (dealer_idx, &decrypted_value) in decrypted_shares.iter().enumerate() {
                let expected_value = all_party_vectors[dealer_idx][party_idx];
                if decrypted_value == expected_value {
                    total_correct += 1;
                }
                total_values += 1;
            }
        }

        let success_rate = (total_correct as f64 / total_values as f64) * 100.0;
        println!("Decryption success rate: {success_rate:.1}%");

        // Should have high success rate
        assert!(
            success_rate >= 95.0,
            "Decryption should achieve >95% success rate"
        );
    }

    #[test]
    fn test_rounding_division() {
        // Test the rounding division implementation
        let test_cases = [
            (BigInt::from(7), BigInt::from(3), BigInt::from(2)), // 7/3 = 2.33... -> 2
            (BigInt::from(8), BigInt::from(3), BigInt::from(3)), // 8/3 = 2.67... -> 3
            (BigInt::from(-7), BigInt::from(3), BigInt::from(-2)), // -7/3 = -2.33... -> -2
            (BigInt::from(-8), BigInt::from(3), BigInt::from(-3)), // -8/3 = -2.67... -> -3
        ];

        for (dividend, divisor, expected) in test_cases {
            let twice_dividend = &dividend * 2;
            let rounded_quotient = if dividend.is_negative() {
                (&twice_dividend - &divisor) / (&divisor * 2)
            } else {
                (&twice_dividend + &divisor) / (&divisor * 2)
            };

            assert_eq!(
                rounded_quotient, expected,
                "Rounding division failed: {dividend} / {divisor} should be {expected}, got {rounded_quotient}"
            );
        }
    }
}
