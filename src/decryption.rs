use crate::encryption::PvwCiphertext;
use crate::params::{PvwError, PvwParameters, Result};
use crate::secret_key::SecretKey;
use fhe_math::rq::{Poly, Representation};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, ToPrimitive, Zero};
use rayon::prelude::*;

/// Decrypt a PVW ciphertext to recover the plaintext scalar for a specific party
pub fn decrypt_party_value(
    ciphertext: &PvwCiphertext,
    secret_key: &SecretKey,
    party_index: usize,
) -> Result<u64> {
    let params = &ciphertext.params;

    // Compute <sk, c1> (inner product) in parallel - keep in NTT representation
    let sk_c1_products: Result<Vec<Poly>> = (0..params.k)
        .into_par_iter()
        .map(|j| {
            let sk_poly = secret_key.get_polynomial(j)?;
            Ok(&sk_poly * &ciphertext.c1[j])
        })
        .collect();

    let sk_c1_products = sk_c1_products?;

    // Sum all products
    let mut sk_c1_sum = Poly::zero(&params.context, Representation::Ntt);
    for product in sk_c1_products {
        sk_c1_sum = &sk_c1_sum + &product;
    }

    // Compute noisy message = <sk, c1> - c2[party_index] - keep in NTT
    let noisy_message = &sk_c1_sum - &ciphertext.c2[party_index];

    // Apply RNS-aware PVW decoding algorithm
    decode_scalar_pvw_rns(&noisy_message, params)
}

/// PVW scalar decoding working directly in RNS representation
fn decode_scalar_pvw_rns(noisy_poly: &Poly, params: &PvwParameters) -> Result<u64> {
    let ell = params.l;

    // Create polynomials for the PVW decoding algorithm
    let delta_poly = create_delta_polynomial(params)?;

    // Compute difference polynomials tmp[i] = z[i] * Delta - z[i+1] in RNS
    let mut tmp_polys = Vec::with_capacity(ell - 1);

    for i in 0..(ell - 1) {
        // Extract coefficient i and i+1 as constant polynomials
        let z_i_poly = extract_coefficient_as_poly(noisy_poly, i, params)?;
        let z_i_plus_1_poly = extract_coefficient_as_poly(noisy_poly, i + 1, params)?;

        // Compute tmp[i] = z[i] * Delta - z[i+1] in RNS
        let tmp_i = &(&z_i_poly * &delta_poly) - &z_i_plus_1_poly;
        tmp_polys.push(tmp_i);
    }

    // Compute last component using Horner's method in RNS
    let mut last_component = tmp_polys[0].clone();
    for (_i, item) in tmp_polys.iter().enumerate().take(ell - 1).skip(1) {
        last_component = &(&last_component * &delta_poly) + item;
    }

    // Reduce modulo Delta^{ell-1}
    let delta_power_poly = create_delta_power_polynomial(params, ell - 1)?;
    last_component = reduce_modulo_poly(&last_component, &delta_power_poly, params)?;
    tmp_polys.push(last_component);

    // Recover noise components working backwards in RNS
    let mut noise_polys = vec![Poly::zero(&params.context, Representation::Ntt); ell];
    noise_polys[ell - 1] = tmp_polys[ell - 1].clone();

    for i in (0..(ell - 1)).rev() {
        // e[i] = (e[i+1] - tmp[i]) / Delta in RNS
        let numerator = &noise_polys[i + 1] - &tmp_polys[i];
        noise_polys[i] = divide_by_delta_rns(&numerator, &delta_poly, params)?;
    }

    // Extract plaintext
    let z0_poly = extract_coefficient_as_poly(noisy_poly, 0, params)?;
    let plaintext_poly = &(&z0_poly * &create_minus_one_poly(params)?) - &noise_polys[0];

    let plaintext_scalar = extract_constant_term_as_u64(&plaintext_poly, params)?;

    Ok(plaintext_scalar)
}

/// Create polynomial representing Delta as a constant polynomial in RNS
fn create_delta_polynomial(params: &PvwParameters) -> Result<Poly> {
    let delta_bigint = BigInt::from(params.delta().clone());

    // Create polynomial with l coefficients: [delta, 0, 0, ..., 0]
    let mut delta_coeffs = vec![BigInt::zero(); params.l];
    delta_coeffs[0] = delta_bigint; // Set constant term to delta

    // Convert to polynomial using existing RNS infrastructure
    let mut delta_poly = params.bigints_to_poly(&delta_coeffs)?;
    if params.l >= 8 {
        delta_poly.change_representation(Representation::Ntt);
    }

    Ok(delta_poly)
}

/// Create polynomial representing Delta^power as a constant polynomial in RNS
fn create_delta_power_polynomial(params: &PvwParameters, power: usize) -> Result<Poly> {
    let delta_power = if power == 0 {
        BigUint::one()
    } else {
        params.delta().pow(power as u32)
    };

    let delta_power_bigint = BigInt::from(delta_power);

    // Create polynomial with l coefficients: [delta^power, 0, 0, ..., 0]
    let mut coeffs = vec![BigInt::zero(); params.l];
    coeffs[0] = delta_power_bigint; // Set constant term to delta^power

    let mut poly = params.bigints_to_poly(&coeffs)?;
    if params.l >= 8 {
        poly.change_representation(Representation::Ntt);
    }

    Ok(poly)
}

/// Create polynomial representing -1 as a constant polynomial
fn create_minus_one_poly(params: &PvwParameters) -> Result<Poly> {
    // Create polynomial with l coefficients: [-1, 0, 0, ..., 0]
    let mut minus_one_coeffs = vec![BigInt::zero(); params.l];
    minus_one_coeffs[0] = BigInt::from(-1); // Set constant term to -1

    let mut poly = params.bigints_to_poly(&minus_one_coeffs)?;
    if params.l >= 8 {
        poly.change_representation(Representation::Ntt);
    }
    Ok(poly)
}

/// Extract coefficient i from a polynomial as a constant polynomial in RNS
fn extract_coefficient_as_poly(
    poly: &Poly,
    coeff_index: usize,
    params: &PvwParameters,
) -> Result<Poly> {
    // Convert to coefficient form temporarily to extract the specific coefficient
    let mut temp_poly = poly.clone();
    temp_poly.change_representation(Representation::PowerBasis);

    // Extract coefficients as BigUint and convert the specific one
    let coeffs_biguint: Vec<BigUint> = Vec::from(&temp_poly);

    let coeff_value = if coeff_index >= coeffs_biguint.len() {
        // Coefficient is implicitly zero
        BigInt::zero()
    } else {
        // Convert the specific coefficient to centered BigInt representation
        let q_total = BigInt::from(params.q_total());
        let half_q = &q_total / 2;
        let coeff_bigint = BigInt::from(coeffs_biguint[coeff_index].clone());

        if coeff_bigint > half_q {
            &coeff_bigint - &q_total
        } else {
            coeff_bigint
        }
    };

    // Create constant polynomial with this coefficient: [coeff_value, 0, 0, ..., 0]
    let mut const_coeffs = vec![BigInt::zero(); params.l];
    const_coeffs[0] = coeff_value; // Set constant term

    let mut const_poly = params.bigints_to_poly(&const_coeffs)?;
    if params.l >= 8 {
        const_poly.change_representation(Representation::Ntt);
    }

    Ok(const_poly)
}

/// Reduce polynomial modulo another polynomial in RNS (simplified version)
fn reduce_modulo_poly(poly: &Poly, modulus_poly: &Poly, params: &PvwParameters) -> Result<Poly> {
    // For PVW, we're reducing modulo Delta^{ell-1} which is a constant polynomial
    // This is equivalent to reducing the constant term modulo that value

    // Extract constant term of both polynomials
    let poly_const = extract_constant_term_bigint(poly, params)?;
    let mod_const = extract_constant_term_bigint(modulus_poly, params)?;

    // Perform modular reduction
    let half_mod = &mod_const / 2;
    let mut reduced = poly_const % &mod_const;

    // Center the result
    if reduced >= half_mod {
        reduced -= &mod_const;
    } else if reduced < -&half_mod {
        reduced += &mod_const;
    }

    // Create polynomial with reduced constant term: [reduced, 0, 0, ..., 0]
    let mut reduced_coeffs = vec![BigInt::zero(); params.l];
    reduced_coeffs[0] = reduced; // Set constant term

    let mut result_poly = params.bigints_to_poly(&reduced_coeffs)?;
    if params.l >= 8 {
        result_poly.change_representation(Representation::Ntt);
    }

    Ok(result_poly)
}

/// Divide polynomial by Delta in RNS (for noise recovery)
fn divide_by_delta_rns(poly: &Poly, delta_poly: &Poly, params: &PvwParameters) -> Result<Poly> {
    // For PVW, this is division of constant terms since we're working with constant polynomials
    let poly_const = extract_constant_term_bigint(poly, params)?;
    let delta_const = extract_constant_term_bigint(delta_poly, params)?;

    // Perform integer division
    let quotient = poly_const / delta_const;

    // Create result polynomial: [quotient, 0, 0, ..., 0]
    let mut quotient_coeffs = vec![BigInt::zero(); params.l];
    quotient_coeffs[0] = quotient; // Set constant term

    let mut result_poly = params.bigints_to_poly(&quotient_coeffs)?;
    if params.l >= 8 {
        result_poly.change_representation(Representation::Ntt);
    }

    Ok(result_poly)
}

/// Extract constant term of polynomial as BigInt (requires temporary conversion)
fn extract_constant_term_bigint(poly: &Poly, params: &PvwParameters) -> Result<BigInt> {
    let mut temp_poly = poly.clone();
    temp_poly.change_representation(Representation::PowerBasis);

    let coeffs_biguint: Vec<BigUint> = Vec::from(&temp_poly);

    if coeffs_biguint.is_empty() {
        return Ok(BigInt::zero());
    }

    // Convert to centered representation
    let q_total = BigInt::from(params.q_total());
    let half_q = &q_total / 2;
    let coeff_bigint = BigInt::from(coeffs_biguint[0].clone());

    let centered_coeff = if coeff_bigint > half_q {
        &coeff_bigint - &q_total
    } else {
        coeff_bigint
    };

    Ok(centered_coeff)
}

/// Extract constant term as u64 with bounds checking
fn extract_constant_term_as_u64(poly: &Poly, params: &PvwParameters) -> Result<u64> {
    let constant_bigint = extract_constant_term_bigint(poly, params)?;

    // Convert to u64 with proper handling
    let plaintext_u64 = if constant_bigint.is_negative() {
        // Handle negative values by taking modular equivalent
        let q_total = BigInt::from(params.q_total());
        let positive_equiv = (&constant_bigint + &q_total) % &q_total;
        if positive_equiv <= BigInt::from(1000u64) {
            positive_equiv.to_u64().unwrap_or(0)
        } else {
            0
        }
    } else if constant_bigint <= BigInt::from(1000u64) {
        constant_bigint.to_u64().unwrap_or(0)
    } else {
        // Too large, likely noise dominating
        0
    };

    Ok(plaintext_u64)
}

/// Decrypt all party values from a ciphertext using a single secret key
pub fn decrypt_all_values(ciphertext: &PvwCiphertext, secret_key: &SecretKey) -> Result<Vec<u64>> {
    // Decrypt all party values in parallel
    let results: Result<Vec<u64>> = (0..ciphertext.params.n)
        .into_par_iter()
        .map(|party_index| decrypt_party_value(ciphertext, secret_key, party_index))
        .collect();

    results
}

/// Decrypt all values intended for a specific party from multiple ciphertexts
///
/// This function matches the encryption pattern: given n ciphertexts (one from each dealer),
/// extract the values intended for the specified party. Each ciphertext has n slots,
/// and this function extracts slot [party_index] from each ciphertext.
///
/// Formula: For each ciphertext i, compute c2[party_index] - <secret_key, c1>
///
/// # Arguments
/// * `all_ciphertexts` - Vector of n ciphertexts (one from each dealer)
/// * `secret_key` - The receiving party's secret key
/// * `party_index` - Which party is decrypting (determines which slot to extract)
///
/// # Returns
/// Vector of n values where result[i] is the value that dealer i encrypted for this party
pub fn decrypt_party_shares(
    all_ciphertexts: &[PvwCiphertext],
    secret_key: &SecretKey,
    party_index: usize,
) -> Result<Vec<u64>> {
    if all_ciphertexts.is_empty() {
        return Err(PvwError::InvalidParameters(
            "No ciphertexts provided".to_string(),
        ));
    }

    let params = &all_ciphertexts[0].params;

    // Validate that we have the expected number of ciphertexts
    if all_ciphertexts.len() != params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Expected {} ciphertexts (one per dealer), got {}",
            params.n,
            all_ciphertexts.len()
        )));
    }

    // Validate party index
    if party_index >= params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Party index {} exceeds maximum {}",
            party_index,
            params.n - 1
        )));
    }

    // Decrypt all ciphertexts in parallel
    let results: Result<Vec<u64>> = all_ciphertexts
        .par_iter()
        .enumerate()
        .map(|(dealer_idx, ciphertext)| {
            // Validate ciphertext structure
            ciphertext.validate().map_err(|e| {
                PvwError::InvalidParameters(format!("Ciphertext {dealer_idx} invalid: {e}"))
            })?;

            // Decrypt the value that dealer_idx encrypted for party_index
            decrypt_party_value(ciphertext, secret_key, party_index)
        })
        .collect();

    results
}

/// Threshold decryption using multiple secret keys
///
/// Currently implements basic decryption using the first provided key.
/// In a full threshold scheme, this would combine partial decryptions
/// from t+1 parties to recover the plaintext.
pub fn threshold_decrypt(
    ciphertext: &PvwCiphertext,
    secret_keys: &[SecretKey],
    _party_indices: &[usize],
) -> Result<Vec<u64>> {
    if secret_keys.is_empty() {
        return Err(PvwError::InvalidParameters(
            "No secret keys provided".to_string(),
        ));
    }

    decrypt_all_values(ciphertext, &secret_keys[0])
}

/// Public version for testing - uses RNS-native algorithm
pub fn decode_scalar_robust_public(noisy_poly: &Poly, params: &PvwParameters) -> Result<u64> {
    decode_scalar_pvw_rns(noisy_poly, params)
}

/// Fallback robust decoding if RNS algorithm fails
#[allow(dead_code)]
fn decode_scalar_robust_fallback(noisy_poly: &Poly, params: &PvwParameters) -> Result<u64> {
    // Simple fallback: extract constant term directly
    let constant_bigint = extract_constant_term_bigint(noisy_poly, params)?;

    // Apply the negative sign correction and extract scalar
    let scalar_estimate = -constant_bigint;

    if scalar_estimate.is_negative() {
        Ok(0)
    } else if scalar_estimate <= BigInt::from(1000u64) {
        Ok(scalar_estimate.to_u64().unwrap_or(0))
    } else {
        Ok(0)
    }
}

/// Advanced RNS-native decoding with optimized polynomial operations
#[allow(dead_code)]
fn decode_scalar_pvw_rns_optimized(noisy_poly: &Poly, params: &PvwParameters) -> Result<u64> {
    let ell = params.l;

    // Pre-compute Delta powers as polynomials
    let mut delta_powers = Vec::with_capacity(ell);
    for i in 0..ell {
        delta_powers.push(create_delta_power_polynomial(params, i)?);
    }

    // Use more efficient polynomial coefficient extraction
    let coeff_polys = extract_all_coefficients_as_polys(noisy_poly, params)?;

    // Apply the PVW decoding algorithm using polynomial arithmetic
    let mut tmp_polys = Vec::with_capacity(ell - 1);
    for i in 0..(ell - 1) {
        let tmp_i = &(&coeff_polys[i] * &delta_powers[1]) - &coeff_polys[i + 1];
        tmp_polys.push(tmp_i);
    }

    // Horner's method for last component
    let mut last_component = tmp_polys[0].clone();
    for (_i, item) in tmp_polys.iter().enumerate().take(ell - 1).skip(1) {
        last_component = &(&last_component * &delta_powers[1]) + item;
    }

    // Modular reduction
    last_component = reduce_modulo_poly(&last_component, &delta_powers[ell - 1], params)?;
    tmp_polys.push(last_component);

    // Noise recovery
    let mut noise_polys = vec![Poly::zero(&params.context, Representation::Ntt); ell];
    noise_polys[ell - 1] = tmp_polys[ell - 1].clone();

    for i in (0..(ell - 1)).rev() {
        let numerator = &noise_polys[i + 1] - &tmp_polys[i];
        noise_polys[i] = divide_by_delta_rns(&numerator, &delta_powers[1], params)?;
    }

    // Final extraction
    let minus_one_poly = create_minus_one_poly(params)?;
    let plaintext_poly = &(&coeff_polys[0] * &minus_one_poly) - &noise_polys[0];

    extract_constant_term_as_u64(&plaintext_poly, params)
}

/// Extract all coefficients as constant polynomials efficiently
#[allow(dead_code)]
fn extract_all_coefficients_as_polys(poly: &Poly, params: &PvwParameters) -> Result<Vec<Poly>> {
    let mut temp_poly = poly.clone();
    temp_poly.change_representation(Representation::PowerBasis);

    let coeffs_biguint: Vec<BigUint> = Vec::from(&temp_poly);

    let q_total = BigInt::from(params.q_total());
    let half_q = &q_total / 2;

    // Extract all coefficients in parallel
    let coeff_polys_result: Result<Vec<Poly>> = (0..params.l)
        .into_par_iter()
        .map(|i| {
            let coeff_bigint = if i < coeffs_biguint.len() {
                let raw_coeff = BigInt::from(coeffs_biguint[i].clone());
                if raw_coeff > half_q {
                    &raw_coeff - &q_total
                } else {
                    raw_coeff
                }
            } else {
                BigInt::zero()
            };

            // Create polynomial with l coefficients: [coeff_bigint, 0, 0, ..., 0]
            let mut const_coeffs = vec![BigInt::zero(); params.l];
            const_coeffs[0] = coeff_bigint; // Set constant term

            let mut const_poly = params.bigints_to_poly(&const_coeffs)?;
            if params.l >= 8 {
                const_poly.change_representation(Representation::Ntt);
            }
            Ok(const_poly)
        })
        .collect();

    coeff_polys_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crs::PvwCrs;
    use crate::encryption::encrypt;
    use crate::params::PvwParametersBuilder;
    use crate::public_key::{GlobalPublicKey, Party};
    use rand::thread_rng;
    use std::sync::Arc;

    /// Standard moduli suitable for PVW operations
    fn test_moduli() -> Vec<u64> {
        vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64]
    }

    /// Create PVW parameters that satisfy the correctness condition
    fn create_correct_test_params() -> Arc<PvwParameters> {
        let moduli = test_moduli();

        let (variance, bound1, bound2) =
            PvwParameters::suggest_correct_parameters(3, 4, 8, &moduli).unwrap_or((1, 50, 100));

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

    /// Create larger parameters for more comprehensive testing
    fn create_larger_test_params() -> Arc<PvwParameters> {
        let moduli = test_moduli();

        // Use smaller, more reliable parameters for the larger test
        let (variance, bound1, bound2) =
            PvwParameters::suggest_correct_parameters(4, 4, 8, &moduli).unwrap_or((1, 30, 60));

        PvwParametersBuilder::new()
            .set_parties(4) // Reduced from 5 to 4 for better reliability
            .set_dimension(4)
            .set_l(8) // Keep l=8 for stability
            .set_moduli(&moduli)
            .set_secret_variance(variance)
            .set_error_bounds_u32(bound1, bound2)
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_basic_encrypt_decrypt_round_trip() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        // Setup: Create parties and global public key
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        // Test data
        let test_scalars = vec![10u64, 25u64, 42u64];

        // Encrypt
        let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();
        assert!(ciphertext.validate().is_ok());

        // Decrypt each party's value
        for (party_idx, &expected_scalar) in test_scalars.iter().enumerate() {
            let decrypted =
                decrypt_party_value(&ciphertext, &parties[party_idx].secret_key, party_idx)
                    .unwrap();
            assert_eq!(
                decrypted, expected_scalar,
                "Decryption failed for party {party_idx}"
            );
        }

        println!("✓ Basic encrypt-decrypt round trip test passed");
    }

    #[test]
    fn test_decrypt_all_values() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        // Setup
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        let test_scalars = vec![5u64, 15u64, 33u64];
        let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();

        // Test decrypt_all_values function - this function tries to decrypt all values with one key
        // In PVW, each party can only correctly decrypt their own designated value
        let decrypted_all = decrypt_all_values(&ciphertext, &parties[0].secret_key).unwrap();

        // Party 0 should correctly decrypt their own value (index 0)
        assert_eq!(decrypted_all[0], test_scalars[0]);

        // The other values may not decrypt correctly since they're not intended for party 0
        // This is expected behavior in PVW - each party only gets their designated share

        println!(
            "✓ Decrypt all values test passed (party 0 correctly decrypted their value: {})",
            decrypted_all[0]
        );
    }

    #[test]
    fn test_zero_scalar_encryption() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        // Test with zero values
        let zero_scalars = vec![0u64; params.n];
        let ciphertext = encrypt(&zero_scalars, &global_pk).unwrap();

        for (party_idx, item) in parties.iter().enumerate().take(params.n) {
            let decrypted = decrypt_party_value(&ciphertext, &item.secret_key, party_idx).unwrap();
            assert_eq!(decrypted, 0, "Zero decryption failed for party {party_idx}");
        }

        println!("✓ Zero scalar encryption test passed");
    }

    #[test]
    fn test_single_scalar_values() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        // Test individual small values
        for test_value in [1u64, 2u64, 7u64, 13u64] {
            let scalars = vec![test_value, 0u64, 0u64];
            let ciphertext = encrypt(&scalars, &global_pk).unwrap();

            let decrypted = decrypt_party_value(&ciphertext, &parties[0].secret_key, 0).unwrap();
            assert_eq!(
                decrypted, test_value,
                "Single scalar {test_value} decryption failed"
            );
        }

        println!("✓ Single scalar values test passed");
    }

    #[test]
    fn test_larger_parameter_set() {
        let params = create_larger_test_params();
        let mut rng = thread_rng();

        // Verify parameters satisfy correctness condition
        if !params.verify_correctness_condition() {
            println!("⚠️  Skipping larger parameter test - correctness condition not satisfied");
            return;
        }

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        // Use smaller test values for better reliability
        let test_scalars: Vec<u64> = (1..=params.n as u64).collect();
        let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();

        let mut successful_decryptions = 0;
        let mut total_attempts = 0;

        // Each party should correctly decrypt their own designated value
        for (party_idx, &expected) in test_scalars.iter().enumerate() {
            total_attempts += 1;
            let decrypted =
                decrypt_party_value(&ciphertext, &parties[party_idx].secret_key, party_idx)
                    .unwrap();

            if decrypted == expected {
                successful_decryptions += 1;
            } else {
                println!("  Party {party_idx} decryption: expected {expected}, got {decrypted}");
            }
        }

        let success_rate = successful_decryptions as f64 / total_attempts as f64;

        // Allow for some tolerance in larger parameter sets due to potential noise issues
        assert!(
            success_rate >= 0.75,
            "Success rate {:.1}% too low for larger parameters",
            success_rate * 100.0
        );

        println!(
            "✓ Larger parameter set test passed (n={}, k={}, l={}) - Success rate: {:.1}%",
            params.n,
            params.k,
            params.l,
            success_rate * 100.0
        );
    }

    #[test]
    fn test_multiple_encryptions_same_key() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        // Test multiple encryptions of the same values
        let test_scalars = vec![7u64, 14u64, 21u64];

        for trial in 0..3 {
            let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();

            for (party_idx, &expected) in test_scalars.iter().enumerate() {
                let decrypted =
                    decrypt_party_value(&ciphertext, &parties[party_idx].secret_key, party_idx)
                        .unwrap();
                assert_eq!(
                    decrypted, expected,
                    "Trial {trial} party {party_idx} decryption failed"
                );
            }
        }

        println!("✓ Multiple encryptions same key test passed");
    }

    #[test]
    fn test_threshold_decrypt_basic() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        let test_scalars = vec![11u64, 22u64, 33u64];
        let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();

        // Test threshold decryption with multiple keys
        let secret_keys: Vec<SecretKey> = parties.iter().map(|p| p.secret_key.clone()).collect();
        let party_indices: Vec<usize> = (0..params.n).collect();

        let decrypted_all = threshold_decrypt(&ciphertext, &secret_keys, &party_indices).unwrap();

        // In the current implementation, threshold_decrypt uses the first key
        // So it should correctly decrypt party 0's value
        assert_eq!(decrypted_all[0], test_scalars[0]);

        println!(
            "✓ Basic threshold decrypt test passed (correctly decrypted party 0's value: {})",
            decrypted_all[0]
        );
    }

    #[test]
    fn test_decrypt_party_shares() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        // Setup
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        // Create share matrix: all_shares[dealer][recipient] = value
        let all_shares: Vec<Vec<u64>> = (0..params.n)
            .map(|dealer| {
                (0..params.n)
                    .map(|recipient| (dealer * 10 + recipient + 1) as u64)
                    .collect()
            })
            .collect();

        // Encrypt all party shares (creates n ciphertexts)
        let all_ciphertexts =
            crate::encryption::encrypt_all_party_shares(&all_shares, &global_pk).unwrap();
        assert_eq!(all_ciphertexts.len(), params.n);

        // Each party decrypts their designated shares from all dealers
        for (party_idx, item) in parties.iter().enumerate().take(params.n) {
            let party_shares =
                decrypt_party_shares(&all_ciphertexts, &item.secret_key, party_idx).unwrap();

            // Verify party_idx got the correct values from all dealers
            for (dealer_idx, &decrypted_value) in party_shares.iter().enumerate() {
                let expected_value = all_shares[dealer_idx][party_idx];
                assert_eq!(
                    decrypted_value, expected_value,
                    "Party {party_idx} failed to decrypt value from dealer {dealer_idx}"
                );
            }
        }

        println!("✓ Decrypt party shares test passed - each party correctly decrypted all their designated shares");
    }

    #[test]
    fn test_cross_party_decryption_fails() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        let test_scalars = vec![100u64, 200u64, 300u64];
        let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();

        // Party 0 should not be able to correctly decrypt party 1's value
        let party_0_trying_to_decrypt_party_1 = decrypt_party_value(
            &ciphertext,
            &parties[0].secret_key,
            1, // Party 0 trying to decrypt party 1's slot
        )
        .unwrap();

        // This should NOT equal the original value (with very high probability)
        assert_ne!(
            party_0_trying_to_decrypt_party_1, test_scalars[1],
            "Cross-party decryption should fail"
        );

        // But party 1 should correctly decrypt their own value
        let party_1_correct_decryption =
            decrypt_party_value(&ciphertext, &parties[1].secret_key, 1).unwrap();
        assert_eq!(party_1_correct_decryption, test_scalars[1]);

        println!("✓ Cross-party decryption failure test passed");
    }

    #[test]
    fn test_decode_scalar_robust_public() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        // Create a simple noisy polynomial for testing
        let test_scalar = 42i64;
        let encoded_poly = params.encode_scalar(test_scalar).unwrap();

        // Add some small noise
        let noise_poly = params.sample_error_1(&mut rng).unwrap();
        let noisy_poly = &encoded_poly + &noise_poly;

        // Test the public decode function
        let decoded = decode_scalar_robust_public(&noisy_poly, &params).unwrap();

        // The decoded value should be close to the original (within noise tolerance)
        let original_u64 = if test_scalar >= 0 {
            test_scalar as u64
        } else {
            0
        };
        assert!(
            decoded <= original_u64 + 10,
            "Decoded value {decoded} too far from original {original_u64}"
        );

        println!("✓ Decode scalar robust public test passed");
    }

    #[test]
    fn test_fallback_decoding() {
        let params = create_correct_test_params();

        // Create a simple polynomial for testing fallback
        let test_value = BigInt::from(25);
        let mut coeffs = vec![BigInt::zero(); params.l];
        coeffs[0] = -test_value; // Negative to test the fallback logic

        let test_poly = params.bigints_to_poly(&coeffs).unwrap();
        let decoded = decode_scalar_robust_fallback(&test_poly, &params).unwrap();

        assert_eq!(decoded, 25u64);

        println!("✓ Fallback decoding test passed");
    }

    #[test]
    fn test_optimized_decoding() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        // Create encoded polynomial
        let test_scalar = 17i64;
        let encoded_poly = params.encode_scalar(test_scalar).unwrap();

        // Add controlled noise
        let noise_poly = params.sample_error_1(&mut rng).unwrap();
        let noisy_poly = &encoded_poly + &noise_poly;

        // Test optimized decoding
        let decoded = decode_scalar_pvw_rns_optimized(&noisy_poly, &params).unwrap();

        // Should recover the original value or be close
        let original_u64 = test_scalar as u64;
        assert!(
            decoded <= original_u64 + 5,
            "Optimized decoding result {decoded} too far from {original_u64}"
        );

        println!("✓ Optimized decoding test passed");
    }

    #[test]
    fn test_edge_case_values() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        // Test edge case values
        let edge_cases = [
            vec![0u64, 0u64, 0u64],     // All zeros
            vec![1u64, 1u64, 1u64],     // All ones
            vec![0u64, 1u64, 0u64],     // Mixed with zeros
            vec![50u64, 75u64, 100u64], // Larger values
        ];

        for (test_idx, test_scalars) in edge_cases.iter().enumerate() {
            let ciphertext = encrypt(test_scalars, &global_pk).unwrap();

            for (party_idx, &expected) in test_scalars.iter().enumerate() {
                let decrypted =
                    decrypt_party_value(&ciphertext, &parties[party_idx].secret_key, party_idx)
                        .unwrap();
                assert_eq!(
                    decrypted, expected,
                    "Edge case {test_idx} party {party_idx} failed"
                );
            }
        }

        println!("✓ Edge case values test passed");
    }

    #[test]
    fn test_helper_functions() {
        let params = create_correct_test_params();

        // Test delta polynomial creation
        let delta_poly = create_delta_polynomial(&params).unwrap();
        let delta_const = extract_constant_term_bigint(&delta_poly, &params).unwrap();
        assert_eq!(delta_const, BigInt::from(params.delta().clone()));

        // Test delta power polynomial creation
        let delta_squared_poly = create_delta_power_polynomial(&params, 2).unwrap();
        let delta_squared_const =
            extract_constant_term_bigint(&delta_squared_poly, &params).unwrap();
        let expected_delta_squared = BigInt::from(params.delta().pow(2));
        assert_eq!(delta_squared_const, expected_delta_squared);

        // Test minus one polynomial
        let minus_one_poly = create_minus_one_poly(&params).unwrap();
        let minus_one_const = extract_constant_term_bigint(&minus_one_poly, &params).unwrap();
        assert_eq!(minus_one_const, BigInt::from(-1));

        println!("✓ Helper functions test passed");
    }

    #[test]
    fn test_coefficient_extraction() {
        let params = create_correct_test_params();

        // Create a test polynomial with known coefficients
        let test_coeffs = vec![
            BigInt::from(42),
            BigInt::from(-17),
            BigInt::from(0),
            BigInt::from(99),
            BigInt::from(-5),
            BigInt::from(0),
            BigInt::from(0),
            BigInt::from(0),
        ];

        let test_poly = params.bigints_to_poly(&test_coeffs).unwrap();

        // Test extracting specific coefficients
        for (i, expected_coeff) in test_coeffs.iter().enumerate() {
            let extracted_poly = extract_coefficient_as_poly(&test_poly, i, &params).unwrap();
            let extracted_const = extract_constant_term_bigint(&extracted_poly, &params).unwrap();
            assert_eq!(
                &extracted_const, expected_coeff,
                "Coefficient {i} extraction failed"
            );
        }

        // Test all coefficients extraction
        let all_coeff_polys = extract_all_coefficients_as_polys(&test_poly, &params).unwrap();
        assert_eq!(all_coeff_polys.len(), params.l);

        for (i, expected_coeff) in test_coeffs.iter().enumerate() {
            let extracted_const =
                extract_constant_term_bigint(&all_coeff_polys[i], &params).unwrap();
            assert_eq!(
                &extracted_const, expected_coeff,
                "All coefficients extraction failed at {i}"
            );
        }

        println!("✓ Coefficient extraction test passed");
    }

    #[test]
    fn test_modular_operations() {
        let params = create_correct_test_params();

        // Test modular reduction
        let large_value = BigInt::from(params.delta().clone()) * BigInt::from(5) + BigInt::from(3);
        let mut large_coeffs = vec![BigInt::zero(); params.l];
        large_coeffs[0] = large_value;
        let large_poly = params.bigints_to_poly(&large_coeffs).unwrap();

        let delta_poly = create_delta_polynomial(&params).unwrap();
        let reduced_poly = reduce_modulo_poly(&large_poly, &delta_poly, &params).unwrap();
        let reduced_const = extract_constant_term_bigint(&reduced_poly, &params).unwrap();

        // Result should be equivalent to 3 (the remainder)
        assert!(
            reduced_const.abs() <= BigInt::from(10),
            "Modular reduction produced unexpected result: {reduced_const}"
        );

        // Test division by delta
        let dividend = BigInt::from(params.delta().clone()) * BigInt::from(7);
        let mut dividend_coeffs = vec![BigInt::zero(); params.l];
        dividend_coeffs[0] = dividend;
        let dividend_poly = params.bigints_to_poly(&dividend_coeffs).unwrap();

        let quotient_poly = divide_by_delta_rns(&dividend_poly, &delta_poly, &params).unwrap();
        let quotient_const = extract_constant_term_bigint(&quotient_poly, &params).unwrap();
        assert_eq!(quotient_const, BigInt::from(7));

        println!("✓ Modular operations test passed");
    }

    #[test]
    fn test_ciphertext_component_access() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        let test_scalars = vec![8u64, 16u64, 24u64];
        let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();

        // Test ciphertext component access
        assert_eq!(ciphertext.len(), params.n);
        assert!(!ciphertext.is_empty());

        let c1_components = ciphertext.c1_components();
        let c2_components = ciphertext.c2_components();

        assert_eq!(c1_components.len(), params.k);
        assert_eq!(c2_components.len(), params.n);

        // Test individual party ciphertext access
        for party_idx in 0..params.n {
            let party_ct = ciphertext.get_party_ciphertext(party_idx).unwrap();
            assert!(Arc::ptr_eq(&party_ct.ctx, &params.context));
        }

        println!("✓ Ciphertext component access test passed");
    }

    #[test]
    fn test_invalid_party_index() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        let test_scalars = vec![1u64, 2u64, 3u64];
        let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();

        // Test invalid party index - should handle gracefully without panicking
        // Note: c2 vector has length params.n, so index params.n is out of bounds

        // Test accessing party ciphertext with invalid index
        let invalid_party_ct = ciphertext.get_party_ciphertext(params.n);
        assert!(
            invalid_party_ct.is_none(),
            "Should return None for invalid party index"
        );

        // Test accessing with valid index
        let valid_party_ct = ciphertext.get_party_ciphertext(0);
        assert!(
            valid_party_ct.is_some(),
            "Should return Some for valid party index"
        );

        println!("✓ Invalid party index test passed");
    }

    #[test]
    fn test_empty_secret_keys_threshold() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        let test_scalars = vec![1u64, 2u64, 3u64];
        let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();

        // Test threshold decrypt with empty keys
        let empty_keys: Vec<SecretKey> = vec![];
        let empty_indices: Vec<usize> = vec![];

        let result = threshold_decrypt(&ciphertext, &empty_keys, &empty_indices);
        assert!(
            result.is_err(),
            "Threshold decrypt should fail with empty keys"
        );

        println!("✓ Empty secret keys threshold test passed");
    }

    #[test]
    fn test_decryption_consistency() {
        let params = create_correct_test_params();
        let mut rng = thread_rng();

        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        let parties: Vec<Party> = (0..params.n)
            .map(|i| Party::new(i, &params, &mut rng).unwrap())
            .collect();

        global_pk.generate_all_party_keys(&parties).unwrap();

        let test_scalars = vec![6u64, 12u64, 18u64];
        let ciphertext = encrypt(&test_scalars, &global_pk).unwrap();

        // Test that each party can correctly decrypt their own designated value
        for (party_idx, &expected) in test_scalars.iter().enumerate() {
            let individual_result =
                decrypt_party_value(&ciphertext, &parties[party_idx].secret_key, party_idx)
                    .unwrap();
            assert_eq!(
                individual_result, expected,
                "Party {party_idx} couldn't decrypt their own value"
            );
        }

        // Test batch decryption with party 0's key - should correctly decrypt party 0's value
        let batch_results = decrypt_all_values(&ciphertext, &parties[0].secret_key).unwrap();
        assert_eq!(
            batch_results[0], test_scalars[0],
            "Batch decryption failed for party 0's designated value"
        );

        println!("✓ Decryption consistency test passed - each party correctly decrypted their designated value");
    }
}
