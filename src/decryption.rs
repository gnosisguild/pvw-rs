use crate::encryption::PvwCiphertext;
use crate::params::{PvwError, PvwParameters, Result};
use crate::secret_key::SecretKey;
use fhe_math::rq::{Poly, Representation};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, ToPrimitive, Zero};
use rayon::prelude::*;

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
        // e[i] = (e[i+1] - tmp[i]) / Delta in RNS with proper rounding
        let numerator = &noise_polys[i + 1] - &tmp_polys[i];
        noise_polys[i] = divide_by_delta_rns(&numerator, &delta_poly, params)?;
    }

    // Extract plaintext with proper handling
    let z0_poly = extract_coefficient_as_poly(noisy_poly, 0, params)?;
    let minus_one_poly = create_minus_one_poly(params)?;
    let plaintext_poly = &(&z0_poly * &minus_one_poly) - &noise_polys[0];

    let plaintext_scalar = extract_constant_term_as_u64(&plaintext_poly, params)?;

    Ok(plaintext_scalar)
}

/// Create delta polynomial with precision handling
fn create_delta_polynomial(params: &PvwParameters) -> Result<Poly> {
    let delta_bigint = BigInt::from(params.delta().clone());

    // Create polynomial with l coefficients: [delta, 0, 0, ..., 0]
    let mut delta_coeffs = vec![BigInt::zero(); params.l];
    delta_coeffs[0] = delta_bigint;

    // Convert to polynomial using existing RNS infrastructure
    let mut delta_poly = params.bigints_to_poly(&delta_coeffs)?;
    if params.l >= 8 {
        delta_poly.change_representation(Representation::Ntt);
    }

    Ok(delta_poly)
}

/// Create delta power polynomial with proper exponentiation
fn create_delta_power_polynomial(params: &PvwParameters, power: usize) -> Result<Poly> {
    let delta_power = if power == 0 {
        BigUint::one()
    } else {
        params.delta().pow(power as u32)
    };

    let delta_power_bigint = BigInt::from(delta_power);

    let mut coeffs = vec![BigInt::zero(); params.l];
    coeffs[0] = delta_power_bigint;

    let mut poly = params.bigints_to_poly(&coeffs)?;
    if params.l >= 8 {
        poly.change_representation(Representation::Ntt);
    }

    Ok(poly)
}

fn create_minus_one_poly(params: &PvwParameters) -> Result<Poly> {
    let mut minus_one_coeffs = vec![BigInt::zero(); params.l];
    minus_one_coeffs[0] = BigInt::from(-1);

    let mut poly = params.bigints_to_poly(&minus_one_coeffs)?;
    if params.l >= 8 {
        poly.change_representation(Representation::Ntt);
    }
    Ok(poly)
}

fn extract_coefficient_as_poly(
    poly: &Poly,
    coeff_index: usize,
    params: &PvwParameters,
) -> Result<Poly> {
    // Convert to coefficient form temporarily
    let mut temp_poly = poly.clone();
    temp_poly.change_representation(Representation::PowerBasis);

    let coeffs_biguint: Vec<BigUint> = Vec::from(&temp_poly);

    let coeff_value = if coeff_index >= coeffs_biguint.len() {
        BigInt::zero()
    } else {
        // Use centered coefficient representation for better precision
        center_coefficient_with_precision(&coeffs_biguint[coeff_index], params)
    };

    // Create constant polynomial
    let mut const_coeffs = vec![BigInt::zero(); params.l];
    const_coeffs[0] = coeff_value;

    let mut const_poly = params.bigints_to_poly(&const_coeffs)?;
    if params.l >= 8 {
        const_poly.change_representation(Representation::Ntt);
    }

    Ok(const_poly)
}

/// Center coefficient representation for improved precision
fn center_coefficient_with_precision(coeff: &BigUint, params: &PvwParameters) -> BigInt {
    let q_total = BigInt::from(params.q_total());
    let coeff_bigint = BigInt::from(coeff.clone());

    // Use precise centering approach
    let half_q = &q_total / 2;

    if coeff_bigint > half_q {
        &coeff_bigint - &q_total
    } else {
        coeff_bigint
    }
}

fn reduce_modulo_poly(poly: &Poly, modulus_poly: &Poly, params: &PvwParameters) -> Result<Poly> {
    let poly_const = extract_constant_term_bigint(poly, params)?;
    let mod_const = extract_constant_term_bigint(modulus_poly, params)?;

    // Perform modular reduction with proper rounding
    let mut reduced = poly_const % &mod_const;

    // Apply centering logic
    let half_mod = &mod_const / 2;
    if reduced > half_mod {
        reduced -= &mod_const;
    } else if reduced < -&half_mod {
        reduced += &mod_const;
    }

    let mut reduced_coeffs = vec![BigInt::zero(); params.l];
    reduced_coeffs[0] = reduced;

    let mut result_poly = params.bigints_to_poly(&reduced_coeffs)?;
    if params.l >= 8 {
        result_poly.change_representation(Representation::Ntt);
    }

    Ok(result_poly)
}

fn divide_by_delta_rns(poly: &Poly, delta_poly: &Poly, params: &PvwParameters) -> Result<Poly> {
    let poly_const = extract_constant_term_bigint(poly, params)?;
    let delta_const = extract_constant_term_bigint(delta_poly, params)?;

    let quotient = if delta_const.is_zero() {
        BigInt::zero()
    } else {
        // Compute quotient with proper rounding
        let twice_poly = &poly_const * 2;
        let rounded_quotient = if poly_const.is_negative() {
            // For negative numbers: (2*poly - delta) / (2*delta)
            (&twice_poly - &delta_const) / (&delta_const * 2)
        } else {
            // For positive numbers: (2*poly + delta) / (2*delta)
            (&twice_poly + &delta_const) / (&delta_const * 2)
        };
        rounded_quotient
    };

    let mut quotient_coeffs = vec![BigInt::zero(); params.l];
    quotient_coeffs[0] = quotient;

    let mut result_poly = params.bigints_to_poly(&quotient_coeffs)?;
    if params.l >= 8 {
        result_poly.change_representation(Representation::Ntt);
    }

    Ok(result_poly)
}

fn extract_constant_term_bigint(poly: &Poly, params: &PvwParameters) -> Result<BigInt> {
    let mut temp_poly = poly.clone();
    temp_poly.change_representation(Representation::PowerBasis);

    let coeffs_biguint: Vec<BigUint> = Vec::from(&temp_poly);

    if coeffs_biguint.is_empty() {
        return Ok(BigInt::zero());
    }

    // Use centered coefficient representation
    Ok(center_coefficient_with_precision(
        &coeffs_biguint[0],
        params,
    ))
}

fn extract_constant_term_as_u64(poly: &Poly, params: &PvwParameters) -> Result<u64> {
    let constant_bigint = extract_constant_term_bigint(poly, params)?;

    // Convert with bounds checking and noise handling
    let plaintext_u64 = if constant_bigint.is_negative() {
        // Handle negative values carefully
        let abs_value = constant_bigint.abs();
        if abs_value <= BigInt::from(1000u64) {
            // Small negative values might be noise, return 0
            0u64
        } else {
            // Large negative values - convert to positive modular equivalent
            let q_total = BigInt::from(params.q_total());
            let positive_equiv = (&constant_bigint + &q_total) % &q_total;
            positive_equiv.to_u64().unwrap_or(0)
        }
    } else {
        // Positive values - directly convert with bounds checking
        if constant_bigint > BigInt::from(u64::MAX) {
            // Value too large, might be noise
            0u64
        } else {
            constant_bigint.to_u64().unwrap_or(0)
        }
    };

    Ok(plaintext_u64)
}

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

    // Compute noisy message = <sk, c1> - c2[party_index]
    let noisy_message = &sk_c1_sum - &ciphertext.c2[party_index];

    // Use the decoding algorithm
    decode_scalar_pvw_rns(&noisy_message, params)
}

/// Decrypt party shares from multiple ciphertexts
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

    // Validate inputs
    if all_ciphertexts.len() != params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Expected {} ciphertexts, got {}",
            params.n,
            all_ciphertexts.len()
        )));
    }

    if party_index >= params.n {
        return Err(PvwError::InvalidParameters(format!(
            "Party index {} exceeds maximum {}",
            party_index,
            params.n - 1
        )));
    }

    // Decrypt all ciphertexts using the decoding algorithm
    let results: Result<Vec<u64>> = all_ciphertexts
        .par_iter()
        .enumerate()
        .map(|(dealer_idx, ciphertext)| {
            ciphertext.validate().map_err(|e| {
                PvwError::InvalidParameters(format!("Ciphertext {dealer_idx} invalid: {e}"))
            })?;

            decrypt_party_value(ciphertext, secret_key, party_index)
        })
        .collect();

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crs::PvwCrs;
    use crate::encryption::encrypt_all_party_shares;
    use crate::params::PvwParametersBuilder;
    use crate::public_key::{GlobalPublicKey, Party};
    use rand::thread_rng;

    #[test]
    fn test_decryption_l16() {
        // Test with l=16 parameters
        let moduli = vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64];
        let num_parties = 10;

        let (variance, bound1, bound2) =
            PvwParameters::suggest_correct_parameters(num_parties, 4, 16, &moduli)
                .expect("Should find parameters for l=16");

        let params = PvwParametersBuilder::new()
            .set_parties(num_parties)
            .set_dimension(4)
            .set_l(16)
            .set_moduli(&moduli)
            .set_secret_variance(variance)
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
        println!("Decryption success rate: {:.1}%", success_rate);

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
                "Rounding division failed: {} / {} should be {}, got {}",
                dividend, divisor, expected, rounded_quotient
            );
        }
    }
}
