use crate::encryption::PvwCiphertext;
use crate::params::{PvwError, PvwParameters, Result};
use crate::secret_key::SecretKey;
use fhe_math::rq::{Context, Poly, Representation};
use num_bigint::ToBigInt;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::ToPrimitive;
use num_traits::Zero;
use std::sync::Arc;

/// Decrypt a PVW ciphertext to recover the plaintext
pub fn decrypt(
    params: &PvwParameters,
    secret_keys: Vec<SecretKey>,
    ctx: &Arc<Context>,
    ct: &PvwCiphertext,
) -> Result<Vec<i64>> {
    let k = params.k;
    let l = params.l;
    let n = params.n;
    let q_total = BigInt::from(params.q_total());
    let half_q = &q_total / 2;

    let mut y = Vec::with_capacity(n);
    for i in 0..n {
        let mut inner_product = Poly::zero(ctx, Representation::Ntt);
        for j in 0..k {
            if ct.c1.len() != k || secret_keys[j].secret_coeffs.len() != k {
                return Err(PvwError::InvalidParameters(
                    "Ciphertext and secret-key dimensions mismatch".into(),
                ));
            }
            let mut sk_i_poly = secret_keys[j].get_polynomial(j)?;
            sk_i_poly.change_representation(Representation::Ntt);

            inner_product += &(&sk_i_poly * &ct.c1[j]);
        }
        //xg + e
        y.push(&ct.c2[i] - &inner_product.clone());
    }

    // Decoding step 1: For i = 1, ..., l-1, let y_i := x'_{i+1} - Δx'_i mod q
    // In 0-indexed: y_i[i] := y[i+1] - Δ * y[i] for i = 0, ..., l-2
    let mut y_i = Vec::with_capacity(n);
    for i in 0..n {
        let mut polynomial_coeffs = Vec::with_capacity(l - 1);
        // Convert polynomial to power basis for coefficient-wise operations
        let mut y_copy = y[i].clone();
        if y_copy.representation() != &Representation::PowerBasis {
            y_copy.change_representation(Representation::PowerBasis);
        }
        let coeffs: Vec<BigUint> = Vec::from(&y_copy);
        let centered_coeffs: Vec<BigInt> = coeffs
            .iter()
            .map(|coeff| center_values(coeff, params.clone()))
            .collect();
        for j in 0..l - 1 {
            let mut coeff =
                &centered_coeffs[j + 1] - params.delta().to_bigint().unwrap() * &centered_coeffs[j];
            coeff = coeff.mod_floor(&q_total);
            if coeff > half_q {
                coeff -= &q_total;
            }
            polynomial_coeffs.push(coeff);
        }
        y_i.push(polynomial_coeffs);
    }

    // Decoding step 2 and 3
    let mut e_vec = Vec::with_capacity(n);
    for i in 0..n {
        let mut z = BigInt::ZERO;
        let deltas = params.gadget_vector();
        let y_i_coeffs = y_i[i].clone();
        for j in 0..l - 1 {
            let delta = center_values(&deltas[l - 2 - j], params.clone());
            z += y_i_coeffs[j].clone() * delta;
        }
        println!("z {:#?}", z);

        let delta_power_l_minus_1 = BigInt::from(params.delta_power_l_minus_1.clone());
        let mut e = z.mod_floor(&delta_power_l_minus_1);
        if e > delta_power_l_minus_1.clone() / 2 {
            e -= &delta_power_l_minus_1;
        }
        e_vec.push(e);
    }

    // Decoding step 4: x'[0] - e / delta^(l-1)
    let mut pt = Vec::with_capacity(n);
    for i in 0..n {
        y[i].change_representation(Representation::PowerBasis);
        let y_i_coeffs: Vec<BigUint> = Vec::from(&y[i]);
        let centered_y_0 = center_values(&y_i_coeffs[0], params.clone());
        let delta_power_l_minus_1 = center_values(&params.delta_power_l_minus_1, params.clone());

        let numerator = &centered_y_0 - &e_vec[i];
        println!("{:#?}", centered_y_0);
        println!("{:#?}", centered_y_0);

        debug_assert!(
            (&numerator % &delta_power_l_minus_1).is_zero(),
            "plaintext‐decoding division not exact; got remainder {}",
            (&numerator % &delta_power_l_minus_1)
        );

        pt.push((numerator / &delta_power_l_minus_1).to_i64().unwrap());
    }
    Ok(pt.clone())
}

fn center_values(coeff: &BigUint, params: PvwParameters) -> BigInt {
    let q_total = BigInt::from(params.q_total());
    let half_q = &q_total / 2;
    let coeff_bigint = BigInt::from(coeff.clone());
    if coeff_bigint > half_q {
        &coeff_bigint - &q_total // Convert to negative
    } else {
        coeff_bigint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encryption::encrypt, GlobalPublicKey, PvwCrs, PvwParametersBuilder};
    use rand::thread_rng;

    /// Standard NTT-friendly moduli for testing
    fn test_moduli() -> Vec<u64> {
        vec![
            0x1FFFFFFEA0001u64, // 562949951979521
            0x1FFFFFFE88001u64, // 562949951881217
            0x1FFFFFFE48001u64, // 562949951619073
        ]
    }

    fn create_test_params() -> Arc<PvwParameters> {
        PvwParametersBuilder::new()
            .set_parties(5)
            .set_dimension(4)
            .set_l(32) // Use smaller degree that works
            .set_moduli(&test_moduli()) // Use working NTT-friendly moduli
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_enc_dec() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create secret keys directly
        let sk1 = SecretKey::random(&params, &mut rng).unwrap();
        let sk2 = SecretKey::random(&params, &mut rng).unwrap();
        let sk3 = SecretKey::random(&params, &mut rng).unwrap();
        let sk4 = SecretKey::random(&params, &mut rng).unwrap();
        let sk5 = SecretKey::random(&params, &mut rng).unwrap();

        let secret_keys = vec![sk1, sk2, sk3, sk4, sk5];

        // Create global public key
        let crs = PvwCrs::new(&params, &mut rng).unwrap();
        let mut global_pk = GlobalPublicKey::new(crs);

        // Generate keys from secret keys
        global_pk.generate_all_keys(&secret_keys, &mut rng).unwrap();

        let scalars: Vec<i64> = vec![1, 2, 1, 3, 1];

        let ct = encrypt(&params, &mut rng, &global_pk, &scalars).unwrap();
        let pt = decrypt(&params, secret_keys, &params.context, &ct).unwrap();

        println!("{:#?}", pt);
    }
}
