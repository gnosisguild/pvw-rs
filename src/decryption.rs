use crate::encryption::PvwCiphertext;
use crate::params::{PvwError, PvwParameters, Result};
use crate::secret_key::SecretKey;
use crate::PvwParametersBuilder;
use fhe_math::rq::traits::TryConvertFrom;
use fhe_math::rq::{Context, Poly, Representation};
use fhe_traits::FheEncrypter;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use std::sync::Arc;

/// Decrypt a PVW ciphertext to recover the plaintext
pub fn decrypt(
    params: &PvwParameters,
    sk: &SecretKey,
    ctx: &Arc<Context>,
    ct: &PvwCiphertext,
) -> Result<Vec<u64>> {
    let k = params.k;
    let l = params.l;

    // Compute y = c2 - (c1 * s)
    if ct.c1.len() != k || sk.secret_coeffs.len() != k {
        return Err(PvwError::InvalidParameters(
            "Ciphertext and secret-key dimensions mismatch".into(),
        ));
    }

    let mut y = Vec::with_capacity(k);
    for i in 0..k {
        let mut inner_product = Poly::zero(ctx, Representation::Ntt);
        let sk_vec = sk.secret_coeffs[i].clone();
        for j in 0..l {
            let mut sk_i_poly = Poly::from_coefficients(&[sk_vec[j]], ctx).map_err(|e| {
                PvwError::InvalidParameters(format!("Failed to create sk polynomial: {}", e))
            })?;
            sk_i_poly.change_representation(Representation::Ntt);

            inner_product += &(&sk_i_poly * &ct.c1[i]);
        }
        //xg + e
        y.push(&ct.c2[i] - &inner_product.clone());
    }

    // We have y = xg + e where g = (Δ^(l-1), ..., Δ, 1)
    // This corresponds to x'_i = xΔ^(l-i) + e_i in Fig.1 notation (1-indexed)

    let delta = params.delta();
    let mut delta_poly = Poly::from_coefficients(&[delta.to_i64().unwrap()], ctx).map_err(|e| {
        PvwError::InvalidParameters(format!("Failed to create delta polynomial: {}", e))
    })?;
    delta_poly.change_representation(Representation::Ntt);

    // Decoding step 1: For i = 1, ..., l-1, let y_i := x'_{i+1} - Δx'_i mod q
    // In 0-indexed: y_i[i] := y[i+1] - Δ * y[i] for i = 0, ..., l-2
    let mut y_i = Vec::with_capacity(l - 1);
    for i in 0..l - 1 {
        let delta_y_i = &delta_poly * &y[i];
        y_i.push(&y[i + 1] - &delta_y_i);
    }

    // Decoding step 2: Set z := Σ_{i=1}^{l-1} Δ^{l-i-1} · y_i
    let mut z = Poly::zero(ctx, Representation::Ntt);
    for i in 0..l - 1 {
        let power = l - i - 2; // l-i-1-1 in 0-indexed
        let mut delta_power_poly = if power == 0 {
            // Δ^0 = 1
            Poly::from_coefficients(&[1i64], ctx).map_err(|e| {
                PvwError::InvalidParameters(format!("Failed to create constant polynomial: {}", e))
            })?
        } else {
            let delta_pow = delta.pow(power as u32);
            Poly::from_coefficients(&[delta_pow.to_i64().unwrap()], ctx).map_err(|e| {
                PvwError::InvalidParameters(format!(
                    "Failed to create delta^{} polynomial: {}",
                    power, e
                ))
            })?
        };
        delta_power_poly.change_representation(Representation::Ntt);

        z += &(&delta_power_poly * &y_i[i]);
    }

    // Decoding step 3: Set e := z mod Δ^{l-1}
    let delta_l_minus_1 = delta.pow((l - 1) as u32);

    // Convert polynomial to power basis for coefficient-wise operations
    let mut z_copy = z.clone();
    if z_copy.representation() != &Representation::PowerBasis {
        z_copy.change_representation(Representation::PowerBasis);
    }

    // Convert coefficients to BigUint and apply modulo reduction
    let coeffs: Vec<BigUint> = Vec::from(&z_copy);
    let reduced_coeffs: Vec<BigUint> = coeffs.iter().map(|c| c % &delta_l_minus_1).collect();

    // Convert back to polynomial in power basis representation
    let mut e = Poly::try_convert_from(
        reduced_coeffs.as_slice(),
        z_copy.ctx(),
        false, // constant-time operations for security
        Representation::PowerBasis,
    )
    .map_err(|e| {
        PvwError::InvalidParameters(format!(
            "Failed to convert coefficients back to polynomial: {}",
            e
        ))
    })?;

    // Convert back to NTT representation for further operations
    e.change_representation(Representation::PowerBasis);
    // Decoding step 4: x'[0] - e / delta^(l-1)
    let mut y0: Poly = y[0].clone();
    y0.change_representation(Representation::PowerBasis);
    let numerator: Vec<BigUint> = Vec::from(&(&y0 - &e));

    let mut pt = Vec::new();
    for i in 0..numerator.len() {
        pt.push((&numerator[i] / &delta_l_minus_1).to_u64().unwrap());
    }
    Ok(pt.clone())
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;
    use rand::thread_rng;

    use crate::{encryption::encrypt, GlobalPublicKey, Party, PvwCrs};

    use super::*;

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
            .set_parties(2)
            .set_dimension(4)
            .set_l(32) // Use smaller degree that works
            .set_moduli(&test_moduli()) // Use working NTT-friendly moduli
            .build_arc()
            .unwrap()
    }

    // #[test]
    // fn test_enc_dec() {
    //     let params = create_test_params();
    //     let mut rng = thread_rng();

    //     // Create parties
    //     let party_0 = Party::new(0, &params, &mut rng).unwrap();
    //     let party_1 = Party::new(1, &params, &mut rng).unwrap();

    //     let crs = PvwCrs::new(&params, &mut rng).unwrap();
    //     let sk = SecretKey::random(&params, &mut rng).unwrap();
    //     let mut global_pk = GlobalPublicKey::new(crs);

    //     // Generate and add public keys
    //     global_pk
    //         .generate_and_add_party(&party_0, &mut rng)
    //         .unwrap();
    //     global_pk
    //         .generate_and_add_party(&party_1, &mut rng)
    //         .unwrap();

    //     let scalars: Vec<u64> = vec![1; 32];

    //     let ct = encrypt(&params, &mut rng, &params.context, &global_pk, &scalars).unwrap();
    //     let pt = decrypt(&params, &sk, &params.context, &ct).unwrap();

    //     println!("{:#?}", pt);
    // }
}
