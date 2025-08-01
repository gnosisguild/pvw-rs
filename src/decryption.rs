use crate::encryption::PvwCiphertext;
use crate::params::{PvwError, PvwParameters, Result};
use crate::secret_key::SecretKey;
use fhe_math::rq::{Context, Poly, Representation};
use num_traits::ToPrimitive;
use std::sync::Arc;

/// Decrypt a PVW ciphertext to recover the plaintext
pub fn decrypt(
    params: &PvwParameters,
    sk: &SecretKey,
    ctx: &Arc<Context>,
    ct: &PvwCiphertext,
) -> Result<Poly> {
    let q = &params.q;
    let k = params.k;
    let l = params.l;
    let g = params.gadget_vector()?;

    // Compute y = c2 - (c1 * s)
    if ct.c1.len() != k || sk.coeff_matrix.len() != k {
        return Err(PvwError::InvalidParameters(
            "Ciphertext and secret-key dimensions mismatch".into(),
        ));
    }

    let mut y = Vec::with_capacity(k);
    for i in 0..k {
        let mut inner_product = Poly::zero(ctx, Representation::Ntt);
        let sk_vec = sk.coeff_matrix[i].clone();
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
                PvwError::InvalidParameters(format!("Failed to create delta^{} polynomial: {}", power, e))
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
    let reduced_coeffs: Vec<BigUint> = coeffs.iter()
        .map(|c| c % &delta_l_minus_1)
        .collect();

    // Convert back to polynomial in power basis representation
    let mut e = Poly::try_convert_from(
        reduced_coeffs.as_slice(),
        z_copy.ctx(),
        false,  // constant-time operations for security
        Representation::PowerBasis
    ).map_err(|e| {
        PvwError::InvalidParameters(format!("Failed to convert coefficients back to polynomial: {}", e))
    })?;
    
    // Convert back to NTT representation for further operations
    e.change_representation(Representation::Ntt);

    // y[0] - e / g_0
    let pt = &y[0] * &g_0_poly;

    Ok(pt)
}
