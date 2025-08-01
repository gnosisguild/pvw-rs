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

        y.push(&ct.c2[i] - &inner_product.clone());
    }

    let mut z = Poly::zero(ctx, Representation::Ntt);
    for i in 0..g.len() {
        // Create polynomial for x[i]
        let mut g_i_poly =
            Poly::from_coefficients(&[g[i].to_i64().unwrap()], ctx).map_err(|e| {
                PvwError::InvalidParameters(format!("Failed to create g_i polynomial: {}", e))
            })?;
        g_i_poly.change_representation(Representation::Ntt);

        z += &(&g_i_poly * &y[i]);
    }

    let mut g_0_poly = Poly::from_coefficients(&[g[0].modinv(q).unwrap().to_i64().unwrap()], ctx)
        .map_err(|e| {
        PvwError::InvalidParameters(format!("Failed to create g_0 polynomial: {}", e))
    })?;
    g_0_poly.change_representation(Representation::Ntt);
    let e = z;

    let pt = &(&y[0] - &e) * &g_0_poly;

    Ok(pt)
}
