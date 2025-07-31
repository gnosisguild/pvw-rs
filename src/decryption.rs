use std::sync::Arc;

use crate::encryption::PvwCiphertext;
use crate::params::{PvwError, PvwParameters, Result};
use crate::secret_key::SecretKey;
use fhe_math::rq::{Context, Poly, Representation};

/// Decrypt a PVW ciphertext to recover the plaintext
pub fn decrypt(
    params: &PvwParameters,
    sk: &SecretKey,
    ctx: &Arc<Context>,
    ct: &PvwCiphertext,
) -> Result<Vec<i64>> {
    let q = &params.q;
    let k = params.k;
    let l = params.l;

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
                PvwError::InvalidParameters(format!("Failed to create m polynomial: {}", e))
            })?;
            sk_i_poly.change_representation(Representation::Ntt);

            inner_product += &(&sk_i_poly * &ct.c1[i]);
        }

        y.push(&ct.c2[i] - &inner_product.clone());
    }

    Ok(sk.coeff_matrix[0].clone())
}
