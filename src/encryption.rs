use crate::params::{PvwError, PvwParameters, Result};
use crate::public_key::GlobalPublicKey;
use fhe_math::rq::{Context, Poly};
use fhe_util::sample_vec_cbd;
use num_bigint::BigUint;
use num_traits::One;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// Ciphertext output of PVW encryption
#[derive(Debug, Clone)]
pub struct PvwCiphertext {
    /// c1 = A * r^T + e1'  ∈ ℤ_q^k
    pub c1: Vec<BigUint>,
    /// c2 = b * r^T + e2' + c  ∈ ℤ_q
    pub c2: BigUint,
}

pub fn encrypt<R: RngCore + CryptoRng>(
    params: &PvwParameters,
    rng: &mut R,
    ctx: &Arc<Context>,
    pk: &GlobalPublicKey,
    message: &[u8],
) -> Result<PvwCiphertext> {
    let q = &params.q;
    let k = params.k;
    let g = params.gadget_vector()?;
    if g.len() != message.len() {
        return Err(PvwError::InvalidParameters(
            "message length must equal gadget dimension ℓ".into(),
        ));
    }

    let e1 = sample_vec_cbd(k, pk.params.variance, rng)
        .map_err(|e1| PvwError::InvalidParameters(format!("Failed to sample noise: {}", e1)))?;

    let e2 = sample_vec_cbd(k, pk.params.variance, rng)
        .map_err(|e2| PvwError::InvalidParameters(format!("Failed to sample noise: {}", e2)))?;

    // TODO: Ask if this should be sk params
    let r = sample_vec_cbd(k, pk.params.variance, rng)
        .map_err(|r| PvwError::InvalidParameters(format!("Failed to sample r: {}", r)))?;
    let r_poly = Poly::from_coefficients(&r, ctx).map_err(|e| {
        PvwError::InvalidParameters(format!("Failed to create r polynomial: {}", e))
    })?;

    let a = pk.crs.matrix.clone();
    let b = pk.matrix.clone();

    // r = 1xk
    // a = kxk
    let mut c1: Vec<BigUint> = Vec::new();
    let mut acc = 0;
    for i in 0..pk.params.l {
        for j in 0..k {
            let temp = a[[i, j]].clone();
            //let temp2 = temp * r[0];
        }
    }

    Ok(PvwCiphertext {
        c1: vec![BigUint::one()],
        c2: BigUint::one(),
    })
}
