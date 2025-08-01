use crate::params::{PvwError, PvwParameters, Result};
use crate::public_key::GlobalPublicKey;
use fhe_math::rq::{Context, Poly, Representation};
use fhe_util::sample_vec_cbd;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::{CryptoRng, RngCore};
use std::sync::Arc;

/// Ciphertext output of PVW encryption
#[derive(Debug, Clone)]
pub struct PvwCiphertext {
    /// c1 = A * r^T + e1'  ∈ ℤ_q^k
    pub c1: Vec<Poly>,
    /// c2 = b * r^T + e2' + c  ∈ ℤ_q
    pub c2: Vec<Poly>,
}

pub fn encrypt<R: RngCore + CryptoRng>(
    params: &PvwParameters,
    rng: &mut R,
    ctx: &Arc<Context>,
    pk: &GlobalPublicKey,
    scalars: &[u64],
) -> Result<PvwCiphertext> {
    let q = &params.q_total();
    let k = params.k;
    let g = params.gadget_vector()?;
    if g.len() != scalars.len() {
        return Err(PvwError::InvalidParameters(
            "scalars length must equal gadget dimension ℓ".into(),
        ));
    }
    // Encode each plaintext scalar x_i as x_i * g ∈ ℤ_q^l
    // Result is x = (x_1*g, x_2*g, ..., x_n*g) ∈ R^n_{l,q}
    let mut x_vec: Vec<BigUint> = Vec::with_capacity(pk.params.n * pk.params.l);
    for x in scalars {
        // Encode this scalar: x_i * g = (x_i * g[0], x_i * g[1], ..., x_i * g[l-1])
        for g_j in &g {
            let encoded_coeff = (x * g_j) % q;
            x_vec.push(encoded_coeff);
        }
    }

    let x: Vec<i64> = x_vec
        .iter()
        .map(|x| x.to_i64().expect("BigUint didn’t fit in i64"))
        .collect();

    let e1 = sample_vec_cbd(k, pk.params.secret_variance.try_into().unwrap(), rng)
        .map_err(|e| PvwError::InvalidParameters(format!("Failed to sample noise: {}", e)))?;

    let e2 = sample_vec_cbd(k, pk.params.secret_variance.try_into().unwrap(), rng)
        .map_err(|e| PvwError::InvalidParameters(format!("Failed to sample noise: {}", e)))?;

    // TODO: Ask if this should be sk params
    let r = sample_vec_cbd(k, pk.params.secret_variance.try_into().unwrap(), rng)
        .map_err(|e| PvwError::InvalidParameters(format!("Failed to sample r: {}", e)))?;

    let a = pk.crs.clone();
    let b = pk.matrix.clone();

    // Compute c1 = A * r^T + e1^T mod q
    // A is k×k matrix, r is k×1 vector, result is k×1 vector
    let mut c1 = Vec::with_capacity(k);
    let mut c2 = Vec::with_capacity(k);

    for i in 0..k {
        // Compute row i of A * r: sum over j of A[i][j] * r[j]
        let mut row_result_a = Poly::zero(ctx, Representation::Ntt);
        // Compute row i of B * r: sum over j of B[i][j] * r[j]
        let mut row_result_b = Poly::zero(ctx, Representation::Ntt);

        // Create polynomial for x[i]
        let x_i_poly = Poly::from_coefficients(&[x[i]], ctx).map_err(|e| {
            PvwError::InvalidParameters(format!("Failed to create m polynomial: {}", e))
        })?;

        // Create polynomial for e1[i]
        let e1_i_poly = Poly::from_coefficients(&[e1[i].clone()], ctx).map_err(|e| {
            PvwError::InvalidParameters(format!("Failed to create e1 polynomial: {}", e))
        })?;

        // Create polynomial for e2[i]
        let e2_i_poly = Poly::from_coefficients(&[e2[i].clone()], ctx).map_err(|e| {
            PvwError::InvalidParameters(format!("Failed to create e2 polynomial: {}", e))
        })?;

        for j in 0..k {
            // Create polynomial for r[j]
            let r_j_poly = Poly::from_coefficients(&[r[j].clone()], ctx).map_err(|e| {
                PvwError::InvalidParameters(format!("Failed to create r[j] polynomial: {}", e))
            })?;

            // A * r
            let a_ij = a.get(i, j).ok_or_else(|| {
                PvwError::InvalidParameters(format!("CRS matrix access failed at ({}, {})", i, j))
            })?;
            let product_a = a_ij * &r_j_poly;
            row_result_a += &product_a;

            // B * r
            let b_vec = b.get((i, j)).ok_or_else(|| {
                PvwError::InvalidParameters(format!("CRS matrix access failed at ({}, {})", i, j))
            })?;
            let b_ij = Poly::from_coefficients(&b_vec, ctx).unwrap();
            let product_b = &b_ij * &r_j_poly;
            row_result_b += &product_b;
        }

        // Add noise: row_result_a + e1[i]
        row_result_a += &e1_i_poly;
        c1.push(row_result_a);

        // Add encoded message and noise: row_result_b + e2[i] + x[i]
        row_result_b += &(e2_i_poly + x_i_poly.clone());
        c2.push(row_result_b);
    }

    Ok(PvwCiphertext { c1, c2 })
}
