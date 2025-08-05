use crate::params::{PvwError, PvwParameters, Result};
use crate::public_key::GlobalPublicKey;
use fhe_math::rq::{Poly, Representation};
use fhe_util::sample_vec_cbd;
use rand::{CryptoRng, RngCore};

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
    pk: &GlobalPublicKey,
    scalars: &[i64],
) -> Result<PvwCiphertext> {
    let k = params.k;
    let l = pk.params.l;
    let n = pk.params.n;
    let ctx = &params.context;

    if scalars.len() != n {
        return Err(PvwError::InvalidParameters(
            "scalars length must equal n".into(),
        ));
    }

    let mut r_polys = Vec::with_capacity(k);
    for _ in 0..k {
        let r = sample_vec_cbd(l, pk.params.secret_variance.try_into().unwrap(), rng)
            .map_err(|e| PvwError::SamplingError(format!("Failed to sample randomness: {}", e)))?;
        let mut r_j_poly = Poly::from_coefficients(r.as_slice(), ctx).map_err(|e| {
            PvwError::InvalidParameters(format!("Failed to create r polynomial: {}", e))
        })?;
        r_j_poly.change_representation(Representation::Ntt);
        r_polys.push(r_j_poly);
    }

    let a = pk.crs.clone();
    let b = pk.matrix.clone();

    // Compute c1 = A * r^T + e1^T mod q
    // A is k×k matrix, r is k×1 vector, result is k×1 vector
    let mut c1 = a.multiply_by_randomness(&r_polys)?;
    let mut c2 = Vec::with_capacity(n);
    for i in 0..k {
        let e1 = params.sample_error_1(rng)?;
        // Add noise
        c1[i] += &e1;
    }

    for i in 0..n {
        // Compute row i of B * r: sum over j of B[i][j] * r[j]
        let mut row_result_b = Poly::zero(ctx, Representation::Ntt);
        for j in 0..k {
            // B * r
            let b_vec = b.get((i, j)).ok_or_else(|| {
                PvwError::InvalidParameters(format!("CRS matrix access failed at ({}, {})", i, j))
            })?;

            let mut b_ij = Poly::from_coefficients(&b_vec, ctx).unwrap();
            b_ij.change_representation(Representation::Ntt);

            let product = &b_ij * &r_polys[j];
            row_result_b += &product;
        }

        let e2 = params.sample_error_2(rng)?;
        // Encode each plaintext scalar x_i as x_i * g ∈ ℤ_q^l
        // Result is x = (x_1*g, x_2*g, ..., x_n*g) ∈ R^n_{l,q}
        let x = params.encode_scalar(scalars[i] as i64)?;
        // Add encoded message and noise: row_result_b + e2[i] + x[i]
        row_result_b += &(e2.clone() + x.clone());
        c2.push(row_result_b);
    }

    Ok(PvwCiphertext { c1, c2 })
}
