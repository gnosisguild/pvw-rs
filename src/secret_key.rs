use fhe_math::rq::Poly;
use fhe_util::sample_vec_cbd;
use crate::PvwParameters; 
use rand::{CryptoRng, RngCore};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The secret key is a vector of `k` polynomials (each in R_q)
pub struct SecretKey {
    pub par: Arc<PvwParameters>,
    pub polys: Vec<Poly>, // length = k
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        for poly in self.polys.iter_mut() {
            poly.coeffs_mut().zeroize(); // assumes mutable coeff access
        }
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    /// Generates a random secret key using CBD distribution
    pub fn random<R: RngCore + CryptoRng>(par: &Arc<PvwParameters>, rng: &mut R) -> Self {
        let mut polys = Vec::with_capacity(par.k);
        for _ in 0..par.k {
            let coeffs = sample_vec_cbd(par.degree, par.variance, rng)
                .expect("Sampling secret key coefficients failed");
            let poly = Poly::from_coefficients(coeffs); // constructor from fhe.rs
            polys.push(poly);
        }
        Self {
            par: par.clone(),
            polys,
        }
    }
/// Returns the secret key as a matrix of coefficients
    pub fn as_matrix(&self) -> Vec<Vec<i64>> {
        self.polys
            .iter()
            .map(|p| p.coeffs().to_vec()) 
            .collect()
    }
}

