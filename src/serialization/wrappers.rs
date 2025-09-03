//! Serializable wrapper types for PVW structures
//!
//! This module provides serde-compatible wrapper types that embed context information
//! and use custom poly serialization for complete, self-contained serialization.

use crate::crypto::PvwCiphertext;
use crate::errors::PvwResult;
use crate::keys::{GlobalPublicKey, PublicKey, SecretKey};
use crate::params::{PvwCrs, PvwParameters};
use crate::serialization::poly::{VecPolyWithContext, VecVecPolyWithContext};
use fhe_math::rq::Poly;
use ndarray::Array2;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Serde-compatible wrapper for PvwParameters  
///
/// Contains only the essential information needed to reconstruct PvwParameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePvwParameters {
    pub n: usize,
    pub k: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub degree: usize,
    pub secret_variance: u32,
    pub error_bound_1: String, // BigInt as string
    pub error_bound_2: String, // BigInt as string
}

impl SerializablePvwParameters {
    /// Create from PvwParameters
    pub fn from_params(params: &Arc<PvwParameters>) -> Self {
        Self {
            n: params.n,
            k: params.k,
            l: params.l,
            moduli: params.moduli().to_vec(),
            degree: params.context.degree,
            secret_variance: params.secret_variance,
            error_bound_1: params.error_bound_1.to_string(),
            error_bound_2: params.error_bound_2.to_string(),
        }
    }
    
    /// Convert back to PvwParameters
    pub fn to_params(&self) -> PvwResult<Arc<PvwParameters>> {
        use num_bigint::BigInt;
        use std::str::FromStr;
        
        let error_bound_1 = BigInt::from_str(&self.error_bound_1)
            .map_err(|e| crate::errors::PvwError::InvalidFormat(format!("Invalid error_bound_1: {}", e)))?;
        let error_bound_2 = BigInt::from_str(&self.error_bound_2)
            .map_err(|e| crate::errors::PvwError::InvalidFormat(format!("Invalid error_bound_2: {}", e)))?;
            
        PvwParameters::builder()
            .set_parties(self.n)
            .set_dimension(self.k)
            .set_l(self.l)
            .set_moduli(&self.moduli)
            .set_secret_variance(self.secret_variance)
            .set_error_bounds(error_bound_1, error_bound_2)
            .build_arc()
    }
}

/// Serde-compatible wrapper for PvwCrs
///
/// This wrapper embeds all necessary parameter information to enable
/// full JSON/serde serialization without external dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePvwCrs {
    /// The CRS matrix using custom poly serialization
    #[serde(with = "VecVecPolyWithContext")]
    matrix: Vec<Vec<Poly>>,
    /// Embedded parameter information for reconstruction
    pub params: SerializablePvwParameters,
}

impl SerializablePvwCrs {
    /// Create from PvwCrs
    pub fn from_crs(crs: &PvwCrs) -> Self {
        // Convert Array2 to Vec<Vec<Poly>>
        let matrix = crs.matrix.outer_iter()
            .map(|row| row.iter().cloned().collect())
            .collect();
            
        Self {
            matrix,
            params: SerializablePvwParameters::from_params(&crs.params),
        }
    }
    
    /// Convert back to PvwCrs
    pub fn to_crs(&self) -> PvwResult<PvwCrs> {
        let params = self.params.to_params()?;
        
        // Convert Vec<Vec<Poly>> back to Array2
        let rows = self.matrix.len();
        let cols = if rows > 0 { self.matrix[0].len() } else { 0 };
        
        let mut flat_data = Vec::new();
        for row in &self.matrix {
            flat_data.extend(row.iter().cloned());
        }
        
        let matrix = Array2::from_shape_vec((rows, cols), flat_data)
            .map_err(|e| crate::errors::PvwError::InvalidFormat(format!("Failed to create matrix: {}", e)))?;
        
        Ok(PvwCrs { matrix, params })
    }
}

/// Serde-compatible wrapper for SecretKey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSecretKey {
    /// Secret key coefficients  
    coefficients: Vec<Vec<i64>>,
    /// Embedded parameter information for reconstruction
    pub params: SerializablePvwParameters,
}

impl SerializableSecretKey {
    /// Create from SecretKey
    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        Self {
            coefficients: secret_key.coefficients().to_vec(),
            params: SerializablePvwParameters::from_params(&secret_key.params),
        }
    }
    
    /// Convert back to SecretKey
    pub fn to_secret_key(&self) -> PvwResult<SecretKey> {
        let params = self.params.to_params()?;
        SecretKey::from_coefficients(params, self.coefficients.clone())
    }
}

/// Serde-compatible wrapper for PublicKey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePublicKey {
    /// Public key polynomials using custom poly serialization
    #[serde(with = "VecPolyWithContext")]
    key_polynomials: Vec<Poly>,
    /// Embedded parameter information for reconstruction
    pub params: SerializablePvwParameters,
}

impl SerializablePublicKey {
    /// Create from PublicKey
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        Self {
            key_polynomials: public_key.key_polynomials.clone(),
            params: SerializablePvwParameters::from_params(&public_key.params),
        }
    }
    
    /// Convert back to PublicKey  
    pub fn to_public_key(&self) -> PvwResult<PublicKey> {
        let params = self.params.to_params()?;
        Ok(PublicKey {
            key_polynomials: self.key_polynomials.clone(),
            params,
        })
    }
}

/// Serde-compatible wrapper for GlobalPublicKey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableGlobalPublicKey {
    /// Global public key matrix using custom poly serialization
    #[serde(with = "VecVecPolyWithContext")]
    matrix: Vec<Vec<Poly>>,
    /// Common Reference String  
    crs: SerializablePvwCrs,
    /// Number of public keys currently stored
    num_keys: usize,
    /// Embedded parameter information for reconstruction
    pub params: SerializablePvwParameters,
}

impl SerializableGlobalPublicKey {
    /// Create from GlobalPublicKey
    pub fn from_global_public_key(global_public_key: &GlobalPublicKey) -> Self {
        // Convert Array2 to Vec<Vec<Poly>>
        let matrix = global_public_key.matrix.outer_iter()
            .map(|row| row.iter().cloned().collect())
            .collect();
            
        Self {
            matrix,
            crs: SerializablePvwCrs::from_crs(&global_public_key.crs),
            num_keys: global_public_key.num_keys,
            params: SerializablePvwParameters::from_params(&global_public_key.params),
        }
    }
    
    /// Convert back to GlobalPublicKey
    pub fn to_global_public_key(&self) -> PvwResult<GlobalPublicKey> {
        let params = self.params.to_params()?;
        let crs = self.crs.to_crs()?;
        
        // Convert Vec<Vec<Poly>> back to Array2
        let rows = self.matrix.len();
        let cols = if rows > 0 { self.matrix[0].len() } else { 0 };
        
        let mut flat_data = Vec::new();
        for row in &self.matrix {
            flat_data.extend(row.iter().cloned());
        }
        
        let matrix = Array2::from_shape_vec((rows, cols), flat_data)
            .map_err(|e| crate::errors::PvwError::InvalidFormat(format!("Failed to create matrix: {}", e)))?;
        
        Ok(GlobalPublicKey { 
            matrix, 
            crs, 
            num_keys: self.num_keys,
            params 
        })
    }
}

/// Serde-compatible wrapper for PvwCiphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePvwCiphertext {
    /// c1 polynomials using custom poly serialization
    #[serde(with = "VecPolyWithContext")]
    c1: Vec<Poly>,
    /// c2 polynomials using custom poly serialization
    #[serde(with = "VecPolyWithContext")]
    c2: Vec<Poly>,
    /// Embedded parameter information for reconstruction
    pub params: SerializablePvwParameters,
}

impl SerializablePvwCiphertext {
    /// Create from PvwCiphertext
    pub fn from_ciphertext(ciphertext: &PvwCiphertext) -> Self {
        Self {
            c1: ciphertext.c1.clone(),
            c2: ciphertext.c2.clone(),
            params: SerializablePvwParameters::from_params(&ciphertext.params),
        }
    }
    
    /// Convert back to PvwCiphertext
    pub fn to_ciphertext(&self) -> PvwResult<PvwCiphertext> {
        let params = self.params.to_params()?;
        Ok(PvwCiphertext {
            c1: self.c1.clone(),
            c2: self.c2.clone(),
            params,
        })
    }
}
