//! Serde serialization support for PVW types
//!
//! This module provides comprehensive serialization support for all PVW types using
//! pure serde with embedded context information. No external dependencies are required
//! for deserialization.
//!
//! ## Structure
//!
//! - `poly`: Custom serialization helpers for fhe-math Poly types
//! - `wrappers`: Serializable wrapper types for PVW structures
//!
//! ## Usage
//!
//! ```rust
//! use pvw::prelude::*;
//! use pvw::serde::wrappers::*;
//! 
//! // Create a serializable wrapper
//! let serializable_params = SerializablePvwParameters::from_params(&params);
//! 
//! // Serialize to JSON
//! let json = serde_json::to_string(&serializable_params)?;
//! 
//! // Deserialize from JSON
//! let deserialized: SerializablePvwParameters = serde_json::from_str(&json)?;
//! let reconstructed_params = deserialized.to_params()?;
//! ```

pub mod poly;
pub mod wrappers;

// Re-export all public types for convenience
pub use poly::{PolyWithContext, VecPolyWithContext, VecVecPolyWithContext};
pub use wrappers::{
    SerializablePvwCiphertext, SerializablePvwCrs, SerializablePvwParameters,
    SerializableGlobalPublicKey, SerializablePublicKey, SerializableSecretKey,
};
