//! Serde serialization support for PVW types
//!
//! This module provides comprehensive serialization support for all PVW types using
//! pure serde with embedded context information. No external dependencies are required
//! for deserialization.
//!
//! - `poly`: Custom serialization helpers for fhe-math Poly types
//! - `wrappers`: Serializable wrapper types for PVW structures

pub mod poly;
pub mod wrappers;

// Re-export all public types for convenience
pub use poly::{PolyWithContext, VecPolyWithContext, VecVecPolyWithContext};
pub use wrappers::{
    SerializableGlobalPublicKey, SerializablePublicKey, SerializablePvwCiphertext,
    SerializablePvwCrs, SerializablePvwParameters, SerializableSecretKey,
};
