//! Common traits for the PVW library
//!
//! This module provides the foundational traits that define the interface
//! for serialization, encoding, and validation across all PVW types.

use std::result::Result;

/// Trait for serializing types to and from bytes
pub trait Serialize {
    /// Serialize the type to a byte vector
    fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    /// Deserialize the type from a byte slice
    fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    where
        Self: Sized;
}

/// Trait for encoding types to and from bytes with specific format
pub trait Encode {
    /// Encode the type to a byte vector
    fn encode(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;

    /// Decode the type from a byte slice
    fn decode(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    where
        Self: Sized;
}

/// Trait for validating types
pub trait Validate {
    /// Validate the type and return a result
    fn validate(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Check if the type is valid
    fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

/// Re-export all traits for easy importing
pub mod prelude {
    pub use super::{Encode, Serialize, Validate};
}
