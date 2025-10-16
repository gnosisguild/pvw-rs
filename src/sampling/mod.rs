//! Mathematical sampling utilities for the PVW library
//!
//! This module provides sampling functionality from various distributions
//! commonly used in lattice-based cryptography.

pub mod normal;
pub mod uniform;

pub use normal::*;
pub use uniform::*;

/// Re-export sampling-related types and functions
pub mod prelude {
    pub use super::*;
}
