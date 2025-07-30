//! PVW Multi-Receiver LWE Encryption Scheme
//!
//! Implementation following "Practical Non-interactive Publicly Verifiable Secret Sharing with Thousands of Parties" (Section 2.5)
//! https://eprint.iacr.org/2021/1397.pdf
pub mod crs;
pub mod encryption;
pub mod params;
pub mod public_key;
pub mod secret_key;
