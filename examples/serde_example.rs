//! Example demonstrating serde serialization support in pvw-rs
//!
//! This example shows how to serialize and deserialize PVW types
//! when the serde feature is enabled.

#[cfg(feature = "serde")]
use pvw::{PvwParameters, SecretKey, Party};
#[cfg(feature = "serde")]
use pvw::{SerializablePvwParameters, SerializableSecretKey, SerializableParty};
#[cfg(feature = "serde")]
use std::sync::Arc;

#[cfg(feature = "serde")]
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("PVW Serde Example");
    println!("=================");

    // Create test parameters
    let params = PvwParameters::builder()
        .set_parties(3)
        .set_dimension(2)
        .set_l(8)
        .set_moduli(&[0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64]) // NTT-friendly primes
        .set_secret_variance(1)
        .set_error_bounds_u32(50, 100)
        .build_arc()?;

    println!("Created PVW parameters with n={}, k={}, l={}", params.n, params.k, params.l);

    // Test serializing parameters
    let serializable_params = params.to_serializable();
    let params_json = serde_json::to_string_pretty(&serializable_params)?;
    println!("\nSerialized parameters to JSON ({} bytes):", params_json.len());
    println!("{}", params_json);

    // Test deserializing parameters
    let deserialized_params: SerializablePvwParameters = serde_json::from_str(&params_json)?;
    let reconstructed_params = Arc::new(PvwParameters::from_serializable(deserialized_params)?);
    println!("\nSuccessfully deserialized parameters!");
    println!("Reconstructed: n={}, k={}, l={}", reconstructed_params.n, reconstructed_params.k, reconstructed_params.l);

    // Create and serialize a secret key
    let mut rng = rand::thread_rng();
    let secret_key = SecretKey::random(&params, &mut rng)?;
    
    let serializable_sk = secret_key.to_serializable();
    let sk_json = serde_json::to_string_pretty(&serializable_sk)?;
    println!("\nSerialized secret key to JSON ({} bytes):", sk_json.len());
    
    // For privacy, we'll just show the structure, not the actual key
    println!("Secret key has {} polynomials with {} coefficients each", 
             serializable_sk.secret_coeffs.len(), 
             serializable_sk.secret_coeffs[0].len());

    // Test deserializing secret key
    let deserialized_sk: SerializableSecretKey = serde_json::from_str(&sk_json)?;
    let _reconstructed_sk = SecretKey::from_serializable(deserialized_sk, reconstructed_params.clone())?;
    println!("Successfully deserialized secret key!");

    // Create and serialize a party
    let party = Party::new(0, &params, &mut rng)?;
    let serializable_party = party.to_serializable();
    let party_json = serde_json::to_string_pretty(&serializable_party)?;
    println!("\nSerialized party to JSON ({} bytes):", party_json.len());
    println!("Party index: {}", serializable_party.index);

    // Test deserializing party
    let deserialized_party: SerializableParty = serde_json::from_str(&party_json)?;
    let reconstructed_party = Party::from_serializable(deserialized_party, &reconstructed_params)?;
    println!("Successfully deserialized party with index {}!", reconstructed_party.index());

    println!("\n✅ All serde operations completed successfully!");
    println!("\nNote: Types containing polynomials (PvwCrs, PublicKey, GlobalPublicKey, PvwCiphertext)");
    println!("cannot be directly serialized with serde due to fhe.rs internals.");
    println!("Use their custom to_bytes() methods from fhe_traits::Serialize instead.");

    Ok(())
}

#[cfg(not(feature = "serde"))]
fn main() {
    println!("This example requires the 'serde' feature to be enabled.");
    println!("Run with: cargo run --features serde --example serde_example");
}
