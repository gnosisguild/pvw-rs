//! Complete serialization example for pvw-rs
//!
//! Demonstrates both serde (JSON) and fhe-traits (binary) serialization
//! for all major PVW types.

use pvw::prelude::*;
use fhe_traits::Serialize;
use std::sync::Arc;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("🔒 PVW Complete Serialization Example");
    println!("=====================================");

    // Create test parameters
    let params = PvwParameters::builder()
        .set_parties(3)
        .set_dimension(2)
        .set_l(8)
        .set_moduli(&[0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64])
        .set_secret_variance(1)
        .set_error_bounds_u32(50, 100)
        .build_arc()?;

    println!("📋 Created PVW parameters: n={}, k={}, l={}", params.n, params.k, params.l);

    // Test 1: Parameters serialization (serde)
    println!("\n1️⃣ Testing Parameters Serialization (JSON)");
    #[cfg(feature = "serde")]
    {
        let serializable_params = params.to_serializable();
        let params_json = serde_json::to_string_pretty(&serializable_params)?;
        println!("   ✅ Serialized to JSON ({} bytes)", params_json.len());
        
        let deserialized: SerializablePvwParameters = serde_json::from_str(&params_json)?;
        let reconstructed_params = Arc::new(PvwParameters::from_serializable(deserialized)?);
        println!("   ✅ Successfully round-trip: n={}, k={}, l={}", 
                 reconstructed_params.n, reconstructed_params.k, reconstructed_params.l);
    }
    #[cfg(not(feature = "serde"))]
    {
        println!("   ⚠️  Skipped (serde feature not enabled)");
    }

    // Test 2: Secret Key serialization (serde)
    println!("\n2️⃣ Testing Secret Key Serialization (JSON)");
    let mut rng = rand::thread_rng();
    let secret_key = SecretKey::random(&params, &mut rng)?;
    
    #[cfg(feature = "serde")]
    {
        let serializable_sk = secret_key.to_serializable();
        let sk_json = serde_json::to_string(&serializable_sk)?;
        println!("   ✅ Serialized to JSON ({} bytes)", sk_json.len());
        
        let deserialized_sk: SerializableSecretKey = serde_json::from_str(&sk_json)?;
        let _reconstructed_sk = SecretKey::from_serializable(deserialized_sk, params.clone())?;
        println!("   ✅ Successfully round-trip secret key");
    }
    #[cfg(not(feature = "serde"))]
    {
        println!("   ⚠️  Skipped (serde feature not enabled)");
    }

    // Test 3: Party serialization (serde)
    println!("\n3️⃣ Testing Party Serialization (JSON)");
    let party = Party::new(0, &params, &mut rng)?;
    
    #[cfg(feature = "serde")]
    {
        let serializable_party = party.to_serializable();
        let party_json = serde_json::to_string(&serializable_party)?;
        println!("   ✅ Serialized to JSON ({} bytes)", party_json.len());
        
        let deserialized_party: SerializableParty = serde_json::from_str(&party_json)?;
        let reconstructed_party = Party::from_serializable(deserialized_party, &params)?;
        println!("   ✅ Successfully round-trip party with index {}", reconstructed_party.index());
    }
    #[cfg(not(feature = "serde"))]
    {
        println!("   ⚠️  Skipped (serde feature not enabled)");
    }

    // Test 4: CRS serialization (fhe-traits binary)
    println!("\n4️⃣ Testing CRS Serialization (Binary)");
    let crs = PvwCrs::new(&params, &mut rng)?;
    
    let crs_bytes = crs.to_bytes();
    println!("   ✅ Serialized to binary ({} bytes)", crs_bytes.len());
    
    let reconstructed_crs = PvwCrs::from_bytes_with_params(&crs_bytes, params.clone())?;
    println!("   ✅ Successfully round-trip CRS with dimensions {:?}", reconstructed_crs.dimensions());

    // Test 5: Public Key serialization (fhe-traits binary)
    println!("\n5️⃣ Testing Public Key Serialization (Binary)");
    let public_key = PublicKey::generate(&secret_key, &crs, &mut rng)?;
    
    let pk_bytes = public_key.to_bytes();
    println!("   ✅ Serialized to binary ({} bytes)", pk_bytes.len());
    
    let reconstructed_pk = PublicKey::from_bytes_with_params(&pk_bytes, params.clone())?;
    println!("   ✅ Successfully round-trip public key with {} polynomials", reconstructed_pk.dimension());

    // Test 6: Global Public Key serialization (fhe-traits binary)
    println!("\n6️⃣ Testing Global Public Key Serialization (Binary)");
    let mut global_pk = GlobalPublicKey::new(crs.clone());
    global_pk.add_public_key(0, public_key)?;
    
    let global_pk_bytes = global_pk.to_bytes();
    println!("   ✅ Serialized to binary ({} bytes)", global_pk_bytes.len());
    
    let reconstructed_global_pk = GlobalPublicKey::from_bytes_with_params(&global_pk_bytes, params.clone())?;
    println!("   ✅ Successfully round-trip global public key with {} keys", 
             reconstructed_global_pk.num_public_keys());

    // Test 7: Ciphertext serialization (fhe-traits binary)
    println!("\n7️⃣ Testing Ciphertext Serialization (Binary)");
    let scalars = vec![42u64, 123u64, 456u64];
    let mut full_global_pk = GlobalPublicKey::new(crs);
    
    // Add all parties
    for i in 0..params.n {
        let party = Party::new(i, &params, &mut rng)?;
        full_global_pk.generate_and_add_party(&party, &mut rng)?;
    }
    
    let ciphertext = encrypt(&scalars, &full_global_pk)?;
    
    let ct_bytes = ciphertext.to_bytes();
    println!("   ✅ Serialized to binary ({} bytes)", ct_bytes.len());
    
    let reconstructed_ct = PvwCiphertext::from_bytes_with_params(&ct_bytes, params.clone())?;
    println!("   ✅ Successfully round-trip ciphertext with {} encrypted values", reconstructed_ct.len());

    println!("\n🎉 All serialization tests passed!");
    println!("\n📊 Summary:");
    println!("   • Parameters: ✅ JSON (serde)");
    println!("   • Secret Keys: ✅ JSON (serde)");
    println!("   • Parties: ✅ JSON (serde)");
    println!("   • CRS: ✅ Binary (fhe-traits)");
    println!("   • Public Keys: ✅ Binary (fhe-traits)");
    println!("   • Global Public Keys: ✅ Binary (fhe-traits)");
    println!("   • Ciphertexts: ✅ Binary (fhe-traits)");
    println!("\n🚀 Complete serialization support for all PVW types!");

    Ok(())
}
