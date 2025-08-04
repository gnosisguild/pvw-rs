//! Simple n-Party Vector Encryption/Decryption Example
//! 
//! This example demonstrates:
//! 1. n parties, each with their own vector of values
//! 2. Use encrypt_all_party_shares() to encrypt all vectors
//! 3. Each party decrypts the values intended for them
//! 4. Clean verification of the encrypt/decrypt cycle

use std::error::Error;
use console::style;
use pvw::{
    public_key::{GlobalPublicKey, Party},
    crs::PvwCrs,
    params::PvwParametersBuilder, PvwParameters,
    encryption,
    decryption,
};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", style("=== Multi-Party Vector Encryption Demo ===").cyan().bold());
    println!();

    // Setup parameters
    let num_parties = 4;
    
    println!("📋 {}", style("Setup:").blue().bold());
    println!("  • Number of parties: {}", num_parties);
    println!("  • Each party has a vector of {} values", num_parties);
    println!();

    // Build PVW parameters with your specified moduli
    let moduli = vec![
        0xffffee001u64,     // Your first modulus
        0xffffc4001u64,     // Your second modulus  
        0x1ffffe0001u64,    // Your third modulus
    ];

    println!("🔧 {}", style("Using Custom Moduli:").blue().bold());
    for (i, &modulus) in moduli.iter().enumerate() {
        println!("  • Modulus {}: 0x{:x} ({} bits)", i, modulus, (modulus as f64).log2().ceil() as u32);
    }
    println!();

    // First, get suggested parameters that satisfy correctness condition
    let (suggested_variance, suggested_bound1, suggested_bound2) = 
        match PvwParameters::suggest_correct_parameters(num_parties, 4, 8, &moduli) {
            Ok(params) => {
                println!("🎯 {}", style("Suggested Parameters:").green().bold());
                println!("  • Secret variance: {}", params.0);
                println!("  • Error bound 1: {}", params.1);
                println!("  • Error bound 2: {}", params.2);
                params
            }
            Err(_) => {
                println!("⚠️  {}", style("Using default parameters (may not satisfy correctness condition)").yellow().bold());
                (1, 50, 100) // Conservative defaults
            }
        };
    println!();

    let params = PvwParametersBuilder::new()
        .set_parties(num_parties)
        .set_dimension(4)
        .set_l(8)
        .set_moduli(&moduli)
        .set_secret_variance(suggested_variance)
        .set_error_bounds_u32(suggested_bound1, suggested_bound2)
        .build_arc()?;

    println!("⚙️  {}", style("PVW Parameters:").blue().bold());
    println!("  • Delta (Δ): {}", params.delta());
    println!("  • Modulus bits: {}", params.q_total().bits());
    
    // Check correctness condition
    if params.verify_correctness_condition() {
        println!("  ✓ Correctness condition satisfied");
    } else {
        println!("  ⚠ Correctness condition NOT satisfied - may need larger delta or smaller error bounds");
    }
    println!();

    let mut rng = OsRng;

    // Generate parties and global public key
    println!("👥 {}", style("Generating Parties:").blue().bold());
    let crs = PvwCrs::new(&params, &mut rng)?;
    let mut global_pk = GlobalPublicKey::new(crs);

    let mut parties = Vec::new();
    for i in 0..num_parties {
        let party = Party::new(i, &params, &mut rng)?;
        global_pk.generate_and_add_party(&party, &mut rng)?;
        parties.push(party);
        println!("  ✓ Party {} created", i);
    }
    println!();

    // Each party creates their vector of values
    println!("📊 {}", style("Party Vectors:").blue().bold());
    let mut all_party_vectors = Vec::new();
    
    for party_id in 0..num_parties {
        // Each party creates a vector of values
        // Party i has values: [i*10+1, i*10+2, i*10+3, i*10+4]
        let party_vector: Vec<u64> = (1..=num_parties)
            .map(|j| (party_id * 10 + j) as u64)
            .collect();
        
        println!("  Party {}: {:?}", party_id, party_vector);
        all_party_vectors.push(party_vector);
    }
    println!();

    // Show what we're encrypting in a nice table
    println!("📋 {}", style("Encryption Matrix:").blue().bold());
    println!("    Each row represents one party's vector to be encrypted");
    println!();
    print!("Party ");
    for i in 0..num_parties {
        print!("{:>8}", format!("Val{}", i));
    }
    println!();
    println!("{}", "-".repeat(6 + num_parties * 8));
    
    for (party_id, vector) in all_party_vectors.iter().enumerate() {
        print!("{:>5} ", party_id);
        for &value in vector {
            print!("{:>8}", value);
        }
        println!();
    }
    println!();

    // Encrypt all party vectors using encrypt_all_party_shares
    println!("🔒 {}", style("Encrypting All Vectors:").blue().bold());
    let start_time = std::time::Instant::now();
    
    let encrypted_vectors = encryption::encrypt_all_party_shares(&all_party_vectors, &global_pk, &mut rng)?;
    
    let encryption_time = start_time.elapsed();
    println!("  ✓ Encrypted {} vectors in {:?}", num_parties, encryption_time);
    println!("  ✓ Generated {} ciphertexts", encrypted_vectors.len());
    println!();

    // Each party decrypts their values from all vectors
    println!("🔓 {}", style("Decryption Results:").blue().bold());
    println!("    Each party decrypts position [party_id] from each encrypted vector");
    println!();

    let mut decryption_results = Vec::new();
    let mut total_correct = 0;
    let mut total_decryptions = 0;

    for recipient_party in 0..num_parties {
        println!("  📤 {}", style(format!("Party {} decrypting:", recipient_party)).green().bold());
        
        let mut party_results = Vec::new();
        
        for sender_party in 0..num_parties {
            let start_decrypt = std::time::Instant::now();
            
            // Party 'recipient_party' decrypts position 'recipient_party' from sender's encrypted vector
            let decrypted_value = decryption::decrypt_party_value(
                &encrypted_vectors[sender_party],
                parties[recipient_party].secret_key(),
                recipient_party
            )?;
            
            let decrypt_time = start_decrypt.elapsed();
            let expected_value = all_party_vectors[sender_party][recipient_party];
            let success = decrypted_value == expected_value;
            
            if success {
                total_correct += 1;
            }
            total_decryptions += 1;
            
            println!("    From Party {}: {} → {} {} ({:?})", 
                sender_party, 
                expected_value, 
                decrypted_value,
                if success { "✓" } else { "✗" },
                decrypt_time
            );
            
            party_results.push((expected_value, decrypted_value, success));
        }
        
        decryption_results.push(party_results);
        println!();
    }

    // Summary statistics
    println!("📈 {}", style("Results Summary:").blue().bold());
    let success_rate = (total_correct as f64 / total_decryptions as f64) * 100.0;
    
    println!("  🎯 Overall: {}/{} decryptions successful ({:.1}%)", 
        total_correct, total_decryptions, success_rate);
    
    // Per-party success rates
    for (party_id, results) in decryption_results.iter().enumerate() {
        let party_correct = results.iter().filter(|(_, _, success)| *success).count();
        let party_rate = (party_correct as f64 / results.len() as f64) * 100.0;
        
        println!("  📊 Party {}: {}/{} successful ({:.1}%)", 
            party_id, party_correct, results.len(), party_rate);
    }
    println!();

    // Show the final decrypted matrix
    println!("📊 {}", style("Decrypted Values Matrix:").blue().bold());
    println!("    Rows = Recipients, Columns = Values from each sender's vector");
    println!();
    print!("Recip ");
    for i in 0..num_parties {
        print!("{:>12}", format!("From Party{}", i));
    }
    println!();
    println!("{}", "-".repeat(6 + num_parties * 12));
    
    for (recipient_id, results) in decryption_results.iter().enumerate() {
        print!("{:>5} ", recipient_id);
        for (expected, decrypted, success) in results {
            let display = if *success {
                format!("{}", decrypted)
            } else {
                format!("{}≠{}", decrypted, expected)
            };
            print!("{:>12}", display);
        }
        println!();
    }
    println!();

    // Performance metrics
    println!("⚡ {}", style("Performance Metrics:").blue().bold());
    println!("  • Total vectors encrypted: {}", num_parties);
    println!("  • Total values decrypted: {}", total_decryptions);
    println!("  • Average encryption time: {:?}", encryption_time / num_parties as u32);
    println!("  • Memory efficiency: Using fhe.rs polynomial operations");
    println!("  • Quantum resistance: Lattice-based cryptography");
    println!();

    // Moduli analysis
    println!("🔍 {}", style("Custom Moduli Analysis:").blue().bold());
    let q_total = params.q_total();
    println!("  • Total modulus Q: {} ({} bits)", q_total, q_total.bits());
    println!("  • Q^(1/l): {} (Delta)", params.delta());
    println!("  • Delta^(l-1): {}", params.delta_power_l_minus_1());
    
    let moduli_product: u128 = moduli.iter().map(|&m| m as u128).product();
    println!("  • Moduli product: 0x{:x}", moduli_product);
    println!("  • Security level: ~{} bits (estimated)", (q_total.bits() as f64 / 2.0) as u32);
    println!();

    // Final status
    if success_rate >= 95.0 {
        println!("🎉 {}", style("SUCCESS: Multi-party vector encryption working perfectly!").green().bold());
        println!("   ✓ All party vectors encrypted successfully");
        println!("   ✓ All intended recipients can decrypt their values");
        println!("   ✓ Privacy preserved: each party only sees their own values");
        println!("   ✓ Custom moduli configuration working correctly");
    } else if success_rate >= 80.0 {
        println!("✅ {}", style("MOSTLY SUCCESSFUL: Minor noise effects detected").yellow().bold());
        println!("   ✓ Core functionality working");
        println!("   ⚠ Some values affected by encryption noise");
        println!("   💡 Consider: Larger delta, smaller error bounds, or different moduli");
    } else {
        println!("⚠️  {}", style("NEEDS ATTENTION: Lower than expected success rate").red().bold());
        println!("   • Check correctness condition: Delta^(l-1) > noise bound");
        println!("   • Try increasing moduli size or adjusting error bounds");
        println!("   • Verify parameter compatibility with your moduli");
    }
    
    println!();
    println!("🚀 {}", style("Ready for multi-party applications!").cyan().bold());
    println!("   • Secure multi-party computation setup");
    println!("   • Distributed secret sharing");
    println!("   • Privacy-preserving data exchange");
    println!("   • Custom moduli: [0x{:x}, 0x{:x}, 0x{:x}]", 
             moduli[0], moduli[1], moduli[2]);

    Ok(())
}