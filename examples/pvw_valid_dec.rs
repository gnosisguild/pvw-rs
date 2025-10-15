//! Multi-Party Vector Encryption Example with Valid Ciphertext Decryption
//!
//! Demonstrates PVW encryption system with valid ciphertext decryption where:
//! 1. Multiple parties each encrypt their own vector of values (n dealers)
//! 2. Some ciphertexts are validated and deemed "valid" for decryption (externally)
//! 3. Each party only decrypts the valid ciphertexts (subset of all dealers)
//! 4. Dealer indices are preserved for later reconstruction
//! 5. Threshold (from BFV) is only used to check if we have enough valid ciphertexts
//! 6. Privacy is preserved: parties only see their designated shares from dealers with valid ciphertexts

use console::style;
use pvw::{
    crypto::PvwCiphertext,
    crypto::{decrypt_party_shares, decrypt_party_value, encrypt_all_party_shares},
    keys::{GlobalPublicKey, Party},
    params::{PvwCrs, PvwParametersBuilder},
};
use rand::{RngCore, rngs::OsRng, seq::SliceRandom};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!(
        "{}",
        style("=== Valid Ciphertext Multi-Party Vector Encryption Demo ===")
            .cyan()
            .bold()
    );
    println!();

    // Configuration
    // let num_parties = 7;
    // let threshold = 5; // Minimum number of valid ciphertexts needed (from threshold BFV)
    // let ring_degree = 8; // Must be a power of two
    // let dimension = 32;
    // let secret_variance = 0.5; // Set your desired variance
    // let moduli = vec![0xffffee001u64, 0xffffc4001u64, 0x1ffffe0001u64];

    //for 128-bit security, try these suggested parameters from https://github.com/gnosisguild/enclave-research/tree/FHE_Parameters/Parameters:
    //In this case don't use suggested_error_bounds, just use these directly
    let moduli = vec![
        0x800000022a0001,
        0x800000021a0001,
        0x80000002120001,
        0x80000001f60001,
    ];
    let num_parties = 5;
    let threshold = 2;
    let ring_degree = 8;
    let dimension = 1024;
    let secret_variance = 10.0;
    let suggested_bound1 = 1;
    let suggested_bound2 = 1172385;

    // Get error bounds that satisfy correctness condition
    // let (suggested_bound1, suggested_bound2) = PvwParameters::suggest_error_bounds(
    //     num_parties,
    //     dimension,
    //     ring_degree,
    //     &moduli,
    //     secret_variance,
    // )
    // .unwrap_or((50, 100));

    // Build PVW parameters
    let params = PvwParametersBuilder::new()
        .set_parties(num_parties)
        .set_dimension(dimension)
        .set_l(ring_degree)
        .set_moduli(&moduli)
        .set_secret_variance(secret_variance)
        .set_error_bounds_u32(suggested_bound1, suggested_bound2)
        .build_arc()?;

    // Display parameters
    println!("⚙️  {}", style("PVW Parameters:").blue().bold());
    println!(
        "  • Parties: {}, Threshold: {}, Dimension: {}, Ring degree: {}",
        params.n, threshold, params.k, params.l
    );
    println!(
        "  • Delta (Δ): {}, Modulus bits: {}",
        params.delta(),
        params.q_total().bits()
    );
    println!(
        "  • Error bounds: ({suggested_bound1}, {suggested_bound2}), Secret variance: {secret_variance}"
    );
    println!(
        "  • Correctness condition: {}",
        if params.verify_correctness_condition() {
            "✓ Satisfied"
        } else {
            "✗ Not satisfied"
        }
    );
    println!();

    let mut rng = OsRng;

    // Generate parties and global public key
    let crs = PvwCrs::new(&params, &mut rng)?;
    let mut global_pk = GlobalPublicKey::new(crs);

    let mut parties = Vec::new();
    for i in 0..num_parties {
        let party: Party = Party::new(i, &params, &mut rng)?;
        global_pk.generate_and_add_party(&party, &mut rng)?;
        parties.push(party);
    }

    // Each party creates their vector of values to distribute
    let mut all_party_vectors = Vec::new();
    for party_id in 0..num_parties {
        let party_vector: Vec<u64> = (1..=num_parties)
            .map(|j| (party_id * 1000 + j) as u64)
            .collect();
        all_party_vectors.push(party_vector);
    }

    // Display the values being encrypted
    println!(
        "📊 {}",
        style("Share Distribution Matrix (what each dealer encrypts):")
            .blue()
            .bold()
    );
    println!("    Rows = Dealers, Columns = Values for each recipient");
    println!();
    print!("Dealer ");
    for i in 0..num_parties {
        print!("{:>8}", format!("→P{i}"));
    }
    println!();
    println!("{}", "-".repeat(7 + num_parties * 8));

    for (dealer_id, vector) in all_party_vectors.iter().enumerate() {
        print!("{dealer_id:>6} ");
        for &value in vector {
            print!("{value:>8}");
        }
        println!();
    }
    println!();

    // Encrypt all party vectors (creates n ciphertexts, one per dealer)
    let start_time = std::time::Instant::now();
    let all_ciphertexts = encrypt_all_party_shares(&all_party_vectors, &global_pk)?;
    let encryption_time = start_time.elapsed();

    // Determine which dealers have valid ciphertexts (externally validated)
    // For this demo, we randomly select a subset of dealers as having valid ciphertexts
    // In real implementation, this would be:
    // let valid_dealer_indices: Vec<usize> = get_validated_dealer_indices(); // External function
    // let num_valid_ciphertexts = valid_dealer_indices.len();
    //
    // // Check if we have enough valid ciphertexts
    // if num_valid_ciphertexts < threshold {
    //     return Err("Insufficient valid ciphertexts".into());
    // }

    // For demonstration, we simulate the validation results:
    let mut dealer_indices: Vec<usize> = (0..num_parties).collect();
    dealer_indices.shuffle(&mut rng);

    // Determine which dealers have valid ciphertexts (random simulation of validation)
    let num_valid_ciphertexts =
        threshold + (rng.next_u32() as usize % (num_parties - threshold + 1));
    let valid_dealer_indices: Vec<usize> = dealer_indices
        .into_iter()
        .take(num_valid_ciphertexts)
        .collect();

    println!(
        "🔍 {}",
        style("Ciphertext Validation Results:").blue().bold()
    );
    println!("    Out of {num_parties} dealers, {num_valid_ciphertexts} have valid ciphertexts");
    println!("    Dealers with valid ciphertexts: {valid_dealer_indices:?}");

    // Check if we have enough valid ciphertexts (threshold condition)
    if num_valid_ciphertexts >= threshold {
        println!("    ✓ Sufficient valid ciphertexts ({num_valid_ciphertexts} ≥ {threshold})");
    } else {
        println!("    ✗ Insufficient valid ciphertexts ({num_valid_ciphertexts} < {threshold})");
        println!("    Protocol would abort here in practice");
        return Ok(());
    }
    println!("    All parties will decrypt only the valid ciphertexts");
    println!();

    // Select only the valid ciphertexts for decryption
    let valid_ciphertexts: Vec<PvwCiphertext> = valid_dealer_indices
        .iter()
        .map(|&dealer_idx| all_ciphertexts[dealer_idx].clone())
        .collect();

    // Each party independently decrypts their shares from valid ciphertexts
    let start_decrypt = std::time::Instant::now();

    let mut valid_shares_only = Vec::new();
    for (party_index, party) in parties.iter().enumerate() {
        let mut party_shares = Vec::new();
        for ciphertext in &valid_ciphertexts {
            let share = decrypt_party_value(ciphertext, &party.secret_key, party_index)?;
            party_shares.push(share);
        }
        valid_shares_only.push(party_shares);
    }

    let decryption_time = start_decrypt.elapsed();

    println!(
        "✅ {}",
        style("Valid ciphertext decryption completed successfully!")
            .green()
            .bold()
    );
    println!("    All parties decrypted the same {num_valid_ciphertexts} valid ciphertexts");
    println!();

    // Count correct decryptions using the valid shares data
    let mut valid_correct = 0;
    let mut valid_total = 0;
    for (recipient_party_index, party_valid_shares) in valid_shares_only.iter().enumerate() {
        for (share_idx, &decrypted_value) in party_valid_shares.iter().enumerate() {
            let dealer_idx = valid_dealer_indices[share_idx]; // Map back to dealer
            let expected_value = all_party_vectors[dealer_idx][recipient_party_index];
            if decrypted_value == expected_value {
                valid_correct += 1;
            }
            valid_total += 1;
        }
    }

    // Display valid ciphertext decryption results (shares only, no dealer IDs)
    println!(
        "📊 {}",
        style("Valid Ciphertext Decryption Results (decrypted shares only):")
            .blue()
            .bold()
    );
    println!(
        "    Each party's {num_valid_ciphertexts} shares from dealers with valid ciphertexts {valid_dealer_indices:?}"
    );
    println!();

    for (recipient_id, shares) in valid_shares_only.iter().enumerate() {
        print!("P{recipient_id}: ");
        for &share in shares {
            print!("{share:>6} ");
        }
        println!();
    }
    println!();

    // Verify valid shares using shares-only data
    println!("🔍 {}", style("Valid Share Verification:").blue().bold());
    let mut valid_verification_details = Vec::new();
    for (recipient_party_index, valid_shares) in valid_shares_only.iter().enumerate() {
        for (share_idx, &decrypted_value) in valid_shares.iter().enumerate() {
            let dealer_idx = valid_dealer_indices[share_idx];
            let expected = all_party_vectors[dealer_idx][recipient_party_index];
            let matches = expected == decrypted_value;
            valid_verification_details.push((
                dealer_idx,
                recipient_party_index,
                expected,
                decrypted_value,
                matches,
            ));
        }
    }

    // Show any valid share mismatches
    let valid_mismatches: Vec<_> = valid_verification_details
        .iter()
        .filter(|(_, _, _, _, matches)| !matches)
        .collect();

    if !valid_mismatches.is_empty() {
        println!("  Valid share mismatches found:");
        for (dealer, recipient, expected, received, _) in valid_mismatches {
            println!("    D{dealer} → P{recipient}: expected {expected}, got {received}");
        }
    } else {
        println!("  ✓ All valid shares correctly transmitted and decrypted!");
    }

    // Results summary
    let valid_success_rate = (valid_correct as f64 / valid_total as f64) * 100.0;
    println!(
        "📈 {}",
        style("Valid Ciphertext Results Summary:").blue().bold()
    );
    println!(
        "  • Valid share success rate: {valid_correct}/{valid_total} ({valid_success_rate:.1}%)"
    );
    println!(
        "  • Operations: {num_parties} encrypt calls, 1 valid ciphertext decrypt call (all parties)"
    );
    println!(
        "  • Each party decrypted {num_valid_ciphertexts} valid shares (instead of all {num_parties})"
    );
    println!("  • Threshold check: {num_valid_ciphertexts} valid ≥ {threshold} required ✓");
    println!();

    // Performance metrics
    println!("⚡ {}", style("Performance:").blue().bold());
    println!(
        "  • Encryption time: {encryption_time:?} ({:?} avg per dealer)",
        encryption_time / num_parties as u32
    );
    println!(
        "  • Valid ciphertext decryption time: {decryption_time:?} (single call for all parties)",
    );
    println!(
        "  • Efficiency: {valid_total} valid decrypt operations vs {} full operations",
        num_parties * num_parties
    );
    println!(
        "  • Savings: {:.1}% fewer decryptions needed",
        (1.0 - valid_total as f64 / (num_parties * num_parties) as f64) * 100.0
    );
    println!();

    // Demonstration: Show what full decryption would have given us
    println!(
        "🔄 {}",
        style("Comparison with Full Decryption:").blue().bold()
    );

    // For comparison, also do full decryption on one party
    let comparison_party_idx = 0;
    let full_shares = decrypt_party_shares(
        &all_ciphertexts,
        &parties[comparison_party_idx].secret_key,
        comparison_party_idx,
    )?;
    let valid_shares = &valid_shares_only[comparison_party_idx];

    println!("  Party {comparison_party_idx} comparison:");
    print!("    Full decryption ({num_parties} shares):           ");
    for &share in &full_shares {
        print!("{share:>6} ");
    }
    println!();

    print!("    Valid ciphertext decryption ({num_valid_ciphertexts} shares): ");
    for &share in valid_shares {
        print!("{share:>6} ");
    }
    println!();
    println!("    (Valid shares are from dealers: {valid_dealer_indices:?})");
    println!();

    // Final status
    if valid_success_rate == 100.0 {
        println!(
            "🎉 {}",
            style("SUCCESS: Valid Ciphertext PVSS working perfectly!")
                .green()
                .bold()
        );
        println!(
            "    Each party received exactly their shares from {num_valid_ciphertexts} dealers with valid ciphertexts."
        );
        println!("    Valid dealer indices preserved for reconstruction: {valid_dealer_indices:?}");
        println!("    Threshold condition satisfied: {num_valid_ciphertexts} ≥ {threshold}");
    } else if valid_success_rate >= 80.0 {
        println!(
            "✅ {}",
            style("MOSTLY SUCCESSFUL: Minor valid ciphertext decryption issues detected")
                .yellow()
                .bold()
        );
    } else {
        println!(
            "⚠️  {}",
            style("NEEDS ATTENTION: Low valid ciphertext success rate")
                .red()
                .bold()
        );
    }

    Ok(())
}
