use criterion::{Criterion, criterion_group, criterion_main};
use fhe::bfv::{BfvParametersBuilder, SecretKey as BfvSecretKey};
use fhe::trbfv::ShareManager;
use num_bigint::BigInt;
use pvw::keys::{GlobalPublicKey, Party};
use pvw::prelude::*;
use rand::thread_rng;
use rayon::prelude::*;
use std::sync::Arc;

/// Extract real share data using trBFV to get the actual structure
fn extract_trbfv_share_data() -> PvwResult<Vec<u64>> {
    // Create BFV parameters matching the trBFV example
    let degree = 8192;
    let plaintext_modulus: u64 = 1000;
    let moduli = vec![
        0x800000022a0001,
        0x800000021a0001,
        0x80000002120001,
        0x80000001f60001,
    ];

    let params = BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus(plaintext_modulus)
        .set_moduli(&moduli)
        .build_arc()
        .unwrap();

    let num_parties = 3;
    let threshold = 2;

    // Generate a secret key
    let mut rng = thread_rng();
    let sk_share = BfvSecretKey::random(&params, &mut rng);

    // Create share manager
    let mut share_manager = ShareManager::new(num_parties, threshold, params.clone());
    let sk_poly = share_manager
        .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
        .unwrap();

    // Generate secret shares
    let sk_sss = share_manager
        .generate_secret_shares_from_poly(sk_poly)
        .unwrap();

    // Extract the first party's shares for all coefficients (modulus 0)
    let first_party_shares: Vec<u64> = sk_sss[0]
        .row(0) // First party (party 0)
        .to_vec();

    println!("🔍 Extracted trBFV share data:");
    println!("  - Number of coefficients: {}", first_party_shares.len());
    println!("  - First 10 share values: {:?}", &first_party_shares[..10]);
    println!(
        "  - Last 10 share values: {:?}",
        &first_party_shares[first_party_shares.len() - 10..]
    );

    Ok(first_party_shares)
}

fn bench_data_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("Data Sizes");

    // 128 bit parameters
    let params_128 = PvwParametersBuilder::new()
        .set_parties(3)
        .set_dimension(1024)
        .set_l(8)
        .set_moduli(&[
            0x800000022a0001,
            0x800000021a0001,
            0x80000002120001,
            0x80000001f60001,
        ])
        .set_secret_variance(10.0)
        .set_error_bound_1(BigInt::from(3105605759u64))
        .set_error_bound_2(BigInt::from(18014398509481984u64))
        .build()
        .unwrap();

    let crs_128 = PvwCrs::new(&Arc::new(params_128.clone()), &mut thread_rng()).unwrap();

    // Create global public keys and parties
    let mut global_pk_128 = GlobalPublicKey::new(crs_128.clone());

    // Create all parties for 128-bit parameters
    let mut parties_128 = Vec::new();
    for i in 0..3 {
        let party = Party::new(i, &Arc::new(params_128.clone()), &mut thread_rng()).unwrap();
        global_pk_128
            .generate_and_add_party(&party, &mut thread_rng())
            .unwrap();
        parties_128.push(party);
    }

    // Estimate sizes based on polynomial dimensions and coefficients
    let ring_degree_128 = params_128.l;

    // Estimate bytes per polynomial (assuming 64-bit coefficients)
    let bytes_per_coeff = 8; // 64-bit coefficients
    let coeffs_per_poly_128 = ring_degree_128;
    let bytes_per_poly_128 = coeffs_per_poly_128 * bytes_per_coeff;

    // Calculate estimated sizes based on actual PVW implementation
    // Each polynomial in fhe.rs already contains RNS coefficients for all moduli
    // So we don't need to multiply by number of moduli - it's already included

    // CRS: KxK matrix of polynomials (each poly already has RNS coefficients)
    // Theoretical: k * k * l * 64 * 4 bits = 1024 * 1024 * 8 * 64 * 4 = 2,147,483,648 bits = 256 MB
    let crs_128_bytes = crs_128.matrix.len() * bytes_per_poly_128 * params_128.moduli().len();

    // Secret keys: K vectors of coefficients (not full polynomials)
    // Each vector has l coefficients, stored as i64 (8 bytes each)
    // Theoretical: 1024 * 8 * 64 * 4 bits = 2,097,152 bits = 256 KB
    let secret_key_128_bytes =
        parties_128[0].secret_key.len() * params_128.l * 8 * params_128.moduli().len(); // K * l * 8 * 4 bytes

    // Simulate encrypting secret key shares for threshold scheme
    // Each party has a BFV secret key of degree 8192 (8192 coefficients)
    // For each coefficient, they generate 3 shares (one for each party)
    // So each party produces 8192 coefficients, each shared among 3 parties
    let num_parties = 3;
    let bfv_degree = 128; // Real BFV degree for production
    let shares_per_coefficient = num_parties; // Each coefficient is shared among 3 parties (one per party)
    let shares_per_party = bfv_degree * shares_per_coefficient; // 8192 * 3 = 24,576 shares per party
    let total_shares = num_parties * shares_per_party; // 3 * 24,576 = 73,728 total shares

    // Each share is the same size as a single secret key share
    // RNS representation: 4 moduli * 64 bits = 32 bytes per coefficient
    let single_share_size = params_128.moduli().len() * 8; // 4 moduli * 8 bytes = 32 bytes
    let total_shares_size = total_shares * single_share_size;

    // Calculate per-party Shamir share size (what each party needs to send)
    let shamir_shares_per_party = bfv_degree * shares_per_coefficient; // 8192 * 3 = 24,576 shares
    let shamir_size_per_party = shamir_shares_per_party * single_share_size; // 24,576 * 32 = 786,432 bytes = 0.75 MB

    // Extract real share data using trBFV
    let secret_key_share_from_party_128 = extract_trbfv_share_data().unwrap();

    // Create secret key shares for threshold scheme
    // Each party has 8192 coefficients, each coefficient is shared among 3 parties
    // Each share needs to be duplicated for all 4 moduli
    println!(
        "🏗️  Creating {} total shares ({} parties × {} coefficients × {} shares per coefficient)",
        num_parties * bfv_degree * shares_per_coefficient,
        num_parties,
        bfv_degree,
        shares_per_coefficient
    );
    println!(
        "📊 Shamir Secret Sharing: Each party generates {} shares ({})",
        shamir_shares_per_party,
        format_bytes(shamir_size_per_party)
    );

    let mut all_party_shares = Vec::new();
    for party_id in 0..num_parties {
        if party_id % 5 == 0 {
            println!(
                "  📝 Creating shares for party {}/{}",
                party_id + 1,
                num_parties
            );
        }
        for coeff_id in 0..bfv_degree {
            for share_id in 0..shares_per_coefficient {
                // Create share data for all 4 moduli using the coefficient value
                let mut share_data = Vec::new();
                let coeff_value = secret_key_share_from_party_128
                    [coeff_id % secret_key_share_from_party_128.len()];
                for _modulus in 0..params_128.moduli().len() {
                    share_data.push(coeff_value);
                }
                all_party_shares.push((party_id, coeff_id, share_id, share_data));
            }
        }
    }
    println!("✅ Created {} shares", all_party_shares.len());

    // Encrypt ALL shares using PVW encryption with parallelization
    // Each party encrypts 3 shares for each of their 8192 coefficients
    let total_operations = num_parties * bfv_degree * shares_per_coefficient;
    println!(
        "🚀 Starting parallel encryption of {} parties × {} coefficients × {} shares = {} total operations",
        num_parties, bfv_degree, shares_per_coefficient, total_operations
    );
    println!("⚡ Using rayon parallelization for faster processing");
    println!(
        "⚠️  NOTE: This is a reduced scale test - real scenario would be 3 × 8192 × 3 = 73,728 operations!"
    );

    // Start timing
    let start_time = std::time::Instant::now();

    // Create all encryption tasks - one for each share
    let encryption_tasks: Vec<_> = (0..num_parties)
        .flat_map(|party_id| {
            (0..bfv_degree).flat_map(move |coeff_id| {
                (0..shares_per_coefficient).map(move |share_id| (party_id, coeff_id, share_id))
            })
        })
        .collect();

    println!("📋 Created {} encryption tasks", encryption_tasks.len());

    // Parallel encryption using rayon
    let all_encrypted_shares: Vec<_> = encryption_tasks
        .par_iter()
        .map(|(party_id, coeff_id, share_id)| {
            // TODO: Uncomment this for more detailed logging
            // println!("  🔄 Processing share {}/{} for coefficient {}/{} party {}",
            //         share_id + 1, shares_per_coefficient, coeff_id + 1, bfv_degree, party_id);

            // Get the specific share for this party's coefficient
            let share_data = all_party_shares
                .iter()
                .find(|(p_id, c_id, s_id, _)| {
                    *p_id == *party_id && *c_id == *coeff_id && *s_id == *share_id
                })
                .map(|(_, _, _, share_data)| share_data.clone())
                .unwrap_or_else(|| vec![0u64; params_128.moduli().len()]);

            // Encrypt this single share into a ciphertext
            let mut padded_scalars = vec![0u64; params_128.n];
            // Convert share data to scalar value for PVW encryption
            let scalar_value = share_data
                .chunks(params_128.l)
                .next()
                .map(|chunk| chunk[0] % params_128.moduli()[0])
                .unwrap_or(0);
            padded_scalars[0] = scalar_value; // Put the share value in the first slot

            // Encrypt this share into one ciphertext
            let encrypted_share = pvw::encrypt(&padded_scalars, &global_pk_128).unwrap();
            (*party_id, *coeff_id, *share_id, encrypted_share)
        })
        .collect();

    let encryption_duration = start_time.elapsed();
    println!(
        "✅ Completed parallel encryption of {} shares in {:?}",
        all_encrypted_shares.len(),
        encryption_duration
    );

    // Calculate performance metrics
    let operations_per_second = total_operations as f64 / encryption_duration.as_secs_f64();
    let time_per_operation = encryption_duration.as_secs_f64() / total_operations as f64;

    println!("📊 Performance Metrics:");
    println!("  - Operations per second: {:.2}", operations_per_second);
    println!(
        "  - Time per operation: {:.3} ms",
        time_per_operation * 1000.0
    );

    // Estimate real-world performance
    let real_operations = 3 * 8192 * 3; // 73,728 operations
    let estimated_real_time =
        std::time::Duration::from_secs_f64(real_operations as f64 * time_per_operation);
    println!(
        "  - Estimated real-world time (73,728 ops): {:?}",
        estimated_real_time
    );
    println!(
        "  - Shamir shares per party: {} ({})",
        shamir_shares_per_party,
        format_bytes(shamir_size_per_party)
    );

    // Calculate total size of encrypted shares
    let encrypted_share_size =
        all_encrypted_shares[0].3.c1.len() * 8 + all_encrypted_shares[0].3.c2.len() * 8; // Rough estimate
    let total_encrypted_size = all_encrypted_shares.len() * encrypted_share_size;

    // Helper function to format bytes
    fn format_bytes(bytes: usize) -> String {
        if bytes >= 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{} bytes", bytes)
        }
    }

    // Print detailed size information to stdout for easy collection
    println!("\n=== PVW-RS DATA SIZE BENCHMARKS (RNS representation) ===");

    println!(
        "Parameters (128-bit): {} parties, {} dimension, {} ring degree, {} moduli",
        params_128.n,
        params_128.k,
        params_128.l,
        params_128.moduli().len()
    );
    println!(
        "CRS (128-bit): {} polynomials (~{}) [KxK matrix, each poly has RNS coeffs]",
        crs_128.matrix.len(),
        format_bytes(crs_128_bytes)
    );
    println!(
        "PVW Secret Key (128-bit): {} vectors of {} coeffs (~{}) [K vectors, l coeffs each, i64]",
        parties_128[0].secret_key.len(),
        params_128.l,
        format_bytes(secret_key_128_bytes)
    );

    // Print secret key share encryption information
    println!(
        "TRBFV Secret Key Share Encryption (3 parties, threshold 2): {} total shares (~{}) [Each party has {} shares: {} coefficients × {} shares per coefficient]",
        total_shares,
        format_bytes(total_shares_size),
        shares_per_party,
        bfv_degree,
        shares_per_coefficient
    );
    println!(
        "Shamir Secret Sharing (per party): {} shares (~{}) [{} coefficients × 3 shares per coefficient]",
        shamir_shares_per_party,
        format_bytes(shamir_size_per_party),
        bfv_degree
    );
    println!(
        "Shamir Secret Sharing (total): {} total shares (~{}) [3 parties × {} per party]",
        total_shares,
        format_bytes(total_shares_size),
        format_bytes(shamir_size_per_party)
    );
    println!(
        "TRBFV Single share size: {} bytes [RNS representation with {} moduli × 8 bytes each]",
        single_share_size,
        params_128.moduli().len()
    );

    // Print encrypted share information
    println!(
        "Encrypted TRBFV Secret Key Shares: {} total encrypted shares (~{}) [PVW encrypted]",
        all_encrypted_shares.len(),
        format_bytes(total_encrypted_size)
    );
    println!(
        "Single encrypted share size: {} bytes [PVW ciphertext]",
        encrypted_share_size
    );
    println!("============================\n");

    // Verify decryption correctness for all parties
    println!("Verifying decryption correctness...");
    let test_message: Vec<u64> = (0..params_128.n).map(|i| (i as u64) % 1000).collect();
    let encrypted_test = pvw::encrypt(&test_message, &global_pk_128).unwrap();

    for party_idx in 0..params_128.n {
        let decrypted_value = pvw::decrypt_party_value(
            &encrypted_test,
            &parties_128[party_idx].secret_key,
            party_idx,
        )
        .unwrap();
        assert_eq!(
            decrypted_value, test_message[party_idx],
            "Decryption failed for party {}: expected {}, got {}",
            party_idx, test_message[party_idx], decrypted_value
        );
    }
    println!("✓ All parties can decrypt their respective values correctly");

    // Test threshold decryption (decrypt_party_shares)
    println!("Verifying threshold decryption correctness...");
    let test_messages: Vec<Vec<u64>> = (0..params_128.n)
        .map(|_| (0..params_128.n).map(|i| (i as u64) % 1000).collect())
        .collect();
    let encrypted_tests: Vec<_> = test_messages
        .iter()
        .map(|msg| pvw::encrypt(msg, &global_pk_128).unwrap())
        .collect();

    for party_idx in 0..params_128.n {
        let decrypted_shares = pvw::decrypt_party_shares(
            &encrypted_tests,
            &parties_128[party_idx].secret_key,
            party_idx,
        )
        .unwrap();
        for (dealer_idx, (original, decrypted)) in test_messages
            .iter()
            .zip(decrypted_shares.iter())
            .enumerate()
        {
            assert_eq!(
                *decrypted, original[party_idx],
                "Threshold decryption failed for party {} from dealer {}: expected {}, got {}",
                party_idx, dealer_idx, original[party_idx], decrypted
            );
        }
    }
    println!("✓ All parties can decrypt their shares from all dealers correctly");

    group.bench_function("decrypt_party_shares_128", |b| {
        // Create test ciphertexts for threshold decryption
        let test_messages: Vec<Vec<u64>> = (0..params_128.n)
            .map(|_| (0..params_128.n).map(|i| (i as u64) % 1000).collect())
            .collect();
        let encrypted_tests: Vec<_> = test_messages
            .iter()
            .map(|msg| pvw::encrypt(msg, &global_pk_128).unwrap())
            .collect();

        // Verify decryption correctness before benchmarking
        let decrypted_shares =
            pvw::decrypt_party_shares(&encrypted_tests, &parties_128[0].secret_key, 0).unwrap();
        for (i, (original, decrypted)) in test_messages
            .iter()
            .zip(decrypted_shares.iter())
            .enumerate()
        {
            assert_eq!(
                *decrypted, original[0],
                "Decryption failed for message {}: expected {}, got {}",
                i, original[0], decrypted
            );
        }

        b.iter(|| {
            pvw::decrypt_party_shares(&encrypted_tests, &parties_128[0].secret_key, 0).unwrap()
        });
    });

    group.finish();
}

fn bench_timing_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Timing Operations");

    // 128-bit parameters for security-level benchmarks
    let params_128 = PvwParametersBuilder::new()
        .set_parties(3)
        .set_dimension(1024)
        .set_l(8)
        .set_moduli(&[
            0x800000022a0001,
            0x800000021a0001,
            0x80000002120001,
            0x80000001f60001,
        ])
        .set_secret_variance(10.0)
        .set_error_bound_1(BigInt::from(3105605759u64))
        .set_error_bound_2(BigInt::from(18014398509481984u64))
        .build()
        .unwrap();

    // CRS Generation Benchmarks
    group.bench_function("generate_crs_128", |b| {
        b.iter(|| PvwCrs::new(&Arc::new(params_128.clone()), &mut thread_rng()).unwrap());
    });

    // Pre-generate CRS for other benchmarks
    let crs_128 = PvwCrs::new(&Arc::new(params_128.clone()), &mut thread_rng()).unwrap();

    // Key Generation Benchmarks
    group.bench_function("generate_secret_key_128", |b| {
        b.iter(|| SecretKey::random(&Arc::new(params_128.clone()), &mut thread_rng()).unwrap());
    });

    // Public Key Generation Benchmarks
    group.bench_function("generate_public_key_128", |b| {
        let secret_key =
            SecretKey::random(&Arc::new(params_128.clone()), &mut thread_rng()).unwrap();
        b.iter(|| PublicKey::generate(&secret_key, &crs_128, &mut thread_rng()).unwrap());
    });

    // Global Public Key and Party Setup Benchmarks
    group.bench_function("setup_global_pk_128", |b| {
        b.iter(|| {
            let mut global_pk = GlobalPublicKey::new(crs_128.clone());
            for i in 0..3 {
                let party =
                    Party::new(i, &Arc::new(params_128.clone()), &mut thread_rng()).unwrap();
                global_pk
                    .generate_and_add_party(&party, &mut thread_rng())
                    .unwrap();
            }
            global_pk
        });
    });

    // Encryption Benchmarks
    let mut global_pk_128 = GlobalPublicKey::new(crs_128.clone());
    for i in 0..3 {
        let party = Party::new(i, &Arc::new(params_128.clone()), &mut thread_rng()).unwrap();
        global_pk_128
            .generate_and_add_party(&party, &mut thread_rng())
            .unwrap();
    }

    // Prepare test messages for encryption
    let message_128: Vec<u64> = (0..params_128.n).map(|i| (i as u64) % 1000).collect();

    group.bench_function("encrypt_message_128", |b| {
        b.iter(|| pvw::encrypt(&message_128, &global_pk_128).unwrap());
    });

    // Decryption Benchmarks (using the first party's secret key)
    let parties_128: Vec<Party> = (0..3)
        .map(|i| Party::new(i, &Arc::new(params_128.clone()), &mut thread_rng()).unwrap())
        .collect();

    // Encrypt messages for decryption benchmarks
    let encrypted_128 = pvw::encrypt(&message_128, &global_pk_128).unwrap();

    group.bench_function("decrypt_party_share_128", |b| {
        b.iter(|| pvw::decrypt_party_value(&encrypted_128, &parties_128[0].secret_key, 0).unwrap());
    });

    group.finish();
}

criterion_group!(benches, bench_data_sizes, bench_timing_operations);
criterion_main!(benches);
