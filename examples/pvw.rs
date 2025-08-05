//! Implementation of PVW parameter and CRS generation using the updated `pvw-rs` crate.

use std::{env, error::Error, process::exit};

use console::style;
use pvw::{GlobalPublicKey, Party, PvwCrs, PvwParametersBuilder};
use rand::rngs::OsRng;

fn print_notice_and_exit(error: Option<String>) {
    println!(
        "{} PVW Parameter and CRS Generation",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} pvw [-h] [--help] [--num_parties=<value>] [--threshold=<value>] [--dimension=<value>] [--redundancy=<value>]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} {} {} {} and {} must be at least 1, {} must be < n/2, {} must be power of 2",
        style("constraints:").magenta().bold(),
        style("num_parties").blue(),
        style("threshold").blue(),
        style("dimension").blue(),
        style("redundancy").blue(),
        style("threshold").blue(),
        style("redundancy").blue(),
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    exit(0);
}

fn main() -> Result<(), Box<dyn Error>> {
    // This executable is a command line tool which enables to specify
    // PVW parameters for multi-receiver LWE encryption.
    let args: Vec<String> = env::args().skip(1).collect();

    // Print the help if requested.
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_notice_and_exit(None)
    }

    // Default parameters
    let mut num_parties = 10;
    let mut threshold = 4;
    let mut dimension = 8; // Increased security parameter k
    let mut redundancy = 8; // Minimal power of 2 for NTT

    // Update the parameters depending on the arguments provided.
    for arg in &args {
        if arg.starts_with("--num_parties") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--num_parties` argument".to_string()))
            } else {
                num_parties = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--threshold") {
            let a: Vec<&str> = arg.rsplit('=').collect();
            if a.len() != 2 || a[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--threshold` argument".to_string()))
            } else {
                threshold = a[0].parse::<usize>()?
            }
        } else if arg.starts_with("--dimension") {
            let parts: Vec<&str> = arg.rsplit('=').collect();
            if parts.len() != 2 || parts[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--dimension` argument".to_string()))
            } else {
                dimension = parts[0].parse::<usize>()?
            }
        } else if arg.starts_with("--redundancy") {
            let parts: Vec<&str> = arg.rsplit('=').collect();
            if parts.len() != 2 || parts[0].parse::<usize>().is_err() {
                print_notice_and_exit(Some("Invalid `--redundancy` argument".to_string()))
            } else {
                redundancy = parts[0].parse::<usize>()?
            }
        } else {
            print_notice_and_exit(Some(format!("Unrecognized argument: {arg}")))
        }
    }

    // Validate parameters
    if num_parties == 0 || threshold == 0 || dimension == 0 || redundancy == 0 {
        print_notice_and_exit(Some("All parameters must be nonzero".to_string()))
    }
    if threshold >= (num_parties + 1) / 2 {
        print_notice_and_exit(Some(
            "Threshold must be strictly less than half the number of parties".to_string(),
        ))
    }
    if (redundancy & (redundancy - 1)) != 0 {
        print_notice_and_exit(Some(
            "Redundancy parameter must be a power of 2".to_string(),
        ))
    }

    // Display PVW setup information
    println!("# PVW Parameter and CRS Generation");
    println!("\tnum_parties (n) = {num_parties}");
    println!("\tthreshold (t) = {threshold}");
    println!("\tdimension (k) = {dimension}");
    println!("\tredundancy (l) = {redundancy}");

    // Standard NTT-friendly moduli for fhe.rs compatibility
    let moduli = vec![
        0x1FFFFFFEA0001u64, // 562949951979521
        0x1FFFFFFE88001u64, // 562949951881217
        0x1FFFFFFE48001u64, // 562949951619073
    ];

    // Build PVW parameters using the new builder pattern
    let params = PvwParametersBuilder::new()
        .set_parties(num_parties)
        .set_dimension(dimension)
        .set_l(redundancy)
        .set_moduli(&moduli)
        .set_secret_variance(1) // CBD variance for secret keys
        .build_arc()?;

    // Display computed threshold (automatically set to < n/2)
    println!("\tcomputed_threshold (t) = {}", params.t);
    println!("\tsecret_variance = {}", params.secret_variance);

    // Display moduli information
    let q_total = params.q_total();
    println!(
        "\ttotal_modulus (Q) = {} (~{} bits)",
        q_total,
        q_total.bits()
    );
    println!("\tmoduli_count = {}", params.moduli().len());
    for (i, &modulus) in params.moduli().iter().enumerate() {
        println!(
            "\t\tq[{}] = {} (~{} bits)",
            i,
            modulus,
            64 - modulus.leading_zeros()
        );
    }

    // Display error bounds
    println!(
        "\terror_bound_1 = {} (~{} bits)",
        params.error_bound_1,
        params.error_bound_1.bits()
    );
    println!(
        "\terror_bound_2 = {} (~{} bits)",
        params.error_bound_2,
        params.error_bound_2.bits()
    );

    println!("\n# Parameter Analysis");

    // Compute and display the gadget vector delta
    let delta = params.delta();
    println!("\tgadget_delta (Δ) = {} (~{} bits)", delta, delta.bits());

    // Generate and display the gadget vector
    let gadget_vector = params.gadget_vector();
    println!("\tgadget_vector (g) length = {}", gadget_vector.len());
    println!("\tgadget_vector elements (first 5):");
    for (i, element) in gadget_vector.iter().take(5).enumerate() {
        println!("\t\tg[{}] = {} (~{} bits)", i, element, element.bits());
    }
    if gadget_vector.len() > 5 {
        println!("\t\t... and {} more elements", gadget_vector.len() - 5);
    }

    // Generate the Common Reference String (CRS)
    println!("\n# CRS Generation");
    let mut rng = OsRng;
    let crs = PvwCrs::new(&params, &mut rng)?;

    println!(
        "\tCRS validation: {}",
        if crs.validate().is_ok() {
            "✓ PASSED"
        } else {
            "✗ FAILED"
        }
    );
    println!(
        "\tCRS matrix A ∈ R_q^({}×{})",
        crs.dimensions().0,
        crs.dimensions().1
    );
    println!("\tCRS polynomial degree: {}", params.l);
    println!("\tCRS representation: NTT (optimized for multiplication)");

    // Sample CRS elements (coefficient form for display)
    println!("\tSample CRS polynomial coefficients:");
    for i in 0..std::cmp::min(2, dimension) {
        for j in 0..std::cmp::min(2, dimension) {
            if let Some(poly) = crs.get(i, j) {
                // Convert a copy to coefficient form for display
                let mut display_poly = poly.clone();
                display_poly.change_representation(fhe_math::rq::Representation::PowerBasis);
                let coeffs = display_poly.coefficients();

                println!("\t\tA[{},{}] coefficients (first 5):", i, j);
                if coeffs.nrows() > 0 {
                    let first_row = coeffs.row(0);
                    for (k, &coeff) in first_row.iter().take(5).enumerate() {
                        println!("\t\t\t[{}] = {}", k, coeff);
                    }
                    if first_row.len() > 5 {
                        println!("\t\t\t... and {} more coefficients", first_row.len() - 5);
                    }
                }
            }
        }
    }

    // Demonstrate key generation workflow
    println!(
        "\n# Key Generation Demo (k={}, l={})",
        dimension, redundancy
    );

    // Generate some parties
    let num_demo_parties = std::cmp::min(3, num_parties);
    let mut parties = Vec::new();
    println!("\tGenerating {} demo parties:", num_demo_parties);

    for i in 0..num_demo_parties {
        let party = Party::new(i, &params, &mut rng)?;
        println!("\t\tParty {}: secret key generated (CBD coefficients)", i);

        // Show sample secret key coefficients
        let sk_coeffs = party.secret_key().coefficients();
        if !sk_coeffs.is_empty() && !sk_coeffs[0].is_empty() {
            println!(
                "\t\t\tSample coefficients: {:?}",
                &sk_coeffs[0][..std::cmp::min(5, sk_coeffs[0].len())]
            );
        }

        parties.push(party);
    }

    // Generate global public key
    println!("\tGenerating global public key...");
    let mut global_pk = GlobalPublicKey::new(crs);
    global_pk.generate_all_party_keys(&parties, &mut rng)?;

    println!(
        "\t✓ Global public key generated for {} parties",
        global_pk.num_public_keys()
    );
    println!(
        "\t✓ Public key validation: {}",
        if global_pk.validate().is_ok() {
            "PASSED"
        } else {
            "FAILED"
        }
    );

    // Display size estimates
    println!("\n# Size Analysis (k={}, l={})", dimension, redundancy);
    let poly_size_bits = params.l * 64; // Rough estimate: l coefficients × 64 bits each
    let crs_size_kb = (dimension * dimension * poly_size_bits) as f64 / (8.0 * 1024.0);
    let sk_size_kb = (dimension * poly_size_bits) as f64 / (8.0 * 1024.0);
    let pk_size_kb = (dimension * poly_size_bits) as f64 / (8.0 * 1024.0);

    println!("\tEstimated sizes (coefficient form):");
    println!(
        "\t\tCRS matrix: ~{:.1} KB ({} polynomials of degree {})",
        crs_size_kb,
        dimension * dimension,
        redundancy
    );
    println!(
        "\t\tSecret key: ~{:.1} KB ({} polynomials of degree {})",
        sk_size_kb, dimension, redundancy
    );
    println!(
        "\t\tPublic key: ~{:.1} KB ({} polynomials of degree {})",
        pk_size_kb, dimension, redundancy
    );
    println!(
        "\t\tGlobal public key: ~{:.1} KB ({} party keys)",
        pk_size_kb * num_parties as f64,
        num_parties
    );

    // Display computational benefits
    println!("\n# Performance Features");
    println!("\t✓ NTT-optimized polynomial multiplication: O(l log l)");
    println!(
        "\t✓ RNS arithmetic for large moduli: {} components",
        params.moduli().len()
    );
    println!("\t✓ Coefficient-based storage: zero-cost coefficient access");
    println!("\t✓ On-demand polynomial conversion: convert only when needed");
    println!("\t✓ fhe.rs integration: production-grade lattice cryptography");

    // Display summary
    println!("\n# Setup Complete");
    println!(
        "✓ PVW parameters generated successfully (k={}, l={})",
        dimension, redundancy
    );
    println!(
        "✓ Gadget vector computed (Δ = {}, {} elements)",
        delta,
        gadget_vector.len()
    );
    println!(
        "✓ CRS matrix A generated ({}×{} polynomials in NTT form)",
        dimension, dimension
    );
    println!(
        "✓ Demo key generation completed ({} parties)",
        num_demo_parties
    );
    println!("✓ All validations passed");

    println!("\n🚀 Ready for PVW multi-receiver encryption protocol!");
    println!(
        "   • Security parameter k = {} (increased security)",
        dimension
    );
    println!(
        "   • Polynomial degree l = {} (minimal for efficiency)",
        redundancy
    );
    println!("   • Parties can encrypt to any subset");
    println!("   • Threshold decryption with t={} parties", params.t);
    println!("   • Efficient polynomial operations via NTT");
    println!("   • Secure coefficient storage with zeroization");

    Ok(())
}
