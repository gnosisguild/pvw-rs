//! Implementation of PVW parameter and CRS generation using the `pvw-rs` crate.

use std::{env, error::Error, process::exit};

use console::style;
use num_bigint::BigUint;
use pvw::PvwParameters;
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

    // @todo: wait to #8 to be completed and use the new parameter set.
    // consider the following a placeholder for now.
    let mut num_parties = 10;
    let mut threshold = 4;
    let mut dimension = 4;
    let mut redundancy = 8;

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

    // @todo: wait to #8 to be completed and use the new parameter set.
    // consider the following a placeholder for now.

    // The parameters are within bound, let's go! Let's first display some
    // information about the PVW setup.
    println!("# PVW Parameter and CRS Generation");
    println!("\tnum_parties (n) = {num_parties}");
    println!("\tthreshold (t) = {threshold}");
    println!("\tdimension (k) = {dimension}");
    println!("\tredundancy (l) = {redundancy}");

    // Create the modulus using the same large modulus as TRBFV for compatibility
    // Q = 0x1FFFFFFEA0001 × 0x1FFFFFFE88001 × 0x1FFFFFFE48001
    let mod1 = BigUint::from(0x1FFFFFFEA0001u64); // 562949951979521
    let mod2 = BigUint::from(0x1FFFFFFE88001u64); // 562949951881217
    let mod3 = BigUint::from(0x1FFFFFFE48001u64); // 562949951619073
    let modulus: BigUint = &mod1 * &mod2 * &mod3;

    println!("\tmodulus (q) = {} (~{} bits)", modulus, modulus.bits());

    // Standard noise parameters (these would typically be chosen based on security analysis)
    let x_s = 1.0; // Secret distribution parameter
    let x_e1 = 1.0; // First noise distribution parameter
    let x_e2 = 1.0; // Second noise distribution parameter

    println!("\tsecret_param (χs) = {x_s}");
    println!("\tnoise_param1 (χe1) = {x_e1}");
    println!("\tnoise_param2 (χe2) = {x_e2}");

    // Generate the PVW parameters structure
    let params = PvwParameters::new(
        num_parties,
        threshold,
        dimension,
        redundancy,
        modulus.clone(),
        x_s,
        x_e1,
        x_e2,
    )?;

    println!("\n# Parameter Analysis");

    // Compute and display the gadget vector delta
    let delta = params.delta();
    println!("\tgadget_delta (Δ) = {} (~{} bits)", delta, delta.bits());

    // Generate and display the gadget vector
    let gadget_vector = params.gadget_vector()?;
    println!("\tgadget_vector (g) length = {}", gadget_vector.len());
    println!("\tgadget_vector elements:");
    for (i, element) in gadget_vector.iter().enumerate() {
        println!("\t\tg[{}] = {} (~{} bits)", i, element, element.bits());
    }

    // Generate the Common Reference String (CRS)
    println!("\n# CRS Generation");
    let mut rng = OsRng;
    let crs_matrix = params.generate_crs(&mut rng);

    println!(
        "\tCRS matrix A ∈ Z_q^({}×{})",
        crs_matrix.nrows(),
        crs_matrix.ncols()
    );
    println!("\tSample CRS elements:");
    for i in 0..std::cmp::min(3, crs_matrix.nrows()) {
        for j in 0..std::cmp::min(3, crs_matrix.ncols()) {
            let element = &crs_matrix[(i, j)];
            println!(
                "\t\tA[{},{}] = {} (~{} bits)",
                i,
                j,
                element,
                element.bits()
            );
        }
    }

    // Display summary
    println!("\n# Setup Complete");
    println!("PVW parameters generated successfully");
    println!("Gadget vector computed (Δ = {})", delta);
    println!(
        "CRS matrix A generated ({}×{} elements)",
        crs_matrix.nrows(),
        crs_matrix.ncols()
    );
    println!(
        "Total CRS size: {} elements × ~{} bits each = ~{:.1} KB",
        crs_matrix.len(),
        modulus.bits(),
        (crs_matrix.len() as f64 * modulus.bits() as f64) / (8.0 * 1024.0)
    );

    println!("\nReady for PVW multi-receiver encryption protocol");

    Ok(())
}
