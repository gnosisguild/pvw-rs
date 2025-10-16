# PVW Multi-Receiver LWE Encryption

A pure-Rust implementation of the PVW (Peikert–Vaikuntanathan–Waters) multi-receiver LWE encryption scheme designed for use in threshold schemes, PVSS (Publicly Verifiable Secret Sharing), and lattice-based cryptography.

[![Rust Version](https://img.shields.io/badge/rust-1.86.0+-blue.svg)](https://www.rust-lang.org)

## Features

- **Multi-receiver encryption** supporting thousands of parties in a single operation
- **RNS optimization** with full Residue Number System support for efficient polynomial arithmetic
- **Threshold decryption** with support for decryption with subset of parties
- **Parameter validation** ensuring correctness condition satisfaction and security bounds
- **Complete serialization** for distributed deployments and key management
- **Parallel processing** optimized for large-scale operations

### Mathematical Background

This library implements the PVW scheme as described in "Practical Non-interactive Publicly Verifiable Secret Sharing with Thousands of Parties" (Section 2.5) from [eprint.iacr.org/2021/1397.pdf](https://eprint.iacr.org/2021/1397.pdf).

The scheme provides:
- **LWE-based encryption** with polynomial ring arithmetic
- **Multi-party key generation** using Common Reference String (CRS)
- **Threshold decryption** with PVW decoding algorithm
- **RNS-aware operations** for efficient modular arithmetic

### Cryptographic Operations

The library supports three main encryption modes:

1. **Vector Encryption**: Encrypt a vector of `n` values where each party can decrypt only their designated value
2. **Broadcast Encryption**: Encrypt a single value that all parties can decrypt  
3. **Share Distribution**: Efficiently distribute secret shares to multiple parties in a single operation

### Performance

The library is optimized for cryptographic workloads with:

- **Efficient polynomial arithmetic** using fhe.rs infrastructure
- **NTT representation** for fast ring operations
- **Minimal memory allocations** with on-demand polynomial conversion
- **Parallel sampling** for large-scale operations
- **RNS optimization** for modular arithmetic

## Usage

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
pvw = { git = "https://github.com/gnosisguild/pvw-rs" }
```

## Architecture

The library follows a modular design with clear separation of concerns:

- **`params`** - Parameter management with RNS support and correctness validation
- **`crs`** - Common Reference String generation and management
- **`keys`** - Secret and public key generation using CBD sampling
- **`crypto`** - Core encryption and decryption operations
- **`sampling`** - Truncated Gaussian sampling for noise generation
- **`traits`** - Common interfaces for serialization and validation

## Security Considerations

This implementation has not been independently audited. Use with appropriate caution in production environments.

### Parameter Selection Guidelines

The implementation includes parameter validation to ensure:
- **Correctness Condition**: `ℓ * (2σ₁ + σ₂) < Δ/2` where `ℓ` is the redundancy parameter
- **Security Level**: Appropriate LWE dimension `k` and modulus size for target security
- **Error Bounds**: Proper error variance selection for reliable decryption

### Recommended Parameters

For different security levels:
- **128-bit security**: `k ≥ 256`, `ℓ ≥ 8`, modulus bits ≥ 1024
- **256-bit security**: `k ≥ 512`, `ℓ ≥ 16`, modulus bits ≥ 2048

## Dependencies

The implementation leverages the fhe.rs ecosystem:
- **`fhe-math`**: Efficient polynomial arithmetic and RNS operations
- **`fhe-util`**: Cryptographic utilities and sampling functions  
- **`fhe-traits`**: Common traits for serialization and operations

Additional dependencies:
- **`num-bigint`**: Arbitrary precision arithmetic for large parameter handling
- **`ndarray`**: Efficient matrix operations for CRS and public key management
- **`rayon`**: Parallel processing for large-scale operations
- **`zeroize`**: Secure memory clearing for sensitive data

## Testing

Run the test suite:

```bash
cargo test
```

Run tests with verbose output:

```bash
cargo test -- --nocapture
```

## Benchmarks

Run benchmarks:

```bash
cargo bench
```

The benchmarks cover:
- Parameter generation for different security levels
- CRS generation and validation
- Key generation workflows
- Sampling operations
- Validation operations

## Examples

For complete working examples demonstrating multi-party setup, share distribution, and threshold decryption, see the `examples/` directory:

```bash
# Multi-party PVW example
cargo run --example pvw

# Threshold PVW example  
cargo run --example trpvw
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
