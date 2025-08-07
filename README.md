# PVW Multi-Receiver LWE Encryption

A pure-Rust implementation of the PVW (Peikert–Vaikuntanathan–Waters) multi-receiver LWE encryption scheme designed for use in threshold schemes, PVSS (Publicly Verifiable Secret Sharing), and lattice-based cryptography.

This implementation follows the protocol described in "Practical Non-interactive Publicly Verifiable Secret Sharing with Thousands of Parties" (Section 2.5) from https://eprint.iacr.org/2021/1397.pdf. The current implementation provides a passively secure version of the protocol optimized for multi-party secret sharing scenarios.

## Architecture

The module follows a modular design with clear separation of concerns:

- `params.rs` - PVW parameter management with RNS (Residue Number System) support and correctness condition validation
- `crs.rs` - Common Reference String generation and management for multi-party encryption
- `secret_key.rs` - Secret key generation using CBD (Centered Binomial Distribution) with efficient coefficient storage
- `public_key.rs` - Individual and global public key management for multi-party scenarios
- `encryption.rs` - Multi-receiver encryption operations supporting vector encryption and broadcast modes
- `decryption.rs` - RNS-aware decryption with PVW decoding algorithm and threshold decryption support
- `normal.rs` - Truncated Gaussian sampling for large variance noise generation with arbitrary precision arithmetic

The module provides complete serialization support for distributed deployments:

- `PvwCrs::to_bytes()` / `PvwCrs::from_bytes()` - For common reference strings
- `GlobalPublicKey::to_bytes()` / `GlobalPublicKey::from_bytes()` - For global public keys
- `SecretKey::serialize_coefficients()` / `SecretKey::from_coefficients()` - For secret key matrices
- `PvwCiphertext::to_bytes()` / `PvwCiphertext::from_bytes()` - For encrypted data

## Usage

For a complete working example demonstrating multi-party setup, share distribution, and threshold decryption, see [`examples/pvw.rs`](examples/pvw.rs).

The example can be run with configurable parameters:
```bash
cargo run --example pvw
```

## Key Features

### Multi-Receiver Encryption
- **Vector Encryption**: Encrypt a vector of `n` values where each party can decrypt only their designated value
- **Broadcast Encryption**: Encrypt a single value that all parties can decrypt
- **Share Distribution**: Efficiently distribute secret shares to multiple parties in a single operation

### RNS Optimization
- **Residue Number System**: Full RNS support for efficient polynomial arithmetic
- **NTT Representation**: Automatic conversion to NTT form for fast ring operations
- **Modular Arithmetic**: Optimized modular operations using fhe.rs infrastructure

### Parameter Management
- **Correctness Validation**: Built-in parameter validation ensuring decryption correctness
- **Security Bounds**: Automatic calculation of error bounds and security parameters
- **Flexible Configuration**: Support for custom moduli chains and security levels

### Threshold Operations
- **Threshold Decryption**: Support for decryption with subset of parties
- **Share Aggregation**: Efficient aggregation of decryption shares
- **Robust Decoding**: Multiple decoding strategies for different noise levels

## Security Considerations

This implementation has not been independently audited. Use with appropriate caution in production environments.

The security of the PVW scheme relies on:
- Proper parameter selection for the underlying LWE problem
- Secure generation and distribution of the common reference string
- Protection of individual secret keys
- Appropriate noise sampling and error bounds
- Correctness condition satisfaction for decryption reliability

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
- `fhe-math`: Efficient polynomial arithmetic and RNS operations
- `fhe-util`: Cryptographic utilities and sampling functions
- `fhe-traits`: Common traits for serialization and operations

Additional dependencies:
- `num-bigint`: Arbitrary precision arithmetic for large parameter handling
- `ndarray`: Efficient matrix operations for CRS and public key management
- `rayon`: Parallel processing for large-scale operations
- `zeroize`: Secure memory clearing for sensitive data

## Performance

The implementation is optimized for:
- **Large-scale deployments**: Efficient handling of thousands of parties
- **Batch operations**: Optimized for encrypting multiple vectors simultaneously
- **Memory efficiency**: On-demand polynomial conversion and RNS-aware storage
- **Parallel processing**: Multi-threaded sampling and arithmetic operations

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
