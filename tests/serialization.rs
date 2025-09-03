//! Comprehensive tests for PVW serialization
//!
//! These tests verify that all PVW types can be serialized and deserialized correctly
//! while preserving their mathematical properties and functionality.

#[cfg(all(test, feature = "serde"))]
mod tests {
    use pvw::prelude::*;
    use rand::thread_rng;
    use serde_json;

    /// Create test parameters for use in serialization tests
    fn create_test_params() -> std::sync::Arc<PvwParameters> {
        PvwParameters::builder()
            .set_parties(3)
            .set_dimension(2)
            .set_l(8)
            .set_moduli(&[0xffffee001u64, 0xffffc4001u64])
            .set_secret_variance(1)
            .set_error_bounds_u32(50, 100)
            .build_arc()
            .expect("Failed to create test parameters")
    }

    #[test]
    fn test_pvw_parameters_serialization() {
        let params = create_test_params();

        // Test serialization
        let serializable = SerializablePvwParameters::from_params(&params);
        let json = serde_json::to_string(&serializable).expect("Failed to serialize parameters");

        // Test deserialization
        let deserialized: SerializablePvwParameters =
            serde_json::from_str(&json).expect("Failed to deserialize parameters");
        let reconstructed = deserialized
            .to_params()
            .expect("Failed to reconstruct parameters");

        // Verify properties
        assert_eq!(params.n, reconstructed.n);
        assert_eq!(params.k, reconstructed.k);
        assert_eq!(params.l, reconstructed.l);
        assert_eq!(params.moduli(), reconstructed.moduli());
        assert_eq!(params.context.degree, reconstructed.context.degree);
        assert_eq!(params.secret_variance, reconstructed.secret_variance);
        assert_eq!(params.error_bound_1, reconstructed.error_bound_1);
        assert_eq!(params.error_bound_2, reconstructed.error_bound_2);
    }

    #[test]
    fn test_pvw_crs_serialization() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create CRS
        let crs = PvwCrs::new(&params, &mut rng).expect("Failed to create CRS");

        // Test serialization
        let serializable = SerializablePvwCrs::from_crs(&crs);
        let json = serde_json::to_string(&serializable).expect("Failed to serialize CRS");

        // Test deserialization
        let deserialized: SerializablePvwCrs =
            serde_json::from_str(&json).expect("Failed to deserialize CRS");
        let reconstructed = deserialized.to_crs().expect("Failed to reconstruct CRS");

        // Verify matrix dimensions
        assert_eq!(crs.matrix.shape(), reconstructed.matrix.shape());
        assert_eq!(crs.params.n, reconstructed.params.n);
        assert_eq!(crs.params.k, reconstructed.params.k);
    }

    #[test]
    fn test_secret_key_serialization() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create secret key
        let secret_key = SecretKey::random(&params, &mut rng).expect("Failed to create secret key");

        // Test serialization
        let serializable = SerializableSecretKey::from_secret_key(&secret_key);
        let json = serde_json::to_string(&serializable).expect("Failed to serialize secret key");

        // Test deserialization
        let deserialized: SerializableSecretKey =
            serde_json::from_str(&json).expect("Failed to deserialize secret key");
        let reconstructed = deserialized
            .to_secret_key()
            .expect("Failed to reconstruct secret key");

        // Verify properties
        assert_eq!(secret_key.coefficients(), reconstructed.coefficients());
        assert_eq!(secret_key.params.n, reconstructed.params.n);
        assert_eq!(secret_key.params.k, reconstructed.params.k);
    }

    #[test]
    fn test_public_key_serialization() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create CRS and public key
        let crs = PvwCrs::new(&params, &mut rng).expect("Failed to create CRS");
        let secret_key = SecretKey::random(&params, &mut rng).expect("Failed to create secret key");
        let public_key =
            PublicKey::generate(&secret_key, &crs, &mut rng).expect("Failed to create public key");

        // Test serialization
        let serializable = SerializablePublicKey::from_public_key(&public_key);
        let json = serde_json::to_string(&serializable).expect("Failed to serialize public key");

        // Test deserialization
        let deserialized: SerializablePublicKey =
            serde_json::from_str(&json).expect("Failed to deserialize public key");
        let reconstructed = deserialized
            .to_public_key()
            .expect("Failed to reconstruct public key");

        // Verify properties
        assert_eq!(
            public_key.key_polynomials.len(),
            reconstructed.key_polynomials.len()
        );
        assert_eq!(public_key.params.n, reconstructed.params.n);
        assert_eq!(public_key.params.k, reconstructed.params.k);
    }

    #[test]
    fn test_global_public_key_serialization() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create CRS and global public key
        let crs = PvwCrs::new(&params, &mut rng).expect("Failed to create CRS");
        let mut global_pk = GlobalPublicKey::new(crs);

        // Add a party key
        let secret_key = SecretKey::random(&params, &mut rng).expect("Failed to create secret key");
        global_pk
            .generate_and_add(0, &secret_key, &mut rng)
            .expect("Failed to add party key");

        // Test serialization
        let serializable = SerializableGlobalPublicKey::from_global_public_key(&global_pk);
        let json =
            serde_json::to_string(&serializable).expect("Failed to serialize global public key");

        // Test deserialization
        let deserialized: SerializableGlobalPublicKey =
            serde_json::from_str(&json).expect("Failed to deserialize global public key");
        let reconstructed = deserialized
            .to_global_public_key()
            .expect("Failed to reconstruct global public key");

        // Verify properties
        assert_eq!(global_pk.matrix.shape(), reconstructed.matrix.shape());
        assert_eq!(global_pk.num_keys, reconstructed.num_keys);
        assert_eq!(global_pk.params.n, reconstructed.params.n);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create full encryption setup
        let crs = PvwCrs::new(&params, &mut rng).expect("Failed to create CRS");
        let mut global_pk = GlobalPublicKey::new(crs);

        // Add all party keys
        for i in 0..params.n {
            let secret_key =
                SecretKey::random(&params, &mut rng).expect("Failed to create secret key");
            global_pk
                .generate_and_add(i, &secret_key, &mut rng)
                .expect("Failed to add party key");
        }

        // Create ciphertext
        let scalars: Vec<u64> = (0..params.n).map(|i| i as u64 + 1).collect();
        let ciphertext = encrypt(&scalars, &global_pk).expect("Failed to encrypt");

        // Test serialization
        let serializable = SerializablePvwCiphertext::from_ciphertext(&ciphertext);
        let json = serde_json::to_string(&serializable).expect("Failed to serialize ciphertext");

        // Test deserialization
        let deserialized: SerializablePvwCiphertext =
            serde_json::from_str(&json).expect("Failed to deserialize ciphertext");
        let reconstructed = deserialized
            .to_ciphertext()
            .expect("Failed to reconstruct ciphertext");

        // Verify properties
        assert_eq!(ciphertext.c1.len(), reconstructed.c1.len());
        assert_eq!(ciphertext.c2.len(), reconstructed.c2.len());
        assert_eq!(ciphertext.params.n, reconstructed.params.n);
        assert_eq!(ciphertext.params.k, reconstructed.params.k);
    }

    #[test]
    fn test_round_trip_consistency() {
        // Test that multiple serialization/deserialization cycles preserve data
        let params = create_test_params();

        // Test with parameters
        let serializable1 = SerializablePvwParameters::from_params(&params);
        let json1 = serde_json::to_string(&serializable1).expect("Failed to serialize (1)");
        let deserialized1: SerializablePvwParameters =
            serde_json::from_str(&json1).expect("Failed to deserialize (1)");
        let reconstructed1 = deserialized1
            .to_params()
            .expect("Failed to reconstruct (1)");

        // Second round trip
        let serializable2 = SerializablePvwParameters::from_params(&reconstructed1);
        let json2 = serde_json::to_string(&serializable2).expect("Failed to serialize (2)");
        let deserialized2: SerializablePvwParameters =
            serde_json::from_str(&json2).expect("Failed to deserialize (2)");
        let reconstructed2 = deserialized2
            .to_params()
            .expect("Failed to reconstruct (2)");

        // Verify consistency
        assert_eq!(params.n, reconstructed2.n);
        assert_eq!(params.k, reconstructed2.k);
        assert_eq!(params.moduli(), reconstructed2.moduli());
        assert_eq!(json1, json2); // JSON should be identical
    }

    #[test]
    fn test_json_serialization_format() {
        let params = create_test_params();
        let serializable = SerializablePvwParameters::from_params(&params);

        // Test JSON
        let json = serde_json::to_string(&serializable).expect("Failed to serialize to JSON");
        let from_json: SerializablePvwParameters =
            serde_json::from_str(&json).expect("Failed to deserialize from JSON");

        // Verify result
        let reconstructed_json = from_json
            .to_params()
            .expect("Failed to reconstruct from JSON");

        assert_eq!(params.n, reconstructed_json.n);
        assert_eq!(params.k, reconstructed_json.k);
        assert_eq!(params.moduli(), reconstructed_json.moduli());
    }
}
