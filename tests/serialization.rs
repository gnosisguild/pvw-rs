//! Tests for PVW direct serialization using bincode

#[cfg(all(test, feature = "serde"))]
mod tests {
    use fhe_traits::Serialize;
    use pvw::prelude::*;
    use rand::thread_rng;

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

        // Test binary serialization with bincode
        let bytes = bincode::serialize(&*params).expect("Failed to serialize");
        let reconstructed: PvwParameters =
            bincode::deserialize(&bytes).expect("Failed to deserialize");

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
    fn test_secret_key_serialization() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create secret key
        let secret_key = SecretKey::random(&params, &mut rng).expect("Failed to create secret key");

        // Test binary serialization with bincode
        let bytes = bincode::serialize(&secret_key).expect("Failed to serialize");
        let reconstructed: SecretKey = bincode::deserialize(&bytes).expect("Failed to deserialize");

        // Verify exact coefficient equality
        assert_eq!(secret_key.coefficients(), reconstructed.coefficients());

        // Verify all parameter fields are identical
        assert_eq!(secret_key.params.n, reconstructed.params.n);
        assert_eq!(secret_key.params.k, reconstructed.params.k);
        assert_eq!(secret_key.params.l, reconstructed.params.l);
        assert_eq!(secret_key.params.moduli(), reconstructed.params.moduli());
        assert_eq!(
            secret_key.params.context.degree,
            reconstructed.params.context.degree
        );
        assert_eq!(
            secret_key.params.secret_variance,
            reconstructed.params.secret_variance
        );
        assert_eq!(
            secret_key.params.error_bound_1,
            reconstructed.params.error_bound_1
        );
        assert_eq!(
            secret_key.params.error_bound_2,
            reconstructed.params.error_bound_2
        );
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

        // Test binary serialization with bincode
        let bytes = bincode::serialize(&public_key).expect("Failed to serialize");
        let reconstructed: PublicKey = bincode::deserialize(&bytes).expect("Failed to deserialize");

        // Verify exact polynomial equality
        assert_eq!(
            public_key.key_polynomials.len(),
            reconstructed.key_polynomials.len()
        );
        for (original, reconstructed_poly) in public_key
            .key_polynomials
            .iter()
            .zip(reconstructed.key_polynomials.iter())
        {
            // Compare polynomial bytes to ensure exact equality
            assert_eq!(original.to_bytes(), reconstructed_poly.to_bytes());
        }

        // Verify all parameter fields are identical
        assert_eq!(public_key.params.n, reconstructed.params.n);
        assert_eq!(public_key.params.k, reconstructed.params.k);
        assert_eq!(public_key.params.l, reconstructed.params.l);
        assert_eq!(public_key.params.moduli(), reconstructed.params.moduli());
        assert_eq!(
            public_key.params.context.degree,
            reconstructed.params.context.degree
        );
        assert_eq!(
            public_key.params.secret_variance,
            reconstructed.params.secret_variance
        );
        assert_eq!(
            public_key.params.error_bound_1,
            reconstructed.params.error_bound_1
        );
        assert_eq!(
            public_key.params.error_bound_2,
            reconstructed.params.error_bound_2
        );
    }

    #[test]
    fn test_pvw_crs_serialization() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create CRS
        let crs = PvwCrs::new(&params, &mut rng).expect("Failed to create CRS");

        // Test binary serialization with bincode
        let bytes = bincode::serialize(&crs).expect("Failed to serialize");
        let reconstructed: PvwCrs = bincode::deserialize(&bytes).expect("Failed to deserialize");

        // Verify exact matrix content equality
        assert_eq!(crs.matrix.shape(), reconstructed.matrix.shape());
        for (original, reconstructed_poly) in crs.matrix.iter().zip(reconstructed.matrix.iter()) {
            // Compare polynomial bytes to ensure exact equality
            assert_eq!(original.to_bytes(), reconstructed_poly.to_bytes());
        }

        // Verify all parameter fields are identical
        assert_eq!(crs.params.n, reconstructed.params.n);
        assert_eq!(crs.params.k, reconstructed.params.k);
        assert_eq!(crs.params.l, reconstructed.params.l);
        assert_eq!(crs.params.moduli(), reconstructed.params.moduli());
        assert_eq!(
            crs.params.context.degree,
            reconstructed.params.context.degree
        );
        assert_eq!(
            crs.params.secret_variance,
            reconstructed.params.secret_variance
        );
        assert_eq!(crs.params.error_bound_1, reconstructed.params.error_bound_1);
        assert_eq!(crs.params.error_bound_2, reconstructed.params.error_bound_2);
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

        // Test binary serialization with bincode
        let bytes = bincode::serialize(&global_pk).expect("Failed to serialize");
        let reconstructed: GlobalPublicKey =
            bincode::deserialize(&bytes).expect("Failed to deserialize");

        // Verify exact matrix content equality
        assert_eq!(global_pk.matrix.shape(), reconstructed.matrix.shape());
        for (original, reconstructed_poly) in
            global_pk.matrix.iter().zip(reconstructed.matrix.iter())
        {
            // Compare polynomial bytes to ensure exact equality
            assert_eq!(original.to_bytes(), reconstructed_poly.to_bytes());
        }

        // Verify CRS content equality
        for (original, reconstructed_poly) in global_pk
            .crs
            .matrix
            .iter()
            .zip(reconstructed.crs.matrix.iter())
        {
            assert_eq!(original.to_bytes(), reconstructed_poly.to_bytes());
        }

        // Verify all other fields
        assert_eq!(global_pk.num_keys, reconstructed.num_keys);

        // Verify all parameter fields are identical
        assert_eq!(global_pk.params.n, reconstructed.params.n);
        assert_eq!(global_pk.params.k, reconstructed.params.k);
        assert_eq!(global_pk.params.l, reconstructed.params.l);
        assert_eq!(global_pk.params.moduli(), reconstructed.params.moduli());
        assert_eq!(
            global_pk.params.context.degree,
            reconstructed.params.context.degree
        );
        assert_eq!(
            global_pk.params.secret_variance,
            reconstructed.params.secret_variance
        );
        assert_eq!(
            global_pk.params.error_bound_1,
            reconstructed.params.error_bound_1
        );
        assert_eq!(
            global_pk.params.error_bound_2,
            reconstructed.params.error_bound_2
        );
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

        // Test binary serialization with bincode
        let bytes = bincode::serialize(&ciphertext).expect("Failed to serialize");
        let reconstructed: PvwCiphertext =
            bincode::deserialize(&bytes).expect("Failed to deserialize");

        // Verify exact ciphertext content equality
        assert_eq!(ciphertext.c1.len(), reconstructed.c1.len());
        assert_eq!(ciphertext.c2.len(), reconstructed.c2.len());

        // Compare all c1 polynomials
        for (original, reconstructed_poly) in ciphertext.c1.iter().zip(reconstructed.c1.iter()) {
            assert_eq!(original.to_bytes(), reconstructed_poly.to_bytes());
        }

        // Compare all c2 polynomials
        for (original, reconstructed_poly) in ciphertext.c2.iter().zip(reconstructed.c2.iter()) {
            assert_eq!(original.to_bytes(), reconstructed_poly.to_bytes());
        }

        // Verify all parameter fields are identical
        assert_eq!(ciphertext.params.n, reconstructed.params.n);
        assert_eq!(ciphertext.params.k, reconstructed.params.k);
        assert_eq!(ciphertext.params.l, reconstructed.params.l);
        assert_eq!(ciphertext.params.moduli(), reconstructed.params.moduli());
        assert_eq!(
            ciphertext.params.context.degree,
            reconstructed.params.context.degree
        );
        assert_eq!(
            ciphertext.params.secret_variance,
            reconstructed.params.secret_variance
        );
        assert_eq!(
            ciphertext.params.error_bound_1,
            reconstructed.params.error_bound_1
        );
        assert_eq!(
            ciphertext.params.error_bound_2,
            reconstructed.params.error_bound_2
        );
    }

    #[test]
    fn test_round_trip_consistency() {
        // Test that multiple serialization/deserialization cycles preserve data
        let params = create_test_params();

        // Test with parameters
        let bytes1 = bincode::serialize(&*params).expect("Failed to serialize (1)");
        let reconstructed1: PvwParameters =
            bincode::deserialize(&bytes1).expect("Failed to deserialize (1)");

        // Second round trip
        let bytes2 = bincode::serialize(&reconstructed1).expect("Failed to serialize (2)");
        let reconstructed2: PvwParameters =
            bincode::deserialize(&bytes2).expect("Failed to deserialize (2)");

        // Verify consistency
        assert_eq!(params.n, reconstructed2.n);
        assert_eq!(params.k, reconstructed2.k);
        assert_eq!(params.moduli(), reconstructed2.moduli());
        assert_eq!(bytes1, bytes2); // Binary should be identical
    }

    #[test]
    fn test_bincode_direct_usage() {
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create a ciphertext
        let crs = PvwCrs::new(&params, &mut rng).expect("Failed to create CRS");
        let mut global_pk = GlobalPublicKey::new(crs);

        for i in 0..params.n {
            let secret_key =
                SecretKey::random(&params, &mut rng).expect("Failed to create secret key");
            global_pk
                .generate_and_add(i, &secret_key, &mut rng)
                .expect("Failed to add party key");
        }

        let scalars: Vec<u64> = vec![42; params.n];
        let ciphertext = encrypt(&scalars, &global_pk).expect("Failed to encrypt");

        // This is exactly what the user wants - direct bincode usage
        let bytes = bincode::serialize(&ciphertext).expect("Serialization failed");
        let reconstructed: PvwCiphertext =
            bincode::deserialize(&bytes).expect("Deserialization failed");

        // Verify the reconstructed ciphertext is EXACTLY the same
        assert_eq!(ciphertext.len(), reconstructed.len());
        assert!(!reconstructed.is_empty());

        // Verify exact polynomial content equality
        for (original, reconstructed_poly) in ciphertext.c1.iter().zip(reconstructed.c1.iter()) {
            assert_eq!(original.to_bytes(), reconstructed_poly.to_bytes());
        }
        for (original, reconstructed_poly) in ciphertext.c2.iter().zip(reconstructed.c2.iter()) {
            assert_eq!(original.to_bytes(), reconstructed_poly.to_bytes());
        }

        // Verify it validates and works correctly
        reconstructed
            .validate()
            .expect("Reconstructed ciphertext should be valid");
    }

    #[test]
    fn test_serialization_deterministic() {
        // Test that the same data always produces the same bytes
        let params = create_test_params();
        let mut rng = thread_rng();

        // Create a secret key
        let secret_key = SecretKey::random(&params, &mut rng).expect("Failed to create secret key");

        // Serialize it multiple times
        let bytes1 = bincode::serialize(&secret_key).expect("Failed to serialize (1)");
        let bytes2 = bincode::serialize(&secret_key).expect("Failed to serialize (2)");
        let bytes3 = bincode::serialize(&secret_key).expect("Failed to serialize (3)");

        // All serializations should produce identical bytes
        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);

        // Deserialize and verify it's still the same
        let reconstructed: SecretKey =
            bincode::deserialize(&bytes1).expect("Failed to deserialize");
        assert_eq!(secret_key.coefficients(), reconstructed.coefficients());
    }
}
