#[cfg(feature = "crypto")]
mod rs256_test {
    use iota_stronghold::{Location, Stronghold};
    use rsa::{pkcs1::EncodeRsaPrivateKey, BigUint, RsaPrivateKey, RsaPublicKey};
    use stronghold_ext::{
        execute_procedure_chained_ext, execute_procedure_ext, procs::rs256, AlgoSignature,
        Algorithm, Rs256, SigningKey, VerifyingKey,
    };

    struct CavpVector {
        n: &'static str,
        e: &'static str,
        msg: &'static str,
        signature: &'static str,
        expected: bool,
    }

    #[test]
    fn test_rs256_round_trip_and_tampering() {
        let algorithm = Rs256;
        let signing_key = algorithm.generate_signing_key();
        let encoded_private_key = signing_key.as_bytes();
        let imported_signing_key =
            <Rs256 as Algorithm>::SigningKey::from_slice(&encoded_private_key).unwrap();
        let verifying_key = imported_signing_key.to_verifying_key();
        let encoded_public_key = verifying_key.as_bytes();
        let imported_verifying_key =
            <Rs256 as Algorithm>::VerifyingKey::from_slice(&encoded_public_key).unwrap();

        let message = b"RS256 test message";
        let signature = algorithm.sign(&imported_signing_key, message);

        assert_eq!(signature.as_bytes().len(), 256);
        assert!(algorithm.verify_signature(&signature, &imported_verifying_key, message));
        assert!(!algorithm.verify_signature(
            &signature,
            &imported_verifying_key,
            b"tampered message"
        ));
    }

    #[test]
    fn rejects_keys_smaller_than_2048_bits() {
        let small_key = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let encoded = small_key.to_pkcs1_der().unwrap();

        assert!(<Rs256 as Algorithm>::SigningKey::from_slice(encoded.as_bytes()).is_err());
    }

    #[test]
    fn verifies_nist_cavp_vectors() {
        let vectors = include!("fixtures/rsa_cavp.rs");

        for vector in vectors {
            let public_key = RsaPublicKey::new(
                BigUint::from_bytes_be(&hex::decode(vector.n).unwrap()),
                BigUint::from_bytes_be(&hex::decode(vector.e).unwrap()),
            )
            .unwrap();
            let signature = <Rs256 as Algorithm>::Signature::try_from_slice(
                &hex::decode(vector.signature).unwrap(),
            )
            .unwrap();
            let message = hex::decode(vector.msg).unwrap();

            assert_eq!(
                Rs256.verify_signature(&signature, &public_key, &message),
                vector.expected
            );
        }
    }

    #[test]
    fn test_rs256_procedures() {
        let stronghold = Stronghold::default();
        let client = stronghold.create_client(b"test_rs256_procedures").unwrap();
        let private_key = Location::generic(b"rs256".to_vec(), b"private".to_vec());

        execute_procedure_ext(
            &client,
            rs256::Rs256Procs::GenerateKey(rs256::GenerateKey {
                output: private_key.clone(),
            }),
        )
        .unwrap();

        let results = execute_procedure_chained_ext(
            &client,
            vec![
                rs256::Rs256Procs::PublicKey(rs256::PublicKey {
                    private_key: private_key.clone(),
                }),
                rs256::Rs256Procs::Sign(rs256::Sign {
                    msg: b"procedure message".to_vec(),
                    private_key: private_key.clone(),
                }),
            ],
        )
        .unwrap();

        let result: Vec<u8> = execute_procedure_ext(
            &client,
            rs256::Rs256Procs::Verify(rs256::Verify {
                msg: b"procedure message".to_vec(),
                signature: results[1].clone().into(),
                private_key,
            }),
        )
        .unwrap()
        .into();

        let public_key: Vec<u8> = results[0].clone().into();
        assert!(public_key.len() >= 256);
        assert_eq!(result, vec![1]);
    }
}
