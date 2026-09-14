#[cfg(feature = "rs256")]
mod rs256_test {
    use iota_stronghold::{Location, Stronghold};
    use rsa::{
        pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
        traits::PublicKeyParts,
        BigUint, RsaPrivateKey, RsaPublicKey,
    };
    use sha2::{Digest, Sha256};
    use stronghold_ext::{
        execute_procedure_chained_ext, execute_procedure_ext, procs::rs256, AlgoSignature,
        Algorithm, Rs256, SigningKey, VerifyingKey, RS256_MINIMUM_BITS,
    };

    struct CavpVector {
        n: &'static str,
        e: &'static str,
        msg: &'static str,
        signature: &'static str,
        expected: bool,
    }

    /// DigestInfo prefix for SHA-256, from RFC 8017 §9.2 note 1:
    /// `SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING (32) }`.
    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

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

    /// RSASSA-PKCS1-v1_5 is deterministic. Blinding the private-key exponentiation guards the
    /// signer against the Marvin timing attack but must not perturb the emitted bytes, or every
    /// signature this crate has already produced would stop reproducing.
    #[test]
    fn signing_is_deterministic() {
        let signing_key = Rs256.generate_signing_key();
        let message = b"RS256 determinism check";

        let first = Rs256.sign(&signing_key, message);
        let second = Rs256.sign(&signing_key, message);

        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    /// Cross-checks the signing path against a hand-assembled RFC 8017 EMSA-PKCS1-v1_5
    /// encoding. Recovering `EM = S^e mod n` and comparing it against padding built here --
    /// rather than by the `rsa` crate -- pins the `0x00 0x01 FF..FF 0x00` framing, the padding
    /// length, and the SHA-256 DigestInfo prefix. A wrong prefix would still round-trip through
    /// this crate's own verifier, so a self-consistency test alone would not catch it.
    #[test]
    fn signature_matches_rfc8017_emsa_pkcs1_v1_5_encoding() {
        let signing_key = Rs256.generate_signing_key();
        let verifying_key = signing_key.to_verifying_key();
        let message = b"RS256 encoding cross-check";

        let signature = Rs256.sign(&signing_key, message);
        let k = verifying_key.size();

        // EM = 0x00 || 0x01 || PS || 0x00 || T, where |PS| = k - |T| - 3 and PS is all 0xff.
        let digest = Sha256::digest(message);
        let t_len = SHA256_DIGEST_INFO_PREFIX.len() + digest.len();
        let mut expected_em = vec![0x00, 0x01];
        expected_em.resize(k - t_len - 1, 0xff);
        expected_em.push(0x00);
        expected_em.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
        expected_em.extend_from_slice(&digest);
        assert_eq!(expected_em.len(), k);

        // Recover the encoded message with the public key.
        let s = BigUint::from_bytes_be(&signature.as_bytes());
        let recovered = s.modpow(verifying_key.e(), verifying_key.n());
        let mut recovered_em = recovered.to_bytes_be();
        // The bignum representation drops the leading zero byte that EM always starts with.
        while recovered_em.len() < k {
            recovered_em.insert(0, 0x00);
        }

        assert_eq!(recovered_em, expected_em);
    }

    /// The minimum is a bit count, not a byte count. A 2047-bit modulus still occupies 256
    /// bytes, so a guard written against the byte length would let it through.
    #[test]
    fn rejects_keys_smaller_than_2048_bits() {
        for bits in [1024usize, 2047] {
            let small_key = RsaPrivateKey::new(&mut rand::thread_rng(), bits).unwrap();
            assert_eq!(small_key.n().bits(), bits);

            let private_der = small_key.to_pkcs1_der().unwrap();
            assert!(
                <Rs256 as Algorithm>::SigningKey::from_slice(private_der.as_bytes()).is_err(),
                "{bits}-bit private key was accepted"
            );

            let public_der = small_key.to_public_key().to_pkcs1_der().unwrap();
            assert!(
                <Rs256 as Algorithm>::VerifyingKey::from_slice(public_der.as_bytes()).is_err(),
                "{bits}-bit public key was accepted"
            );
        }
    }

    #[test]
    fn accepts_keys_at_the_minimum() {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), RS256_MINIMUM_BITS).unwrap();
        let der = key.to_pkcs1_der().unwrap();

        assert!(<Rs256 as Algorithm>::SigningKey::from_slice(der.as_bytes()).is_ok());
    }

    #[test]
    fn verifies_nist_cavp_vectors() {
        let vectors = include!("fixtures/rsa_cavp.rs");

        for (index, vector) in vectors.into_iter().enumerate() {
            let public_key = RsaPublicKey::new(
                BigUint::from_bytes_be(&hex::decode(vector.n).unwrap()),
                BigUint::from_bytes_be(&hex::decode(vector.e).unwrap()),
            )
            .unwrap();
            assert_eq!(public_key.n().bits(), RS256_MINIMUM_BITS);

            // Take the vectors through the guarded import path, not just `RsaPublicKey::new`,
            // so the 2048-bit minimum is exercised against real keys rather than only rejecting.
            let der = public_key.to_pkcs1_der().unwrap();
            let imported = <Rs256 as Algorithm>::VerifyingKey::from_slice(der.as_bytes()).unwrap();

            let signature = <Rs256 as Algorithm>::Signature::try_from_slice(
                &hex::decode(vector.signature).unwrap(),
            )
            .unwrap();
            let message = hex::decode(vector.msg).unwrap();

            assert_eq!(
                Rs256.verify_signature(&signature, &imported, &message),
                vector.expected,
                "CAVP vector {index} did not match its expected result"
            );
        }
    }

    #[test]
    fn test_rs256_procedures() {
        let stronghold = Stronghold::default();
        let client = stronghold.create_client(b"test_rs256_procedures").unwrap();
        let private_key = Location::generic(b"rs256".to_vec(), b"private".to_vec());
        let message = b"procedure message";

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
                    msg: message.to_vec(),
                    private_key: private_key.clone(),
                }),
            ],
        )
        .unwrap();

        let public_key: Vec<u8> = results[0].clone().into();
        let signature: Vec<u8> = results[1].clone().into();

        // The returned public key must round-trip through the guarded import path, be the
        // advertised size, and actually verify the signature the vault just produced.
        let imported = <Rs256 as Algorithm>::VerifyingKey::from_slice(&public_key)
            .expect("PublicKey procedure returned bytes that do not decode");
        assert_eq!(imported.n().bits(), RS256_MINIMUM_BITS);
        assert_eq!(signature.len(), imported.size());

        let parsed = <Rs256 as Algorithm>::Signature::try_from_slice(&signature).unwrap();
        assert!(Rs256.verify_signature(&parsed, &imported, message));

        let result: Vec<u8> = execute_procedure_ext(
            &client,
            rs256::Rs256Procs::Verify(rs256::Verify {
                msg: message.to_vec(),
                signature: signature.clone(),
                private_key: private_key.clone(),
            }),
        )
        .unwrap()
        .into();
        assert_eq!(result, vec![1]);

        // And a tampered message must be rejected through the same procedure.
        let result: Vec<u8> = execute_procedure_ext(
            &client,
            rs256::Rs256Procs::Verify(rs256::Verify {
                msg: b"tampered message".to_vec(),
                signature,
                private_key,
            }),
        )
        .unwrap()
        .into();
        assert_eq!(result, vec![0]);
    }
}
