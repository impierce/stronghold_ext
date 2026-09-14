// The multi-key snapshot needs both EC algorithms; the RS256 section below is additive.
#[cfg(all(feature = "es256", feature = "es256k"))]
mod snapshot_test {
    use iota_stronghold::{KeyProvider, Location, SnapshotPath, Stronghold};
    #[cfg(feature = "rs256")]
    use rsa::traits::PublicKeyParts;
    use stronghold_ext::{
        execute_procedure_chained_ext, execute_procedure_ext,
        procs::{es256::Es256Procs, es256k::Es256kProcs, *},
        Algorithm, Es256, Es256k, VerifyingKey,
    };
    #[cfg(feature = "rs256")]
    use stronghold_ext::{procs::rs256::Rs256Procs, AlgoSignature, Rs256, RS256_MINIMUM_BITS};

    static STRONGHOLD_CLIENT_PATH: &[u8] = b"iota_identity_client";

    #[test]
    fn snapshot_generation_test() {
        let stronghold = Stronghold::default();

        let client_path = "./snapshots/multi-key-stronghold.bin".to_owned();

        let snapshot_path = SnapshotPath::from_path(client_path.clone());
        let key_provider = KeyProvider::with_passphrase_hashed_blake2b(b"sup3rSecr3t".to_vec())
            .expect("failed to load key");

        let client = stronghold.create_client(STRONGHOLD_CLIENT_PATH).unwrap();

        let es256k_loc = Location::generic(b"iota_identity_vault".to_vec(), b"key-1".to_vec());

        let es256_loc: Location =
            Location::generic(b"iota_identity_vault".to_vec(), b"key-2".to_vec());

        let gen_key = Es256kProcs::GenerateKey(es256k::GenerateKey {
            output: es256k_loc.clone(),
        });

        // create es256k secret key and put it into the stronghold vault.2
        let _ = execute_procedure_ext(&client, gen_key).unwrap();

        let gen_key = Es256Procs::GenerateKey(es256::GenerateKey {
            output: es256_loc.clone(),
        });

        // create es256 secret key and put it into the stronghold vault.
        let _ = execute_procedure_ext(&client, gen_key).unwrap();

        // RS256 private keys are ~1.2 KB of variable-length PKCS#1 DER rather than a fixed
        // 32-byte scalar, so they exercise the vault's storage differently to the EC keys.
        #[cfg(feature = "rs256")]
        let rs256_loc: Location =
            Location::generic(b"iota_identity_vault".to_vec(), b"key-3".to_vec());

        #[cfg(feature = "rs256")]
        {
            let gen_key = Rs256Procs::GenerateKey(rs256::GenerateKey {
                output: rs256_loc.clone(),
            });
            let _ = execute_procedure_ext(&client, gen_key).unwrap();
        }

        // Set the work factor to 10 to speed up the commit.
        engine::snapshot::try_set_encrypt_work_factor(10).unwrap();

        stronghold
            .write_client(STRONGHOLD_CLIENT_PATH)
            .expect("store client state into snapshot state failed");

        stronghold
            .commit_with_keyprovider(&snapshot_path, &key_provider)
            .expect("stronghold could not commit");

        // clear the stronghold client state.
        stronghold.clear().unwrap();

        // reload the client.
        let client = stronghold
            .load_client_from_snapshot(STRONGHOLD_CLIENT_PATH, &key_provider, &snapshot_path)
            .expect("read client state from snapshot state failed");

        let pub_key = Es256kProcs::PublicKey(es256k::PublicKey {
            private_key: es256k_loc.clone(),
        });

        let sign = Es256kProcs::Sign(es256k::Sign {
            msg: b"test".to_vec(),
            private_key: es256k_loc.clone(),
        });

        // Chain together the public key and sign procedures.
        let res = execute_procedure_chained_ext(&client, vec![pub_key, sign]).unwrap();

        let pk: Vec<u8> = res[0].clone().into();
        // Public key is sec1 encoded which means it should be 33 bytes long.  leading byte should be either 2, 3 or 4 because its a compressed point.
        assert_eq!(pk.len(), 33);

        // check to see that the public key is valid.
        let vk = <Es256k as Algorithm>::VerifyingKey::from_slice(&pk);
        assert!(vk.is_ok());

        // get the signature bytes for verification.
        let sig = res[1].clone();

        let verify = Es256kProcs::Verify(es256k::Verify {
            msg: b"test".to_vec(),
            signature: sig.into(),
            private_key: es256k_loc.clone(),
        });

        let res: [u8; 1] = execute_procedure_ext(&client, verify)
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(res[0], 1);

        let pub_key = Es256Procs::PublicKey(es256::PublicKey {
            private_key: es256_loc.clone(),
        });

        let sign = Es256Procs::Sign(es256::Sign {
            msg: b"test".to_vec(),
            private_key: es256_loc.clone(),
        });

        // Chain together the public key and sign procedures.
        let res = execute_procedure_chained_ext(&client, vec![pub_key, sign]).unwrap();

        let pk: Vec<u8> = res[0].clone().into();
        // Public key is sec1 encoded which means it should be 33 bytes long.  leading byte should be either 2, 3 or 4 because its a compressed point.
        assert_eq!(pk.len(), 33);

        // check to see that the public key is valid.
        let vk = <Es256 as Algorithm>::VerifyingKey::from_slice(&pk);
        assert!(vk.is_ok());

        // get the signature bytes for verification.
        let sig = res[1].clone();

        let verify = Es256Procs::Verify(es256::Verify {
            msg: b"test".to_vec(),
            signature: sig.into(),
            private_key: es256_loc.clone(),
        });

        let res: [u8; 1] = execute_procedure_ext(&client, verify)
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(res[0], 1);

        #[cfg(feature = "rs256")]
        {
            let pub_key = Rs256Procs::PublicKey(rs256::PublicKey {
                private_key: rs256_loc.clone(),
            });

            let sign = Rs256Procs::Sign(rs256::Sign {
                msg: b"test".to_vec(),
                private_key: rs256_loc.clone(),
            });

            let res = execute_procedure_chained_ext(&client, vec![pub_key, sign]).unwrap();

            let pk: Vec<u8> = res[0].clone().into();
            let sig: Vec<u8> = res[1].clone().into();

            // The key survived the snapshot round trip intact: it still decodes, is still the
            // advertised size, and still verifies what it signed after reloading.
            let vk = <Rs256 as Algorithm>::VerifyingKey::from_slice(&pk)
                .expect("rs256 public key did not survive the snapshot round trip");
            assert_eq!(vk.n().bits(), RS256_MINIMUM_BITS);
            assert_eq!(sig.len(), vk.size());

            let parsed = <Rs256 as Algorithm>::Signature::try_from_slice(&sig).unwrap();
            assert!(Rs256.verify_signature(&parsed, &vk, b"test"));

            let verify = Rs256Procs::Verify(rs256::Verify {
                msg: b"test".to_vec(),
                signature: sig,
                private_key: rs256_loc.clone(),
            });

            let res: [u8; 1] = execute_procedure_ext(&client, verify)
                .unwrap()
                .try_into()
                .unwrap();

            assert_eq!(res[0], 1);
        }
    }
}
