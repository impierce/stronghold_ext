#[cfg(feature = "es256")]
mod es256_test {
    use ecdsa::signature::hazmat::PrehashVerifier;

    use ecdsa::signature::DigestSigner;
    use ecdsa::signature::DigestVerifier;
    use sha2::{Digest, Sha256};
    use stronghold_ext::{Algorithm, Es256, VerifyingKey};

    struct TestVector {
        Msg: &'static str,
        d: &'static str,
        Qx: &'static str,
        Qy: &'static str,
        k: &'static str,
        R: &'static str,
        S: &'static str,
    }

    #[test]
    fn test_es256_pk() {
        let tvs = include!("fixtures/p256_tvs.rs");

        for tv in tvs {
            let d = hex::decode(tv.d).unwrap();
            let qx = hex::decode(tv.Qx).unwrap();
            let qy = hex::decode(tv.Qy).unwrap();
            let msg = hex::decode(tv.Msg).unwrap();

            let R = hex::decode(tv.R).unwrap();
            let S = hex::decode(tv.S).unwrap();

            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(R.as_slice());
            s.copy_from_slice(S.as_slice());

            // build uncompressed public key from x and y bytes.
            let mut key_bytes = [0u8; 2 * 32 + 1];
            key_bytes[0] = 4; // uncompressed key marker
            key_bytes[1..=32].copy_from_slice(&qx);
            key_bytes[33..].copy_from_slice(&qy);

            let vk = <Es256 as Algorithm>::VerifyingKey::from_slice(&key_bytes).unwrap();

            // build uncompressed public key from x and y encoded points.
            let q_encoded = ecdsa::EncodedPoint::<p256::NistP256>::from_affine_coordinates(
                qx.as_slice().into(),
                qy.as_slice().into(),
                false,
            );
            let q = ecdsa::VerifyingKey::<p256::NistP256>::from_encoded_point(&q_encoded).unwrap();

            assert_eq!(q, vk);

            // create signature from r and s scalars.
            let sig = ecdsa::Signature::<p256::NistP256>::from_scalars(r, s).unwrap();

            let res = q.verify_prehash(&msg, &sig);

            assert!(res.is_ok());

            let z = p256::FieldBytes::from_slice(&msg);
            let d = p256::FieldBytes::from_slice(&d);

            let kpair = ecdsa::SigningKey::<p256::NistP256>::from_bytes(d).unwrap();
            let kpair_0 = <Es256 as Algorithm>::SigningKey::from_slice(d).unwrap();

            assert_eq!(kpair_0, kpair);

            let mut digest = Sha256::default();
            digest.update(&z);
            let sig0 = kpair.sign_digest(digest);

            let sig = Es256.sign(&kpair_0, &z);

            assert_eq!(sig, sig0);

            let res = Es256.verify_signature(&sig, &vk, &z);

            let mut digest = Sha256::default();
            digest.update(&z);
            let res0 = q.verify_digest(digest, &sig);

            assert!(res);
            assert!(res0.is_ok());
        }
    }
}
