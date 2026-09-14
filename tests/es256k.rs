#[cfg(feature = "es256k")]
mod es256k_test {

    use ecdsa::signature::DigestSigner;

    use sha2::{Digest, Sha256};
    use stronghold_ext::{Algorithm, Es256k, VerifyingKey};

    #[test]
    fn test_es256k() {
        let msg = hex::decode("4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a")
            .unwrap();
        let d = hex::decode("ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f")
            .unwrap();

        let x = hex::decode("779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd")
            .unwrap();
        let y = hex::decode("e94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f")
            .unwrap();
        let p = hex::decode("04779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f").unwrap();
        let R = hex::decode("241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795")
            .unwrap();
        let S = hex::decode("139c98ddeba50a63bbc95014a47ba1779db5ac846a85eee69bbd95b58bc96044")
            .unwrap();

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(R.as_slice());
        s.copy_from_slice(S.as_slice());

        // build public key from p
        let vk = <Es256k as Algorithm>::VerifyingKey::from_slice(&p).unwrap();
        // setup public key from x and y bytes.
        let mut key_bytes = [0u8; 2 * 32 + 1];
        key_bytes[0] = 4; // uncompressed key marker
        key_bytes[1..=32].copy_from_slice(&x);
        key_bytes[33..].copy_from_slice(&y);

        let vk0 = <Es256k as Algorithm>::VerifyingKey::from_slice(&key_bytes).unwrap();

        // build uncompressed public key from x and y encoded points.
        let q_encoded = ecdsa::EncodedPoint::<k256::Secp256k1>::from_affine_coordinates(
            x.as_slice().into(),
            y.as_slice().into(),
            false,
        );

        let vk1 = ecdsa::VerifyingKey::<k256::Secp256k1>::from_encoded_point(&q_encoded).unwrap();
        // verify all of the public keys are the same.
        assert_eq!(vk, vk0);
        assert_eq!(vk, vk1);

        let z = k256::FieldBytes::from_slice(&msg);

        let d = k256::FieldBytes::from_slice(&d);
        // create private keys from d.
        let kpair = ecdsa::SigningKey::<k256::Secp256k1>::from_bytes(&d).unwrap();
        let kpair_0 = <Es256k as Algorithm>::SigningKey::from_slice(&d).unwrap();

        assert_eq!(kpair_0, kpair);

        // sign the message with the private key.
        let mut digest = Sha256::default();
        digest.update(&z);
        let sig0 = kpair.sign_digest(digest);

        let sig = Es256k::default().sign(&kpair_0, &z);

        assert_eq!(sig, sig0);
    }
}
