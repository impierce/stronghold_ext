use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use std::{borrow::Cow, num::NonZeroUsize};

use crate::{AlgoSignature, Algorithm, SigningKey as SKey, VerifyingKey as VKey};

const MINIMUM_BITS: usize = 2048;

impl AlgoSignature for Signature {
    const LENGTH: Option<NonZeroUsize> = None;

    fn try_from_slice(slice: &[u8]) -> crate::Result<Self> {
        Ok(Signature::try_from(slice)?)
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

/// `RS256` signing algorithm: RSASSA-PKCS1-v1_5 with SHA-256.
#[derive(Debug, Default)]
pub struct Rs256;

impl Algorithm for Rs256 {
    type SigningKey = RsaPrivateKey;
    type VerifyingKey = RsaPublicKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("RS256")
    }

    fn curve(&self) -> Cow<'static, str> {
        Cow::Borrowed("")
    }

    fn generate_signing_key(&self) -> Self::SigningKey {
        RsaPrivateKey::new(&mut rand::thread_rng(), MINIMUM_BITS)
            .expect("failed to generate an RSA-2048 key")
    }

    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        SigningKey::<Sha256>::new(signing_key.clone()).sign(message)
    }

    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        VerifyingKey::<Sha256>::new(verifying_key.clone())
            .verify(message, signature)
            .is_ok()
    }
}

impl SKey<Rs256> for RsaPrivateKey {
    fn from_slice(raw: &[u8]) -> crate::Result<Self> {
        let key = Self::from_pkcs1_der(raw)?;
        if key.size() * 8 < MINIMUM_BITS {
            return Err(crate::Error::RsaKeyTooSmall);
        }
        Ok(key)
    }

    fn to_verifying_key(&self) -> RsaPublicKey {
        self.to_public_key()
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(
            self.to_pkcs1_der()
                .expect("failed to encode RSA private key")
                .as_bytes()
                .to_vec(),
        )
    }
}

impl VKey<Rs256> for RsaPublicKey {
    fn from_slice(raw: &[u8]) -> crate::Result<Self> {
        let key = Self::from_pkcs1_der(raw)?;
        if key.size() * 8 < MINIMUM_BITS {
            return Err(crate::Error::RsaKeyTooSmall);
        }
        Ok(key)
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(
            self.to_pkcs1_der()
                .expect("failed to encode RSA public key")
                .as_bytes()
                .to_vec(),
        )
    }
}
