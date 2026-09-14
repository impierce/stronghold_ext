use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use std::{borrow::Cow, num::NonZeroUsize};

use crate::{AlgoSignature, Algorithm, SigningKey as SKey, VerifyingKey as VKey};

/// Smallest RSA modulus this crate will generate, import, or verify against.
///
/// RFC 7518 § 3.3 requires a key of 2048 bits or larger for RSASSA-PKCS1-v1_5.
pub const RS256_MINIMUM_BITS: usize = 2048;

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
        RsaPrivateKey::new(&mut rand::thread_rng(), RS256_MINIMUM_BITS)
            .expect("failed to generate an RSA-2048 key")
    }

    /// Signs a message with a `SigningKey` (private key) and returns a `Signature`.
    ///
    /// Uses [`RandomizedSigner`] rather than [`Signer`](rsa::signature::Signer) so that the
    /// private-key exponentiation is blinded. The plain `Signer` impl passes no RNG, which
    /// leaves the operation open to the Marvin timing attack (RUSTSEC-2023-0071). Blinding is
    /// internal to the modular exponentiation, so the emitted signature bytes are unchanged:
    /// RSASSA-PKCS1-v1_5 remains deterministic for a given key and message.
    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        SigningKey::<Sha256>::new(signing_key.clone())
            .sign_with_rng(&mut rand::thread_rng(), message)
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
        // `size()` is the modulus length in *bytes*, i.e. it rounds up to the next byte
        // boundary, so `size() * 8` would wave through keys of 2041..=2047 bits. Compare the
        // exact bit length of the modulus instead.
        if key.n().bits() < RS256_MINIMUM_BITS {
            return Err(crate::Error::RsaKeyTooSmall);
        }
        Ok(key)
    }

    fn to_verifying_key(&self) -> RsaPublicKey {
        self.to_public_key()
    }

    /// Serializes the private key to PKCS#1 DER.
    ///
    /// The `Cow<'_, [u8]>` return type of the trait cannot carry zeroizing storage, so the
    /// returned buffer holds d, p, q, dp, dq and qinv and is *not* scrubbed when dropped.
    /// Callers that persist key material should encode via [`EncodeRsaPrivateKey::to_pkcs1_der`]
    /// and keep the resulting `SecretDocument`, as `procs::rs256::GenerateKey` does.
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
        if key.n().bits() < RS256_MINIMUM_BITS {
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
