use k256::{
    ecdsa::{
        signature::{DigestSigner, DigestVerifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{FieldBytesSize, Generate},
    Secp256k1,
};
use sha2::{digest::typenum::Unsigned, Digest, Sha256};
use std::{borrow::Cow, marker::PhantomData, num::NonZeroUsize, ops::Add};

use crate::{AlgoSignature, Algorithm, SigningKey as SKey, VerifyingKey as VKey};

/// Algorithm implementing elliptic curve digital signatures (ECDSA) on the secp256k1 curve.
///
/// Could be updated later to support multiple digests outside of sha256.
#[derive(Debug)]
pub struct Es256k {
    _digest: PhantomData<Sha256>,
}

impl AlgoSignature for Signature {
    const LENGTH: Option<NonZeroUsize> =
        NonZeroUsize::new(<FieldBytesSize<Secp256k1> as Add>::Output::USIZE);

    fn try_from_slice(slice: &[u8]) -> crate::Result<Self> {
        Signature::try_from(slice).map_err(From::from)
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

impl Default for Es256k
where
    SigningKey: DigestSigner<Sha256, Signature>,
    VerifyingKey: DigestVerifier<Sha256, Signature>,
{
    fn default() -> Self {
        Es256k {
            _digest: PhantomData,
        }
    }
}

impl Algorithm for Es256k
where
    SigningKey: DigestSigner<Sha256, Signature>,
    VerifyingKey: DigestVerifier<Sha256, Signature>,
{
    type SigningKey = SigningKey;
    type VerifyingKey = VerifyingKey;
    type Signature = Signature;

    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed("ES256K")
    }

    fn curve(&self) -> Cow<'static, str> {
        Cow::Borrowed("K-256")
    }

    fn generate_signing_key(&self) -> Self::SigningKey {
        Self::SigningKey::generate()
    }

    /// Signs a message with a `SigningKey` (private key) and returns a `Signature`.
    /// Using Sha256 as the digest to hash the message before signing as per the es256k spec.
    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        signing_key.sign_digest(|digest: &mut Sha256| digest.update(message))
    }

    /// Verifies a signature given a message and a `VerifyingKey`.
    /// Uses Sha256 as the digest to hash the message before verifying as per the es256k spec.
    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool {
        // Some implementations (e.g., OpenSSL) produce high-S signatures, which
        // are considered invalid by this implementation. Hence, we perform normalization here.
        //
        // See also: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        let normalized_signature = signature.normalize_s();

        verifying_key
            .verify_digest(
                |digest: &mut Sha256| {
                    digest.update(message);
                    Ok(())
                },
                &normalized_signature,
            )
            .is_ok()
    }
}

impl SKey<Es256k> for SigningKey {
    fn from_slice(raw: &[u8]) -> crate::Result<Self> {
        Self::from_slice(raw).map_err(From::from)
    }

    /// Returns a `VerifyingKey` aka a public key from the private key.
    fn to_verifying_key(&self) -> VerifyingKey {
        *self.verifying_key()
    }

    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_bytes().to_vec())
    }
}

impl VKey<Es256k> for VerifyingKey {
    /// Takes a slice of bytes in sec1 format and returns a `VerifyingKey`.
    ///
    /// Sec1format is a format where the first byte indicates the type of key.
    fn from_slice(raw: &[u8]) -> crate::Result<Self> {
        Self::from_sec1_bytes(raw).map_err(From::from)
    }

    /// Serializes the key to a compressed encoded point format.  Will include a leading byte indicating the type of key.
    ///
    /// Should maybe expose the ability to change whether or not the key is compressed.
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        let bytes = self.to_sec1_point(true).as_bytes().to_vec();
        Cow::Owned(bytes)
    }
}
