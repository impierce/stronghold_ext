use std::{borrow::Cow, num::NonZeroUsize};

pub mod es256;
pub mod es256k;
pub mod rs256;

///  A trait for interfacing with cryptographic signatures.  
///
/// Provides a uniform interface to move from one backend to another.
pub trait AlgoSignature: Sized {
    const LENGTH: Option<NonZeroUsize>;

    fn try_from_slice(slice: &[u8]) -> crate::Result<Self>;

    fn as_bytes(&self) -> Cow<'_, [u8]>;
}

/// The main trait for manipulating cryptographic algorithms.
///
/// Follows a simple interface for generating, signing and verifying signatures with
/// a crytographic algorithm.
pub trait Algorithm {
    type SigningKey;
    type VerifyingKey;
    type Signature: AlgoSignature;

    /// Returns the name of this algorithm.
    fn name(&self) -> Cow<'static, str>;

    /// Returns the name of the curve used by this algorithm.
    fn curve(&self) -> Cow<'static, str>;

    /// Generates a new random signing key.
    fn generate_signing_key(&self) -> Self::SigningKey;

    /// Signs a `message` with the `signing_key`.
    fn sign(&self, signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature;

    /// Verifies the `message` against the `signature` and `verifying_key`.
    fn verify_signature(
        &self,
        signature: &Self::Signature,
        verifying_key: &Self::VerifyingKey,
        message: &[u8],
    ) -> bool;
}

/// Verifying key for a specific signature cryptosystem. In the case of public-key cryptosystems,
/// this is a public key.
///
/// This trait provides a uniform interface for different backends / implementations
/// of the same cyptosystem.
pub trait VerifyingKey<T>: Sized
where
    T: Algorithm<VerifyingKey = Self>,
{
    /// Creates a key from `raw` bytes. Returns an error if the bytes do not represent
    /// a valid key.
    fn from_slice(raw: &[u8]) -> crate::Result<Self>;

    /// Returns the key as raw bytes.
    ///
    /// Implementations should return `Cow::Borrowed` whenever possible (that is, if the bytes
    /// are actually stored within the implementing data structure).
    fn as_bytes(&self) -> Cow<'_, [u8]>;
}

/// Signing key for a specific signature cryptosystem. In the case of public-key cryptosystems,
/// this is a private key.
///
/// This trait provides a uniform interface for different backends / implementations
/// of the same cryptosystem.
pub trait SigningKey<T>: Sized
where
    T: Algorithm<SigningKey = Self>,
{
    /// Creates a key from `raw` bytes. Returns an error if the bytes do not represent
    /// a valid key.
    fn from_slice(raw: &[u8]) -> crate::Result<Self>;

    /// Converts a signing key to a verification key.
    fn to_verifying_key(&self) -> T::VerifyingKey;

    /// Returns the key as raw bytes.
    fn as_bytes(&self) -> Cow<'_, [u8]>;
}
