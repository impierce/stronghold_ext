// This is a library that extends the iota_stronghold library to allow user-defined cryptographic algorithms.
// This library also includes its own implementations of the es256, es256k and rs256 algorithms.
mod ext;
pub use ext::{execute_procedure_chained_ext, execute_procedure_ext, ProcedureExt};

#[cfg(feature = "_crypto_base")]
use thiserror::Error as DeriveError;

#[cfg(feature = "_crypto_base")]
mod crypto;

#[cfg(feature = "_crypto_base")]
pub use crypto::{AlgoSignature, Algorithm, SigningKey, VerifyingKey};

#[cfg(feature = "es256")]
pub use crypto::es256::Es256;
#[cfg(feature = "es256k")]
pub use crypto::es256k::Es256k;
#[cfg(feature = "rs256")]
pub use crypto::rs256::{Rs256, RS256_MINIMUM_BITS};

#[cfg(feature = "_crypto_base")]
pub mod procs;

// Error types for the crypto module.
//
// Marked `#[non_exhaustive]` so that adding an algorithm (and therefore a new
// error variant) is not a breaking change for downstream exhaustive matches.
#[cfg(feature = "_crypto_base")]
#[derive(Debug, DeriveError)]
#[non_exhaustive]
pub enum Error {
    #[error("signature error: `{0}`")]
    CryptoError(#[from] signature::Error),
    #[cfg(feature = "es256")]
    #[error("signature error: `{0}`")]
    P256Error(#[from] p256::elliptic_curve::Error),
    #[cfg(feature = "rs256")]
    #[error("RSA error: `{0}`")]
    RsaError(#[from] rsa::Error),
    #[cfg(feature = "rs256")]
    #[error("RSA PKCS#1 error: `{0}`")]
    RsaPkcs1Error(#[from] rsa::pkcs1::Error),
    #[cfg(feature = "rs256")]
    #[error("RSA key must be at least {RS256_MINIMUM_BITS} bits")]
    RsaKeyTooSmall,
}

// crypto result type.
#[cfg(feature = "_crypto_base")]
pub type Result<T> = core::result::Result<T, Error>;

#[macro_export]
macro_rules! ext_procs {
        {$Enum:ident, _ => { $($Proc:ident),+ }} => {
            $(
                impl From<$Proc> for $Enum {
                    fn from(proc: $Proc) -> Self {
                        $Enum::$Proc(proc)
                    }
                }
            )+
        };
        {$Enum:ident, $Trait:ident => { $($Proc:ident),+ }} => {
            $(
                impl Procedure for $Proc {
                    type Output = <$Proc as $Trait>::Output;

                    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
                        self.exec(runner)
                    }
                }
            )+
            ext_procs!($Enum, _ => { $($Proc),+ });
        };
        {$Enum:ident, $($Trait:tt => { $($Proc:ident),+ }),+} => {
            $(
                ext_procs!($Enum, $Trait => { $($Proc),+ } );
            )+
        };
    }

#[macro_export]
macro_rules! generic_procedures {
        { $Enum:ident, $Trait:ident<$n:literal> => { $($Proc:ident),+ }} => {
            $(
                impl Procedure for $Proc {
                    type Output = <$Proc as $Trait<$n>>::Output;

                    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
                        self.exec(runner)
                    }
                }
            )+
            ext_procs!($Enum, _ => { $($Proc),+ });
        };
        {$Enum:ident, $($Trait:tt<$n:literal> => { $($Proc:ident),+ }),+} => {
            $(
                generic_procedures!($Enum, $Trait<$n> => { $($Proc),+ });
            )+
        };

    }
