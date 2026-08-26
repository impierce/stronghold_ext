// This is a library that extends the iota_stronghold library to allow user-defined cryptographic algorithms.
// This library also includes its own implementations of the es256 and es256k algorithms.
mod ext;
pub use ext::{execute_procedure_chained_ext, execute_procedure_ext, ProcedureExt};

#[cfg(feature = "crypto")]
use thiserror::Error as DeriveError;

#[cfg(feature = "crypto")]
mod crypto;

#[cfg(feature = "crypto")]
pub use crypto::{
    es256::Es256, es256k::Es256k, rs256::Rs256, AlgoSignature, Algorithm, SigningKey, VerifyingKey,
};
#[cfg(feature = "crypto")]
pub mod procs;

// Error types for the crypto module.
#[cfg(feature = "crypto")]
#[derive(Debug, DeriveError)]
pub enum Error {
    #[error("signature error: `{0}`")]
    CryptoError(#[from] ecdsa::Error),
    #[error("signature error: `{0}`")]
    P256Error(#[from] p256::elliptic_curve::Error),
    #[error("RSA error: `{0}`")]
    RsaError(#[from] rsa::Error),
    #[error("RSA PKCS#1 error: `{0}`")]
    RsaPkcs1Error(#[from] rsa::pkcs1::Error),
    #[error("RSA key must be at least 2048 bits")]
    RsaKeyTooSmall,
}

// crypto result type.
#[cfg(feature = "crypto")]
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
