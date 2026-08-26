use crate::{
    ext_procs, generic_procedures, AlgoSignature, Algorithm, ProcedureExt, Rs256, SigningKey,
    VerifyingKey,
};

use engine::runtime::memories::buffer::Buffer;
use iota_stronghold::procedures::{Procedure, ProcedureError, Runner};
use iota_stronghold::{
    procedures::{FatalProcedureError, GenerateSecret, ProcedureOutput, Products, UseSecret},
    Location,
};
use serde::{Deserialize, Serialize};
use stronghold_utils::GuardDebug;
use zeroize::Zeroizing;

/// The primary procedures for the [`Rs256`] algorithm.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub enum Rs256Procs {
    GenerateKey(GenerateKey),
    PublicKey(PublicKey),
    Sign(Sign),
    Verify(Verify),
}

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct PublicKey {
    pub private_key: Location,
}

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct GenerateKey {
    pub output: Location,
}

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct Sign {
    pub msg: Vec<u8>,
    pub private_key: Location,
}

#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct Verify {
    pub msg: Vec<u8>,
    pub signature: Vec<u8>,
    pub private_key: Location,
}

generic_procedures!(Rs256Procs, UseSecret<1> => {PublicKey, Sign, Verify});
ext_procs!(Rs256Procs, GenerateSecret => {GenerateKey});

impl UseSecret<1> for PublicKey {
    type Output = Vec<u8>;

    fn use_secret(self, guard: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let sk = <Rs256 as Algorithm>::SigningKey::from_slice(&guard[0].borrow())
            .map_err(|e| format!("Rs256: failed to get signing key: {:?}", e))?;
        Ok(sk.to_verifying_key().as_bytes().to_vec())
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

impl UseSecret<1> for Sign {
    type Output = Vec<u8>;

    fn use_secret(self, guard: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let sk = <Rs256 as Algorithm>::SigningKey::from_slice(&guard[0].borrow())
            .map_err(|e| format!("Rs256: failed to get signing key: {:?}", e))?;
        Ok(Rs256.sign(&sk, &self.msg).as_bytes().to_vec())
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

impl UseSecret<1> for Verify {
    type Output = Vec<u8>;

    fn use_secret(self, guard: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let sk = <Rs256 as Algorithm>::SigningKey::from_slice(&guard[0].borrow())
            .map_err(|e| format!("Rs256: failed to get signing key: {:?}", e))?;
        let sig = <Rs256 as Algorithm>::Signature::try_from_slice(&self.signature)
            .map_err(|e| format!("Rs256: failed to get signature: {:?}", e))?;
        let valid = Rs256.verify_signature(&sig, &sk.to_verifying_key(), &self.msg);
        Ok(if valid { 1u8 } else { 0u8 }.to_be_bytes().to_vec())
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

impl GenerateSecret for GenerateKey {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let key = Rs256.generate_signing_key().as_bytes().to_vec();
        Ok(Products {
            secret: Zeroizing::new(key),
            output: (),
        })
    }

    fn target(&self) -> &Location {
        &self.output
    }
}

impl ProcedureExt for Rs256Procs {
    fn input(&self) -> Option<Location> {
        match self {
            Self::GenerateKey(_) => None,
            Self::PublicKey(proc) => Some(proc.private_key.clone()),
            Self::Sign(proc) => Some(proc.private_key.clone()),
            Self::Verify(proc) => Some(proc.private_key.clone()),
        }
    }

    fn output(&self) -> Option<Location> {
        match self {
            Self::GenerateKey(proc) => Some(proc.output.clone()),
            Self::PublicKey(_) | Self::Sign(_) | Self::Verify(_) => None,
        }
    }
}

impl Procedure for Rs256Procs {
    type Output = ProcedureOutput;

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        match self {
            Self::GenerateKey(proc) => proc.execute(runner).map(Into::into),
            Self::PublicKey(proc) => proc.execute(runner).map(Into::into),
            Self::Sign(proc) => proc.execute(runner).map(Into::into),
            Self::Verify(proc) => proc.execute(runner).map(Into::into),
        }
    }
}
