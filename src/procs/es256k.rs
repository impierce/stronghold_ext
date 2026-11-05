use crate::{
    ext_procs, generic_procedures, AlgoSignature, Algorithm, Es256k, ProcedureExt, SigningKey,
    VerifyingKey,
};

use engine::runtime::memories::buffer::Buffer;
use iota_stronghold::{
    procedures::{FatalProcedureError, GenerateSecret, ProcedureOutput, Products, UseSecret},
    Location,
};

use iota_stronghold::procedures::{Procedure, ProcedureError, Runner};
use serde::{Deserialize, Serialize};
use stronghold_utils::GuardDebug;
use zeroize::Zeroizing;

/// The primary procedures for the [`Es256k`] algorithm.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub enum Es256kProcs {
    GenerateKey(GenerateKey),
    PublicKey(PublicKey),
    Sign(Sign),
    Verify(Verify),
}

/// Returns a Es256 public key from an already existing private key in the vault.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct PublicKey {
    pub private_key: Location,
}

/// Generates a random Es256 private key and stores it in the vault at the supplied [`Location`].
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct GenerateKey {
    pub output: Location,
}

/// Signs a message using the indicated private key from the vault.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct Sign {
    pub msg: Vec<u8>,
    pub private_key: Location,
}

/// Verifies that a message was signed by the indicated private key in the vault.
/// Generates a new public key to preform this verification. The public key is discarded.
/// Returns 1 if the signature is valid, 0 otherwise.
#[derive(Clone, GuardDebug, Serialize, Deserialize)]
pub struct Verify {
    pub msg: Vec<u8>,
    pub signature: Vec<u8>,
    pub private_key: Location,
}

generic_procedures!(Es256kProcs, UseSecret<1> => {PublicKey, Sign, Verify});
ext_procs!(Es256kProcs, GenerateSecret => {GenerateKey});

impl UseSecret<1> for PublicKey {
    type Output = Vec<u8>;

    fn use_secret(self, guard: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let sk = <Es256k as Algorithm>::SigningKey::from_slice(&guard[0].borrow())
            .map_err(|e| format!("Es256k: Failed to get signing key from guard {:?}", e))?;

        let vk = sk.to_verifying_key();

        Ok(vk.as_bytes().to_vec())
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

impl UseSecret<1> for Sign {
    type Output = Vec<u8>;

    fn use_secret(self, guard: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let sk = <Es256k as Algorithm>::SigningKey::from_slice(&guard[0].borrow())
            .map_err(|e| format!("Es256k: Failed to get signing key from guard {:?}", e))?;

        let sig = <Es256k as Algorithm>::sign(&Es256k::default(), &sk, &self.msg);

        Ok(sig.as_bytes().to_vec())
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

impl UseSecret<1> for Verify {
    type Output = Vec<u8>;

    fn use_secret(self, guard: [Buffer<u8>; 1]) -> Result<Self::Output, FatalProcedureError> {
        let sk = <Es256k as Algorithm>::SigningKey::from_slice(&guard[0].borrow())
            .map_err(|e| format!("Es256k: Failed to get signing key from guard {:?}", e))?;

        let sig = <Es256k as Algorithm>::Signature::try_from_slice(self.signature.as_slice())
            .map_err(|e| format!("Es256k: Failed to get signature from vector {:?}", e))?;

        let vk = sk.to_verifying_key();
        let res = <Es256k as Algorithm>::verify_signature(&Es256k::default(), &sig, &vk, &self.msg);

        if res {
            Ok(u8::to_be_bytes(1).to_vec())
        } else {
            Ok(u8::to_be_bytes(0).to_vec())
        }
    }

    fn source(&self) -> [Location; 1] {
        [self.private_key.clone()]
    }
}

impl GenerateSecret for GenerateKey {
    type Output = ();

    fn generate(self) -> Result<Products<Self::Output>, FatalProcedureError> {
        let sk = <Es256k as Algorithm>::generate_signing_key(&Es256k::default());
        let sk = sk.as_bytes().to_vec();

        Ok(Products {
            secret: Zeroizing::new(sk),
            output: (),
        })
    }

    fn target(&self) -> &Location {
        &self.output
    }
}

impl ProcedureExt for Es256kProcs {
    fn input(&self) -> Option<Location> {
        match self {
            Es256kProcs::GenerateKey(_) => None,
            Es256kProcs::PublicKey(proc) => Some(proc.private_key.clone()),
            Es256kProcs::Sign(proc) => Some(proc.private_key.clone()),
            Es256kProcs::Verify(proc) => Some(proc.private_key.clone()),
        }
    }

    fn output(&self) -> Option<Location> {
        match self {
            Es256kProcs::GenerateKey(proc) => Some(proc.output.clone()),
            Es256kProcs::PublicKey(_) => None,
            Es256kProcs::Sign(_) => None,
            Es256kProcs::Verify(_) => None,
        }
    }
}

impl Procedure for Es256kProcs {
    type Output = ProcedureOutput;

    fn execute<R: Runner>(self, runner: &R) -> Result<Self::Output, ProcedureError> {
        match self {
            Es256kProcs::GenerateKey(proc) => proc.execute(runner).map(|o| o.into()),
            Es256kProcs::PublicKey(proc) => proc.execute(runner).map(|o| o.into()),
            Es256kProcs::Sign(proc) => proc.execute(runner).map(|o| o.into()),
            Es256kProcs::Verify(proc) => proc.execute(runner).map(|o| o.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iota_stronghold::Stronghold;

    use crate::{execute_procedure_chained_ext, execute_procedure_ext};

    #[test]
    fn test_es256k_procs() {
        let stronghold = Stronghold::default();
        let client = stronghold.create_client(b"test_es256k_procs").unwrap();

        let sk_loc = Location::generic(b"secret_key".to_vec(), b"record".to_vec());

        let gen_key = Es256kProcs::GenerateKey(GenerateKey {
            output: sk_loc.clone(),
        });

        // create es256k secret key and put it into the stronghold vault.
        let _ = execute_procedure_ext(&client, gen_key).unwrap();

        let pub_key = Es256kProcs::PublicKey(PublicKey {
            private_key: sk_loc.clone(),
        });

        let sign = Es256kProcs::Sign(Sign {
            msg: b"test".to_vec(),
            private_key: sk_loc.clone(),
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

        let verify = Es256kProcs::Verify(Verify {
            msg: b"test".to_vec(),
            signature: sig.into(),
            private_key: sk_loc.clone(),
        });

        let res: [u8; 1] = execute_procedure_ext(&client, verify)
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(res[0], 1);
    }
}
