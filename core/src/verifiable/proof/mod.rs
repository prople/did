use std::marker::PhantomData;

use serde_jcs;

use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};

use crate::types::{DIDError, ToJCS, Validator};

pub(crate) mod config;
pub(crate) mod hash;
pub(crate) mod serialize;
pub(crate) mod transform;
pub(crate) mod verifier;

pub mod eddsa;
pub mod integrity;
pub mod types;

use eddsa::EddsaJcs2022;
use integrity::Integrity;

use types::{
    ProofConfigValidator, ProofError, ProofOptionsValidator, ProofPurpose, Proofable,
    DEFAULT_PROOF_CRYPTOSUITE, DEFAULT_PROOF_TYPE,
};

/// `Proof` is an object used to generate `DID Proof` used at `VC` and `VP`
///
/// Ref:
/// - <https://www.w3.org/TR/vc-data-model-2.0/#credentials>
/// - <https://www.w3.org/TR/vc-data-model-2.0/#proofs-signatures>
/// - <https://www.w3.org/TR/vc-data-model-2.0/#algorithms>
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(crate = "self::serde")]
pub struct Proof {
    pub id: String,

    #[serde(rename = "type")]
    pub typ: String,

    #[serde(rename = "proofPurpose")]
    pub proof_purpose: ProofPurpose,

    #[serde(rename = "proofValue")]
    pub proof_value: String,

    /// Following the formal specification, the "verification method"
    /// must be a string map to some URL
    ///
    /// Note, that when it is expressed, it's value points to the actual
    /// location of the data; the location of the public key
    ///  
    /// Ref: https://www.w3.org/TR/vc-data-integrity/#proofs
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,
}

impl Default for Proof {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            typ: "".to_string(),
            proof_purpose: ProofPurpose::Unknown,
            proof_value: String::from(""),
            verification_method: String::from(""),
            created: None,
            expires: None,
            cryptosuite: None,
        }
    }
}

impl Proof {
    pub fn new(id: String) -> Self {
        Self {
            id,
            typ: DEFAULT_PROOF_TYPE.to_string(),
            proof_purpose: ProofPurpose::Unknown,
            proof_value: String::from(""),
            verification_method: String::from(""),
            created: None,
            expires: None,
            cryptosuite: Some(DEFAULT_PROOF_CRYPTOSUITE.to_string()),
        }
    }

    pub fn typ(&mut self, proof_type: String) {
        self.typ = proof_type;
    }

    pub fn set_signature_as_string(&mut self, sig: String) {
        self.proof_value = sig
    }

    pub fn purpose(&mut self, purpose: String) {
        self.proof_purpose = ProofPurpose::from(purpose)
    }

    pub fn method(&mut self, method: String) {
        self.verification_method = method
    }

    pub fn cryptosuite(&mut self, suite: String) {
        self.cryptosuite = Some(suite)
    }

    pub fn created(&mut self, created: String) {
        self.created = Some(created)
    }

    pub fn expires(&mut self, expires: String) {
        self.expires = Some(expires)
    }

    pub fn remove_proof_value(&mut self) -> &mut Self {
        self.proof_value = "".to_string();
        self
    }
}

/// The implementation of [`Validator`] here is to follow formal specification for the `Add Proof`
///
/// There is a little adjustment on the algorithm, we're not validate the verification method. The verification
/// method used to get the private key's bytes, in Prople, the keypair will be given directly, so there
/// is a difference between the designed architecture with the formal specification.
///
/// Spec: https://www.w3.org/TR/vc-data-integrity/#add-proof
impl Validator for Proof {
    fn validate(&self) -> Result<(), DIDError> {
        if self.typ.is_empty() {
            return Err(DIDError::ValidateError("missing type".to_string()));
        }

        match self.proof_purpose {
            ProofPurpose::Unknown => {
                Err(DIDError::ValidateError("unknown proof purpose".to_string()))
            }
            _ => Ok(()),
        }
    }
}

impl ProofOptionsValidator for Proof {
    fn validate_type(&self) -> Result<(), types::ProofError> {
        if self.typ != DEFAULT_PROOF_TYPE {
            return Err(types::ProofError::ProofGenerationError(
                "invalid proof type".to_string(),
            ));
        }

        Ok(())
    }

    fn validate_cryptosuite(&self) -> Result<(), types::ProofError> {
        match self.cryptosuite.to_owned() {
            Some(suite) => {
                if suite != DEFAULT_PROOF_CRYPTOSUITE {
                    return Err(ProofError::ProofGenerationError(
                        "invalid cryptosuite".to_string(),
                    ));
                }
            }
            _ => {
                return Err(ProofError::ProofGenerationError(
                    "missing cryptosuite".to_string(),
                ))
            }
        }

        Ok(())
    }
}

impl ProofConfigValidator for Proof {
    fn validate_created(&self) -> Result<(), ProofError> {
        match self.created.to_owned() {
            Some(created) => {
                let _ = created
                    .parse::<DateTime<Utc>>()
                    .map_err(|err| ProofError::ProofGenerationError(err.to_string()))?;
            }
            _ => {
                return Err(ProofError::ProofGenerationError(
                    "invalid created format".to_string(),
                ))
            }
        }

        Ok(())
    }
}

impl ToJCS for Proof {
    fn to_jcs(&self) -> Result<String, DIDError> {
        let output = serde_jcs::to_string(self)
            .map_err(|err| DIDError::GenerateJSONJCSError(err.to_string()))?;
        Ok(output)
    }
}

/// DataIntegrityEddsaJcs2022 is a factory pattern implementation used to build the [`Integrity`]
/// and [`EddsaJcs2022`] instances
pub struct DataIntegrityEddsaJcs2022<TDoc>
where
    TDoc: Proofable,
{
    _phantom: PhantomData<TDoc>,
}

impl<TDoc> Default for DataIntegrityEddsaJcs2022<TDoc>
where
    TDoc: Proofable,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<TDoc> DataIntegrityEddsaJcs2022<TDoc>
where
    TDoc: Proofable,
{
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    pub fn build(&self) -> Integrity<TDoc, EddsaJcs2022> {
        let eddsa_crypto_instance = EddsaJcs2022::new();
        Integrity::<TDoc, _>::new(eddsa_crypto_instance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rst_common::standard::serde_json;

    #[test]
    fn test_proof_default() {
        let mut proof = Proof::default();
        proof.proof_purpose = ProofPurpose::AssertionMethod;
        proof.verification_method = "testing".to_string();

        let json = serde_json::to_string(&proof).unwrap();
        let from_json = serde_json::from_str::<Proof>(&json).unwrap();

        assert_eq!(from_json.proof_purpose, proof.proof_purpose);
        assert_eq!(from_json.verification_method, proof.verification_method);
    }
}
