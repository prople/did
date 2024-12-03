use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use crate::types::{DIDError, JSONValue, ToJCS, ToJSON, Validator};
use crate::verifiable::objects::VC;
use crate::verifiable::types::{Context, Type};

use crate::verifiable::proof::types::{ProofError, Proofable};
use crate::verifiable::proof::Proof;

/// `VP` a main object used to generate `DID VP`. The `VP` object MUST contains
/// a [`VC`] object, it may be a single `VC` or multiple
///
/// Ref: <https://www.w3.org/TR/vc-data-model-2.0/#presentations>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(crate = "self::serde")]
pub struct VP {
    #[serde(rename = "@context")]
    pub contexts: Vec<Context>,

    #[serde(rename = "type")]
    pub types: Vec<Type>,

    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VC>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
}

impl VP {
    pub fn new() -> Self {
        Self {
            contexts: Vec::new(),
            types: Vec::new(),
            verifiable_credential: Vec::new(),
            proof: None,
            holder: None,
        }
    }

    pub fn add_context(&mut self, context: Context) -> &mut Self {
        self.contexts.push(context);
        self
    }

    pub fn add_type(&mut self, t: Type) -> &mut Self {
        self.types.push(t);
        self
    }

    pub fn add_credential(&mut self, cred: VC) -> &mut Self {
        self.verifiable_credential.push(cred);
        self
    }

    pub fn add_proof(&mut self, proof: Proof) -> &mut Self {
        self.proof = Some(proof);
        self
    }

    pub fn set_holder(&mut self, holder: String) -> &mut Self {
        self.holder = Some(holder);
        self
    }
}

impl ToJSON for VP {
    fn to_json(&self) -> Result<JSONValue, DIDError> {
        match self.validate() {
            Ok(_) => {
                let jsonstr = serde_json::to_string(self)
                    .map_err(|err| DIDError::GenerateJSONError(err.to_string()))?;

                Ok(JSONValue::from(jsonstr))
            }
            Err(err) => Err(err),
        }
    }
}

impl ToJCS for VP {
    fn to_jcs(&self) -> Result<String, DIDError> {
        match self.validate() {
            Ok(_) => serde_jcs::to_string(self)
                .map_err(|err| DIDError::GenerateJSONError(err.to_string())),
            Err(err) => Err(err),
        }
    }
}

impl Validator for VP {
    fn validate(&self) -> Result<(), DIDError> {
        if self.contexts.is_empty() {
            return Err(DIDError::GenerateJSONError(String::from(
                "vp: empty context",
            )));
        }

        if self.types.is_empty() {
            return Err(DIDError::GenerateJSONError(String::from("vp: empty types")));
        }

        if self.verifiable_credential.is_empty() {
            return Err(DIDError::GenerateJSONError(String::from(
                "vp: empty credentials",
            )));
        }

        Ok(())
    }
}

impl Proofable for VP {
    fn get_proof(&self) -> Option<Proof> {
        self.proof.to_owned()
    }

    fn setup_proof(&mut self, proof: Proof) -> &mut Self {
        self.add_proof(proof);
        self
    }

    fn parse_json_bytes(bytes: Vec<u8>) -> Result<Self, ProofError> {
        let parsed: Self = serde_json::from_slice(bytes.as_slice())
            .map_err(|err| ProofError::ProofGenerationError(err.to_string()))?;

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_json() {
        let vc = VC::new("id1".to_string(), "issuer".to_string());
        let mut vp = VP::new();

        vp.add_context("context1".to_string())
            .add_context("context2".to_string())
            .add_type("type".to_string())
            .add_credential(vc);

        let try_json = vp.to_json();
        assert!(!try_json.is_err());

        let expected_json = r#"{"@context":["context1","context2"],"type":["type"],"verifiableCredential":[{"@context":[],"type":[],"credentialSubject":null,"id":"id1","issuer":"issuer"}]}"#;
        assert_eq!(JSONValue::from(expected_json), try_json.unwrap())
    }

    #[test]
    fn test_generate_jcs() {
        let vc = VC::new("id1".to_string(), "issuer".to_string());
        let mut vp = VP::new();

        vp.add_context("context1".to_string())
            .add_context("context2".to_string())
            .add_type("type".to_string())
            .add_credential(vc);

        let try_json = vp.to_jcs();
        assert!(!try_json.is_err());
    }

    #[test]
    fn test_validate_failed_context_empty() {
        let vp = VP::new();
        let try_json = vp.to_json();
        assert!(try_json.is_err());
        assert_eq!(
            DIDError::GenerateJSONError("vp: empty context".to_string()),
            try_json.unwrap_err()
        )
    }

    #[test]
    fn test_validate_failed_types_empty() {
        let mut vp = VP::new();
        vp.add_context("context1".to_string());

        let try_json = vp.to_json();
        assert!(try_json.is_err());
        assert_eq!(
            DIDError::GenerateJSONError("vp: empty types".to_string()),
            try_json.unwrap_err()
        )
    }

    #[test]
    fn test_validate_failed_credential_empty() {
        let mut vp = VP::new();
        vp.add_context("context1".to_string());
        vp.add_type("type".to_string());

        let try_json = vp.to_json();
        assert!(try_json.is_err());
        assert_eq!(
            DIDError::GenerateJSONError("vp: empty credentials".to_string()),
            try_json.unwrap_err()
        )
    }
}
