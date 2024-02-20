use serde::{Deserialize, Serialize};

use crate::types::Error;
use crate::verifiable::objects::{Proof, VC};
use crate::verifiable::types::{Context, ToJCS, Type};

#[derive(Debug, Serialize, Deserialize)]
pub struct VP {
    #[serde(rename = "@context")]
    contexts: Vec<Context>,

    #[serde(rename = "type")]
    types: Vec<Type>,

    #[serde(rename = "verifiableCredential")]
    verifiable_credential: Vec<VC>,

    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Vec<Proof>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    holder: Option<String>,
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
        match &mut self.proof {
            Some(proofs) => {
                proofs.push(proof);
                self.proof = Some(proofs.to_vec())
            }
            None => self.proof = Some(vec![proof]),
        }

        self
    }

    pub fn set_holder(&mut self, holder: String) -> &mut Self {
        self.holder = Some(holder);
        self
    }

    pub fn to_json(&self) -> Result<String, Error> {
        match self.validate() {
            Ok(_) => {
                serde_json::to_string(self).map_err(|err| Error::GenerateJSONError(err.to_string()))
            }
            Err(err) => Err(err),
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.contexts.is_empty() {
            return Err(Error::GenerateJSONError(String::from("vp: empty context")));
        }

        if self.types.is_empty() {
            return Err(Error::GenerateJSONError(String::from("vp: empty types")));
        }

        if self.verifiable_credential.is_empty() {
            return Err(Error::GenerateJSONError(String::from(
                "vp: empty credentials",
            )));
        }

        Ok(())
    }
}

impl ToJCS for VP {
    fn to_jcs(&self) -> Result<String, Error> {
        match self.validate() {
            Ok(_) => {
                serde_jcs::to_string(self).map_err(|err| Error::GenerateJSONError(err.to_string()))
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_json() {
        let vc = VC::new("id1".to_string());
        let mut vp = VP::new();

        vp.add_context("context1".to_string())
            .add_context("context2".to_string())
            .add_type("type".to_string())
            .add_credential(vc);

        let try_json = vp.to_json();
        assert!(!try_json.is_err());

        let expected_json = r#"{"@context":["context1","context2"],"type":["type"],"verifiableCredential":[{"@context":[],"type":[],"credentialSubject":null,"id":"id1"}]}"#;
        assert_eq!(expected_json, try_json.unwrap())
    }

    #[test]
    fn test_generate_jcs() {
        let vc = VC::new("id1".to_string());
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
            Error::GenerateJSONError("vp: empty context".to_string()),
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
            Error::GenerateJSONError("vp: empty types".to_string()),
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
            Error::GenerateJSONError("vp: empty credentials".to_string()),
            try_json.unwrap_err()
        )
    }
}
