use rst_common::standard::serde::{Deserialize, Serialize};
use rst_common::standard::serde_json::Value;

use crate::types::Error;
use crate::verifiable::objects::Proof;
use crate::verifiable::types::ToJCS;

pub type Context = String;
pub type ID = String;
pub type Type = String;
pub type SRI = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct VC {
    #[serde(rename = "@context")]
    contexts: Vec<Context>,

    #[serde(rename = "type")]
    types: Vec<Type>,

    #[serde(rename = "credentialSubject")]
    credential_subject: Value,

    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,

    id: ID,
}

impl VC {
    pub fn new(id: ID) -> Self {
        Self {
            id,
            contexts: Vec::new(),
            types: Vec::new(),
            credential_subject: Value::Null,
            proof: None,
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

    pub fn set_credential(&mut self, credential: Value) -> &mut Self {
        self.credential_subject = credential;
        self
    }

    pub fn proof(&mut self, proof: Proof) -> &mut Self {
        self.proof = Some(proof);
        self
    }

    pub fn to_json(&self) -> Result<String, Error> {
        let validation = self.validate();
        match validation {
            Ok(_) => {
                serde_json::to_string(self).map_err(|err| Error::GenerateJSONError(err.to_string()))
            }
            Err(err) => Err(err),
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.contexts.is_empty() {
            return Err(Error::GenerateVCError(String::from(
                "vc_error: empty context",
            )));
        }

        if self.types.is_empty() {
            return Err(Error::GenerateVCError(String::from(
                "vc_error: empty types",
            )));
        }

        if self.credential_subject == Value::Null {
            return Err(Error::GenerateVCError(String::from(
                "vc_error: credential should not be null",
            )));
        }

        Ok(())
    }
}

impl ToJCS for VC {
    fn to_jcs(&self) -> Result<String, Error> {
        let validation = self.validate();
        match validation {
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

    #[derive(Serialize, Deserialize)]
    struct FakeCredentialProperties {
        pub user_agent: String,
        pub user_did: String,
    }

    #[derive(Serialize, Deserialize)]
    struct FakeCredentialSubject {
        id: String,
        connection: FakeCredentialProperties,
    }

    #[test]
    fn test_generate_credential() {
        let mut vc = VC::new(String::from("id"));
        vc.add_context(String::from("context1"))
            .add_context("context2".to_string())
            .add_type("VerifiableCredential".to_string());

        let credential_props = FakeCredentialProperties {
            user_agent: String::from("test_agent"),
            user_did: String::from("test_did"),
        };

        let credential = FakeCredentialSubject {
            id: String::from("id"),
            connection: credential_props,
        };

        let credential_value = serde_json::to_value(credential);
        assert!(!credential_value.is_err());

        vc.set_credential(credential_value.unwrap());
        let json_str = vc.to_json();
        assert!(!json_str.is_err());

        let expected_json = r#"{"@context":["context1","context2"],"type":["VerifiableCredential"],"credentialSubject":{"connection":{"user_agent":"test_agent","user_did":"test_did"},"id":"id"},"id":"id"}"#;
        assert_eq!(json_str.unwrap(), expected_json.to_string())
    }

    #[test]
    fn test_generate_credential_jcs() {
        let mut vc = VC::new(String::from("id"));
        vc.add_context(String::from("context1"))
            .add_context("context2".to_string())
            .add_type("VerifiableCredential".to_string());

        let credential_props = FakeCredentialProperties {
            user_agent: String::from("test_agent"),
            user_did: String::from("test_did"),
        };

        let credential = FakeCredentialSubject {
            id: String::from("id"),
            connection: credential_props,
        };

        let credential_value = serde_json::to_value(credential);
        assert!(!credential_value.is_err());

        vc.set_credential(credential_value.unwrap());
        let json_str = vc.to_jcs();
        assert!(!json_str.is_err());
    }

    #[test]
    fn test_generate_empty_context() {
        let vc = VC::new(String::from("id"));
        let try_json = vc.to_json();
        assert!(try_json.is_err());

        assert_eq!(
            Error::GenerateVCError(String::from("vc_error: empty context")),
            try_json.unwrap_err()
        )
    }

    #[test]
    fn test_generate_empty_types() {
        let mut vc = VC::new(String::from("id"));
        vc.add_context(String::from("context1"));
        vc.add_context(String::from("context2"));

        let try_json = vc.to_json();
        assert!(try_json.is_err());

        assert_eq!(
            Error::GenerateVCError(String::from("vc_error: empty types")),
            try_json.unwrap_err()
        )
    }

    #[test]
    fn test_generate_empty_credential() {
        let mut vc = VC::new(String::from("id"));
        vc.add_context(String::from("context1"))
            .add_context("context2".to_string())
            .add_type("VerifiableCredential".to_string());

        let try_json = vc.to_json();
        assert!(try_json.is_err());

        assert_eq!(
            Error::GenerateVCError(String::from("vc_error: credential should not be null")),
            try_json.unwrap_err()
        )
    }
}
