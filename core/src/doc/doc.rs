use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use crate::types::*;

/// `Primary` is a main data structure used for `authentication`, `assertion`
/// `capabilityInvocation` and `capabilityDelegation`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct Primary {
    pub id: DIDSyntax,
    pub controller: DIDController,

    #[serde(rename = "type")]
    pub verification_type: DIDVerificationKeyType,

    #[serde(rename = "publicKeyMultibase")]
    pub multibase: DIDMultibase,
}

/// `Doc` is a main data structure modeling the core properties
/// from the `DID Document`
///
/// Ref: <https://www.w3.org/TR/did-core/#core-properties>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct Doc {
    #[serde(rename = "@context")]
    pub context: Vec<DIDContext>,

    pub id: DIDSyntax,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Primary>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "capabilityInvocation")]
    pub cap_invoke: Option<Vec<Primary>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "capabilityDelegation")]
    pub cap_delegate: Option<Vec<Primary>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "assertionMethod")]
    pub assertion: Option<Vec<Primary>>,
}

impl Doc {
    pub fn generate(did: String) -> Self {
        let context = vec![CONTEXT_DEFAULT.to_string()];
        Self {
            context,
            id: did,
            authentication: None,
            cap_delegate: None,
            cap_invoke: None,
            assertion: None,
        }
    }

    pub fn add_context(&mut self, context: DIDContext) -> &mut Self {
        self.context.push(context);
        self
    }

    pub fn add_assertion(&mut self, assertion: Primary) -> &mut Self {
        if let Some(ref mut assertions) = self.assertion {
            assertions.push(assertion.clone())
        }

        if let None = self.assertion {
            self.assertion = Some(vec![assertion.clone()]);
        }

        self
    }

    pub fn add_authentication(&mut self, auth: Primary) -> &mut Self {
        if let Some(ref mut authentication) = self.authentication {
            authentication.push(auth.clone())
        }

        if let None = self.authentication {
            self.authentication = Some(vec![auth.clone()]);
        }

        self
    }

    pub fn add_cap_delegate(&mut self, delegate: Primary) -> &mut Self {
        if let Some(ref mut cap_delegate) = self.cap_delegate {
            cap_delegate.push(delegate.clone())
        }

        if let None = self.cap_delegate {
            self.cap_delegate = Some(vec![delegate.clone()]);
        }

        self
    }

    pub fn add_cap_invoke(&mut self, invoke: Primary) -> &mut Self {
        if let Some(ref mut cap_invoke) = self.cap_invoke {
            cap_invoke.push(invoke.clone())
        }

        if let None = self.cap_invoke {
            self.cap_invoke = Some(vec![invoke.clone()]);
        }

        self
    }
}

impl ToJSON for Doc {
    fn to_json(&self) -> Result<String, DIDError> {
        serde_json::to_string(self).map_err(|err| DIDError::GenerateDocError(err.to_string()))
    }
}

impl Validator for Doc {
    fn validate(&self) -> Result<(), DIDError> {
        if self.id.is_empty() {
            return Err(DIDError::ValidateError("[doc]: missing id".to_string()));
        }

        if self.context.len() < 1 {
            return Err(DIDError::ValidateError(
                "[doc]: at least one context must be filled".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_assertion() {
        let primary = Primary {
            id: "id".to_string(),
            controller: "controller".to_string(),
            verification_type: "verification".to_string(),
            multibase: "multibase".to_string(),
        };

        let mut doc = Doc::generate("test".to_string());
        let json = doc
            .add_assertion(primary.clone())
            .add_assertion(primary.clone())
            .to_json();

        assert!(!json.is_err());

        let fromjson: Result<Doc, _> = serde_json::from_str(json.as_ref().unwrap().as_str());
        assert!(!fromjson.as_ref().is_err());

        let doc = fromjson.unwrap();
        assert!(doc.authentication.is_none());
        assert!(doc.cap_delegate.is_none());
        assert!(doc.cap_invoke.is_none());
        assert_eq!(doc.assertion.unwrap().len(), 2);
    }

    #[test]
    fn test_validation_error() {
        let mut doc = Doc::generate("test".to_string());
        doc.context = vec![];

        let validation = doc.validate();
        assert!(validation.is_err());
    }

    #[test]
    fn test_validation_success() {
        let doc = Doc::generate("test".to_string());
        let validation = doc.validate();
        assert!(validation.is_ok());
    }
}
