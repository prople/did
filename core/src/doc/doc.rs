use rst_common::standard::serde::{Deserialize, Serialize};
use rst_common::standard::serde_json;

use crate::types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Primary {
    pub id: DID,
    pub controller: DIDController,

    #[serde(rename = "type")]
    pub verification_type: DIDVerificationKeyType,

    #[serde(rename = "publicKeyMultibase")]
    pub multibase: DIDMultibase,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Doc {
    #[serde(rename = "@context")]
    pub context: Vec<DIDContext>,

    pub id: DID,

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

    pub fn to_json(&self) -> Result<String, Error> {
        let json = serde_json::to_string(self);
        match json {
            Ok(value) => Ok(value),
            Err(err) => Err(Error::GenerateDocError(err.to_string())),
        }
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

}
