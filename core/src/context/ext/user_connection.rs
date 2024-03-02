use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use crate::types::{DIDError, ToJSON, CONTEXT_VC};

pub const CONTEXT_USER_AGENT_ADDRESS: &str = "https://schema.org/identifier";

/// `UserConnectionCredentialProperties` is a properties designed to  fullfil the connection
/// request contexts when user want to connect with others
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(crate = "self::serde")]
pub struct UserConnectionCredentialProperties {
    pub user_agent_address: String,
    pub user_did: String,
}

impl Default for UserConnectionCredentialProperties {
    fn default() -> Self {
        Self {
            user_agent_address: String::from(CONTEXT_USER_AGENT_ADDRESS),
            user_did: String::from(CONTEXT_VC),
        }
    }
}

/// `UserConnectionCredentialContext` is a custom context used specifically for the `Prople` needs
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(crate = "self::serde")]
pub struct UserConnectionCredentialContext {
    #[serde(rename = "@context")]
    pub context: UserConnectionCredentialProperties,
}

impl UserConnectionCredentialContext {
    pub fn new(properties: UserConnectionCredentialProperties) -> Self {
        Self {
            context: properties,
        }
    }
}

/// `UserConnectionCredential` is an object used to generate main credential when connecting with others
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
#[serde(crate = "self::serde")]
pub struct UserConnectionCredential {
    pub user_connection_credential: UserConnectionCredentialContext,
}

impl UserConnectionCredential {
    pub fn new(context: UserConnectionCredentialContext) -> Self {
        Self {
            user_connection_credential: context,
        }
    }
}

impl ToJSON for UserConnectionCredential {
    fn to_json(&self) -> Result<String, DIDError> {
        serde_json::to_string(self).map_err(|err| DIDError::GenerateJSONError(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_user_connection_credential_json() {
        let credential = UserConnectionCredential::default();
        let to_json = credential.to_json();
        assert!(!to_json.is_err());

        let expected_json = r#"{"UserConnectionCredential":{"@context":{"userAgentAddress":"https://schema.org/identifier","userDid":"https://www.w3.org/2018/credentials/#VerifiableCredential"}}}"#;
        assert_eq!(to_json.unwrap(), expected_json.to_string())
    }
}
