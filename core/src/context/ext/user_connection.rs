use crate::types::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserConnectionCredentialProperties {
    pub user_agent_address: String,
    pub user_did: String,
}

impl Default for UserConnectionCredentialProperties {
    fn default() -> Self {
        Self {
            user_agent_address: String::from("https://schema.org/identifier"),
            user_did: String::from("https://www.w3.org/2018/credentials/#VerifiableCredential"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
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

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct UserConnectionCredential {
    pub user_connection_credential: UserConnectionCredentialContext,
}

impl UserConnectionCredential {
    pub fn new(context: UserConnectionCredentialContext) -> Self {
        Self {
            user_connection_credential: context,
        }
    }

    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|err| Error::GenerateJSONError(err.to_string()))
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
