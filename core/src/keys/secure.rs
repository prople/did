use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use prople_crypto::KeySecure::KeySecure;

use crate::types::{DIDError, ToJSON};

#[derive(Debug)]
pub enum Error {
    BuildKeySecureError,
    BuildIdentityPrivateKeysError,
    BuildJSONError,
    StorageError,
}

pub trait KeySecureBuilder {
    fn build_keysecure(&self, password: String) -> Result<KeySecure, Error>;
}

pub trait IdentityPrivateKeyPairsBuilder {
    fn build_private_keys(&self, password: String) -> Result<IdentityPrivateKeyPairs, Error>;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct PrivateKeyPairs {
    pub verification: KeySecure,
    pub aggrement: KeySecure,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct IdentityPrivateKeyPairs {
    pub identity: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<PrivateKeyPairs>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion: Option<PrivateKeyPairs>,
}

impl IdentityPrivateKeyPairs {
    pub fn new(identity: String) -> Self {
        Self {
            identity,
            authentication: None,
            assertion: None,
        }
    }

    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::BuildJSONError)
    }
}

impl ToJSON for IdentityPrivateKeyPairs {
    fn to_json(&self) -> Result<String, crate::types::DIDError> {        
        serde_json::to_string(self).map_err(|err| DIDError::GenerateJSONError(err.to_string()))
    }
}