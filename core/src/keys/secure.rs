use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use prople_crypto::keysecure::KeySecure;

use crate::types::{DIDError, ToJSON};

/// `Error` defined for specific this module error types
#[derive(Debug)]
pub enum Error {
    BuildKeySecureError,
    BuildIdentityPrivateKeysError,
    BuildJSONError,
    StorageError,
}

/// `KeySecureBuilder` is a trait that should be implemented by any objects
/// that need to save it's properties and structure into [`KeySecure`] format
pub trait KeySecureBuilder {
    fn build_keysecure(&self, password: String) -> Result<KeySecure, Error>;
}

/// `IdentityPrivateKeyPairsBuilder` is a trait that implemented to build privat ekeys
pub trait IdentityPrivateKeyPairsBuilder {
    fn build_private_keys(&self, password: String) -> Result<IdentityPrivateKeyPairs, Error>;
}

/// `PrivateKeyPairs` used to generate the `verification` and `aggrement`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct PrivateKeyPairs {
    pub verification: KeySecure,
    pub aggrement: KeySecure,
}

/// `IdentityPrivateKeyPairs` used to specific identity object, it is different with the `Identity` object
///
/// This object used to as an object that will be saved to [`KeySecure`] format
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl ToJSON for IdentityPrivateKeyPairs {
    fn to_json(&self) -> Result<String, crate::types::DIDError> {
        serde_json::to_string(self).map_err(|err| DIDError::GenerateJSONError(err.to_string()))
    }
}
