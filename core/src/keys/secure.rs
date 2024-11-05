use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::with_errors::thiserror::{self, Error as ThisError};

use prople_crypto::keysecure::KeySecure;

use crate::types::{DIDError, JSONValue, ToJSON};

/// `Error` defined for specific this module error types
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("keysecure error")]
    BuildKeySecureError,

    #[error("keysecure error: unable to build identity private keys")]
    BuildIdentityPrivateKeysError,

    #[error("keysecure error: unable to build JSON")]
    BuildJSONError,

    #[error("keysecure error: storage error")]
    StorageError,

    #[error("keysecure error: decrypt error: {0}")]
    DecryptError(String),
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

impl PrivateKeyPairs {
    pub fn decrypt_verification(&self, password: String) -> Result<Vec<u8>, Error> {
        let decrypted = self
            .verification
            .decrypt(password)
            .map_err(|err| Error::DecryptError(err.to_string()))?;

        Ok(decrypted)
    }

    pub fn decrypt_agreement(&self, password: String) -> Result<Vec<u8>, Error> {
        let decrypted = self
            .aggrement
            .decrypt(password)
            .map_err(|err| Error::DecryptError(err.to_string()))?;

        Ok(decrypted)
    }
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
    fn to_json(&self) -> Result<JSONValue, DIDError> {
        let jsonstr = serde_json::to_string(self)
            .map_err(|err| DIDError::GenerateJSONError(err.to_string()))?;
        Ok(JSONValue::from(jsonstr))
    }
}
