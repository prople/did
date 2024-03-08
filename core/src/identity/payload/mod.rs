//! `payload` module contain a [`Payload`] and [`Resolver`] objects including
//! hash and signature helper's functions
//! 
//! This module used to generate this kind of data
//! ```json
//! {
//!   "payload": {
//!     "account": {
//!       "key": "<generated_hash_blake3>",
//!       "version-hash": "<sha384>"
//!     },
//!     "resolver": {
//!       "address": {
//!         "type": "pair", // or peer
//!         "value": "<multiaddress_format>"
//!       },
//!       "allowed_did": [{
//!         "access_token": "<token>",
//!         "did": "<base58_encoded_did_content>"
//!       }], // list of allowed DID account who can send the message      
//!     },
//!     "created_at": "<rfc3339>"
//!   },
//!   "hash": "<sha256_of_payload>",
//!   "signature": "<signature_of_payload>"
//! }
//! ``` 
//! 
//! This kind of data will be encoded using `multibase` through `Base58btc` format then will be used 
//! as DID account key
use rst_common::standard::chrono::Utc;
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::with_cryptography::hex;
use rst_common::with_cryptography::sha2::{Digest, Sha384};

pub mod account;
pub mod resolver;

use account::Account;
use resolver::Resolver;

use crate::account::Account as AccountCore;
use crate::types::{DIDError, ToJSON};

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct Payload {
    pub account: Account,
    pub resolver: Resolver,
    pub created_at: String,
}

impl Payload {
    pub fn new(account: Account, resolver: Resolver) -> Self {
        Self {
            account,
            resolver,
            created_at: Utc::now().to_rfc3339(),
        }
    }
}

impl ToJSON for Payload {
    fn to_json(&self) -> Result<String, DIDError> {
        serde_json::to_string(self).map_err(|err| DIDError::GenerateJSONError(err.to_string()))
    }
}

/// `hash_payload` used to generate hashed value of given [`Payload`] using `Sha384` algorithm
pub fn hash_payload(payload: Payload) -> Result<String, DIDError> {
    let payload_to_json = payload
        .to_json()
        .map_err(|err| DIDError::BuildPayloadError(err.to_string()))?;

    let mut sha384_hasher = Sha384::new();
    sha384_hasher.update(payload_to_json.as_bytes());

    let hashed = sha384_hasher.finalize();
    Ok(hex::encode(hashed))
}

/// `sign_payload` will create a signature the [`Payload`] using entity's private key
pub fn sign_payload(payload: Payload, account: AccountCore) -> Result<String, DIDError> {
    let payload_to_json = payload
        .to_json()
        .map_err(|err| DIDError::BuildPayloadError(err.to_string()))?;

    let signature = account.signature(payload_to_json.as_bytes());
    Ok(signature.to_hex())
}
