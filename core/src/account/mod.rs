//! `account` is main module used to generate an [`Account`]
//!
//! The `Account` itself actually is a JSON data in string format.
//! The JSON will has properties like this
//!
//! ```json
//! {
//!     "payload": {
//!       "account": {
//!         "key": "<generated_hash_blake3>",
//!         "version-hash": "<sha384>"
//!       },
//!       "resolver": {
//!         "address": {
//!           "type": "pair", // or peer
//!           "value": "<multiaddress_format>"
//!         },
//!         "allowed_did": [{
//!           "access_token": "<token>",
//!           "did": "<base58_encoded_did_content>"
//!         }], // list of allowed DID account who can send the message      
//!       },
//!       "created_at": "<rfc3339>"
//!     },
//!     "hash": "<sha256_of_payload>",
//!     "signature": "<signature_of_payload>"
//!   }
//! ```
//!
//! This JSON data properties designed to be self-describe, which means, by decode
//! this JSON, user will be get complete information including for it's account verification
//! because it also has two security properties which are `hash` and `signature`  
mod account;

pub use account::Account;
