//! `doc` module take responsibility to generate the `DID Documents`
//!
//! The data structure will follow the standard from `W3C DID CORE`
//! Ref: <https://www.w3.org/TR/did-core/#core-properties>
//!
//! Simple document:
//! ```json
//! {
//!     "@context": [
//!       "https://www.w3.org/ns/did/v1",
//!       "https://w3id.org/security/suites/ed25519-2020/v1"
//!     ]
//!     "id": "did:example:123456789abcdefghi",
//!     "authentication": [{
//!       "id": "did:example:123456789abcdefghi#keys-1",
//!       "type": "Ed25519VerificationKey2020",
//!       "controller": "did:example:123456789abcdefghi",
//!       "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
//!     }]
//!   }
//! ````
mod doc;

pub mod types {
    use super::*;

    pub use doc::{Doc, Primary, PublicKeyDecoded};

    pub trait ToDoc {
        fn to_doc(&self) -> Doc;
    }
}
