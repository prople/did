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
use multibase;

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use prople_crypto::ecdh::pubkey::PublicKey as ECDHPubKey;
use prople_crypto::eddsa::pubkey::PubKey as EdDSAPubKey;
use prople_crypto::types::ByteHex;

use crate::types::*;

pub trait ToDoc {
    fn to_doc(&self) -> Doc;
}

#[derive(Debug)]
pub enum PublicKeyDecoded {
    EdDSA(EdDSAPubKey),
    ECDH(ECDHPubKey),
}

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

impl Primary {
    pub fn decode_pub_key(&self) -> Result<PublicKeyDecoded, DIDError> {
        match self.verification_type.to_owned().as_str() {
            VERIFICATION_TYPE_ED25519 => {
                let public_key = self.decode_pub_key_verificaiton()?;
                Ok(PublicKeyDecoded::EdDSA(public_key))
            }
            VERIFICATION_TYPE_X25519 => {
                let public_key = self.decode_pub_key_agreement()?;
                Ok(PublicKeyDecoded::ECDH(public_key))
            }
            _ => Err(DIDError::DecodePubKeyError(
                "unknown verification type".to_string(),
            )),
        }
    }

    fn decode_pub_key_verificaiton(&self) -> Result<EdDSAPubKey, DIDError> {
        let (_, pubkey_bytes) = multibase::decode(&self.multibase).map_err(|_| {
            DIDError::DecodePubKeyError(
                "unable to decode encoded multibase to EDDSA public key".to_string(),
            )
        })?;

        let pubkey_string = String::from_utf8(pubkey_bytes).map_err(|_| {
            DIDError::DecodePubKeyError("unable convert public key to string".to_string())
        })?;

        let pubkey = EdDSAPubKey::from_hex(ByteHex::from(pubkey_string))
            .map_err(|_| DIDError::DecodePubKeyError("unable to restore public key".to_string()))?;
        Ok(pubkey)
    }

    fn decode_pub_key_agreement(&self) -> Result<ECDHPubKey, DIDError> {
        let (_, pubkey_bytes) = multibase::decode(&self.multibase).map_err(|_| {
            DIDError::DecodePubKeyError(
                "unable to decode encoded multibase to ECDH public key".to_string(),
            )
        })?;

        let pubkey_string = String::from_utf8(pubkey_bytes).map_err(|_| {
            DIDError::DecodePubKeyError("unable convert public key to string".to_string())
        })?;

        let pubkey = ECDHPubKey::from_hex(ByteHex::from(pubkey_string))
            .map_err(|_| DIDError::DecodePubKeyError("unable to restore public key".to_string()))?;

        Ok(pubkey)
    }
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

        if self.assertion.is_none() {
            self.assertion = Some(vec![assertion.clone()]);
        }

        self
    }

    pub fn add_authentication(&mut self, auth: Primary) -> &mut Self {
        if let Some(ref mut authentication) = self.authentication {
            authentication.push(auth.clone())
        }

        if self.authentication.is_none() {
            self.authentication = Some(vec![auth.clone()]);
        }

        self
    }

    pub fn add_cap_delegate(&mut self, delegate: Primary) -> &mut Self {
        if let Some(ref mut cap_delegate) = self.cap_delegate {
            cap_delegate.push(delegate.clone())
        }

        if self.cap_delegate.is_none() {
            self.cap_delegate = Some(vec![delegate.clone()]);
        }

        self
    }

    pub fn add_cap_invoke(&mut self, invoke: Primary) -> &mut Self {
        if let Some(ref mut cap_invoke) = self.cap_invoke {
            cap_invoke.push(invoke.clone())
        }

        if self.cap_invoke.is_none() {
            self.cap_invoke = Some(vec![invoke.clone()]);
        }

        self
    }
}

impl ToJSON for Doc {
    fn to_json(&self) -> Result<JSONValue, DIDError> {
        let jsonstr = serde_json::to_string(self)
            .map_err(|err| DIDError::GenerateDocError(err.to_string()))?;
        Ok(JSONValue::from(jsonstr))
    }
}

impl Validator for Doc {
    fn validate(&self) -> Result<(), DIDError> {
        if self.id.is_empty() {
            return Err(DIDError::ValidateError("[doc]: missing id".to_string()));
        }

        if self.context.is_empty() {
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

    use prople_crypto::eddsa::keypair::KeyPair;

    use crate::keys::{AgreementKey, VerificationKey};

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

        let fromjson: Result<Doc, _> =
            serde_json::from_str(json.as_ref().unwrap().to_string().as_str());
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

    #[test]
    fn test_decode_public_key_eddsa() {
        let key = VerificationKey::new();
        let pairs = key.generate();

        let primary = Primary {
            id: "id".to_string(),
            controller: "controller".to_string(),
            verification_type: VERIFICATION_TYPE_ED25519.to_string(),
            multibase: pairs.clone().pub_key,
        };

        let decoded = primary.decode_pub_key();
        assert!(!decoded.is_err());

        let decoded_pub_key = decoded.unwrap();
        assert!(matches!(decoded_pub_key, PublicKeyDecoded::EdDSA(_)));

        match decoded_pub_key {
            PublicKeyDecoded::EdDSA(pubkey) => {
                let privkey_pem = pairs.priv_key.to_pem().unwrap();
                let keypair_regenerated = KeyPair::from_pem(privkey_pem).unwrap();
                let pubkey_regenerated = keypair_regenerated.pub_key();
                assert_eq!(pubkey.to_hex(), pubkey_regenerated.to_hex())
            }
            _ => panic!("unknown"),
        }
    }

    #[test]
    fn test_decode_public_key_ecdh() {
        let key = AgreementKey::new();
        let pairs = key.generate();

        let primary = Primary {
            id: "id".to_string(),
            controller: "controller".to_string(),
            verification_type: VERIFICATION_TYPE_X25519.to_string(),
            multibase: pairs.clone().pub_key,
        };

        let decoded = primary.decode_pub_key();
        assert!(!decoded.is_err());

        let decoded_pub_key = decoded.unwrap();
        assert!(matches!(decoded_pub_key, PublicKeyDecoded::ECDH(_)));

        match decoded_pub_key {
            PublicKeyDecoded::ECDH(pubkey) => {
                let keypair = pairs.priv_key;
                assert_eq!(keypair.pub_key().to_hex(), pubkey.to_hex());
            }
            _ => panic!("unknown"),
        }
    }

    #[test]
    fn test_decode_public_key_invalid_type() {
        let primary = Primary {
            id: "id".to_string(),
            controller: "controller".to_string(),
            verification_type: "unknown".to_string(),
            multibase: "".to_string(),
        };

        let decoded = primary.decode_pub_key();
        assert!(decoded.is_err());
        assert!(matches!(
            decoded.unwrap_err(),
            DIDError::DecodePubKeyError(_)
        ))
    }
}
