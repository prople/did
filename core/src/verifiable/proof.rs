use prople_crypto::EDDSA::{KeyPair, Signature};
use rst_common::standard::serde::{Deserialize, Serialize};
use rst_common::with_cryptography::blake3::{self, Hash};

use crate::types::Error;
use crate::verifiable::types::ToJCS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    id: String,

    #[serde(rename = "type")]
    typ: String,

    #[serde(rename = "proofPurpose")]
    proof_purpose: String,

    #[serde(rename = "proofValue")]
    proof_value: String,

    #[serde(rename = "verificationMethod")]
    verification_method: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    cryptosuite: Option<String>,
}

impl Proof {
    pub fn new(id: String) -> Self {
        Self {
            id,
            typ: String::from(""),
            proof_purpose: String::from(""),
            proof_value: String::from(""),
            verification_method: String::from(""),
            created: None,
            expires: None,
            nonce: None,
            cryptosuite: None,
        }
    }

    pub fn signature(&mut self, value: Value) {
        self.proof_value = value.generate()
    }

    pub fn purpose(&mut self, purpose: String) {
        self.proof_purpose = purpose
    }

    pub fn method(&mut self, method: String) {
        self.verification_method = method
    }

    pub fn cryptosuite(&mut self, suite: String) {
        self.cryptosuite = Some(suite)
    }

    pub fn created(&mut self, created: String) {
        self.created = Some(created)
    }

    pub fn expires(&mut self, expires: String) {
        self.expires = Some(expires)
    }

    pub fn nonce(&mut self, nonce: String) {
        self.nonce = Some(nonce)
    }
}

pub struct Value {
    signature: Signature,
}

impl Value {
    pub fn new(keypair: KeyPair, message: &[u8]) -> Self {
        Self {
            signature: keypair.signature(message),
        }
    }

    pub fn transform(keypair: KeyPair, unsecured: Box<dyn ToJCS>) -> Result<(Hash, String), Error> {
        let tojcs = unsecured.to_jcs().map_err(|err| match err {
            Error::GenerateVCError(msg) => Error::GenerateJSONJCSError(msg.to_string()),
            _ => Error::GenerateJSONJCSError("unable to generate canonicalized json".to_string()),
        })?;

        let toblake = blake3::hash(tojcs.as_bytes());
        let value = Value::new(keypair, toblake.as_bytes());
        Ok((toblake, value.generate()))
    }

    pub fn generate(&self) -> String {
        self.signature.to_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifiable::objects::{VC, VP};
    use crate::verifiable::types::ToJCS;
    use rst_common::with_cryptography::hex;
    use prople_crypto::errors::EddsaError;

    #[derive(Serialize, Deserialize)]
    struct FakeCredentialProperties {
        pub user_agent: String,
        pub user_did: String,
    }

    #[derive(Serialize, Deserialize)]
    struct FakeCredentialSubject {
        id: String,
        connection: FakeCredentialProperties,
    }

    #[test]
    fn test_generate_and_verify_proof_value() {
        let orig_message = b"hello world";
        let hashed_message = blake3::hash(orig_message);

        let keypair = KeyPair::generate();
        let value = Value::new(keypair.clone(), hashed_message.clone().as_bytes());
        let proof_value = value.generate();

        let pubkey = keypair.clone().pub_key();
        let try_verify_value =
            pubkey.verify(hashed_message.clone().as_bytes(), proof_value.clone());
        assert!(!try_verify_value.is_err());
        assert!(try_verify_value.unwrap());
    }

    #[test]
    fn test_generate_mismatch_proof_value() {
        let orig_message = b"hello world";
        let hashed_message = blake3::hash(orig_message);

        let keypair = KeyPair::generate();
        let pubkey = keypair.clone().pub_key();

        let invalid_hex = hex::encode("invalid");
        let try_verify_value = pubkey.verify(hashed_message.clone().as_bytes(), invalid_hex);

        assert!(try_verify_value.is_err());
        assert!(matches!(
            try_verify_value,
            Err(EddsaError::InvalidSignatureError(_))
        ))
    }

    #[test]
    fn test_generate_and_verify_vc_proof() {
        let mut vc = VC::new(String::from("id"));
        vc.add_context(String::from("context1"));
        vc.add_context(String::from("context2"));
        vc.add_type(String::from("VerifiableCredential"));

        let credential_props = FakeCredentialProperties {
            user_agent: String::from("test_agent"),
            user_did: String::from("test_did"),
        };

        let credential = FakeCredentialSubject {
            id: String::from("id"),
            connection: credential_props,
        };

        let credential_value = serde_json::to_value(credential);
        assert!(!credential_value.is_err());

        vc.set_credential(credential_value.unwrap());
        let json_str = vc.to_jcs();
        assert!(!json_str.is_err());

        let vc_jcs = json_str.unwrap();
        let keypair = KeyPair::generate();
        let value = Value::new(keypair.clone(), vc_jcs.clone().as_bytes());

        let proof_value = value.generate();

        let pubkey = keypair.clone().pub_key();
        let try_verify_value = pubkey.verify(vc_jcs.clone().as_bytes(), proof_value.clone());
        assert!(!try_verify_value.is_err());
        assert!(try_verify_value.unwrap());
    }

    #[test]
    fn test_generate_and_verify_vp_proof() {
        let vc = VC::new("id1".to_string());
        let mut vp = VP::new();

        vp.add_context("context1".to_string());
        vp.add_context("context2".to_string());
        vp.add_type("type".to_string());
        vp.add_credential(vc);

        let try_json = vp.to_jcs();
        assert!(!try_json.is_err());

        let vp_jcs = try_json.unwrap();
        let keypair = KeyPair::generate();
        let value = Value::new(keypair.clone(), vp_jcs.clone().as_bytes());

        let proof_value = value.generate();

        let pubkey = keypair.clone().pub_key();
        let try_verify_value = pubkey.verify(vp_jcs.clone().as_bytes(), proof_value.clone());
        assert!(!try_verify_value.is_err());
        assert!(try_verify_value.unwrap());
    }

    #[test]
    fn test_transform_from_vp() {
        let vc = VC::new("id1".to_string());
        let mut vp = VP::new();

        vp.add_context("context1".to_string());
        vp.add_context("context2".to_string());
        vp.add_type("type".to_string());
        vp.add_credential(vc);

        let keypair = KeyPair::generate();
        let try_transformed = Value::transform(keypair.clone(), Box::new(vp));
        assert!(!try_transformed.is_err());

        let transformed = try_transformed.unwrap();
        let hashed = transformed.clone().0;
        let signature = transformed.clone().1;

        let pubkey = keypair.clone().pub_key();
        let try_verify_value = pubkey.verify(hashed.clone().as_bytes(), signature.clone());
        assert!(!try_verify_value.is_err());
    }

    #[test]
    fn test_transform_from_vc() {
        let mut vc = VC::new(String::from("id"));
        vc.add_context(String::from("context1"));
        vc.add_context(String::from("context2"));
        vc.add_type(String::from("VerifiableCredential"));

        let credential_props = FakeCredentialProperties {
            user_agent: String::from("test_agent"),
            user_did: String::from("test_did"),
        };

        let credential = FakeCredentialSubject {
            id: String::from("id"),
            connection: credential_props,
        };

        let credential_value = serde_json::to_value(credential);
        assert!(!credential_value.is_err());

        vc.set_credential(credential_value.unwrap());

        let keypair = KeyPair::generate();
        let try_transformed = Value::transform(keypair.clone(), Box::new(vc));
        assert!(!try_transformed.is_err());

        let transformed = try_transformed.unwrap();
        let hashed = transformed.clone().0;
        let signature = transformed.clone().1;

        let pubkey = keypair.clone().pub_key();
        let try_verify_value = pubkey.verify(hashed.clone().as_bytes(), signature.clone());
        assert!(!try_verify_value.is_err());
    }
}
