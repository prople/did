use prople_crypto::eddsa::keypair::KeyPair;
use prople_crypto::eddsa::pubkey::PubKey;
use prople_crypto::eddsa::signature::Signature;

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::with_cryptography::blake3::{self, Hash};

use crate::types::{DIDError, ToJCS, Validator};

pub mod integrity;
pub mod types;

use types::{ProofPurpose, DEFAULT_PROOF_CRYPTOSUITE, DEFAULT_PROOF_TYPE};

/// `Proof` is an object used to generate `DID Proof` used at `VC` and `VP`
///
/// Ref:
/// - <https://www.w3.org/TR/vc-data-model-2.0/#credentials>
/// - <https://www.w3.org/TR/vc-data-model-2.0/#proofs-signatures>
/// - <https://www.w3.org/TR/vc-data-model-2.0/#algorithms>
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(crate = "self::serde")]
pub struct Proof {
    pub id: String,

    #[serde(rename = "type")]
    pub typ: String,

    #[serde(rename = "proofPurpose")]
    pub proof_purpose: ProofPurpose,

    #[serde(rename = "proofValue")]
    pub proof_value: String,

    #[serde(rename = "verificationMethod")]
    pub verification_method: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,
}

impl Default for Proof {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            typ: "".to_string(),
            proof_purpose: ProofPurpose::Unknown,
            proof_value: String::from(""),
            verification_method: String::from(""),
            created: None,
            expires: None,
            cryptosuite: None,
        }
    }
}

impl Proof {
    pub fn new(id: String) -> Self {
        Self {
            id,
            typ: DEFAULT_PROOF_TYPE.to_string(),
            proof_purpose: ProofPurpose::Unknown,
            proof_value: String::from(""),
            verification_method: String::from(""),
            created: None,
            expires: None,
            cryptosuite: Some(DEFAULT_PROOF_CRYPTOSUITE.to_string()),
        }
    }

    pub fn typ(&mut self, proof_type: String) {
        self.typ = proof_type;
    }

    pub fn signature(&mut self, value: Value) {
        self.proof_value = value.generate()
    }

    pub fn set_signature_as_string(&mut self, sig: String) {
        self.proof_value = sig
    }

    pub fn purpose(&mut self, purpose: String) {
        self.proof_purpose = ProofPurpose::from(purpose)
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
}

/// The implementation of [`Validator`] here is to follow formal specification for the `Add Proof`
///
/// Spec: https://www.w3.org/TR/vc-data-integrity/#add-proof
impl Validator for Proof {
    fn validate(&self) -> Result<(), DIDError> {
        if self.typ.is_empty() {
            return Err(DIDError::ValidateError("missing type".to_string()));
        }

        if self.verification_method.is_empty() {
            return Err(DIDError::ValidateError(
                "missing verification method".to_string(),
            ));
        }

        match self.proof_purpose {
            ProofPurpose::Unknown => {
                Err(DIDError::ValidateError("unknown proof purpose".to_string()))
            }
            _ => Ok(()),
        }
    }
}

/// `Value` is a wrapper object of a [`Signature`]
pub struct Value {
    signature: Signature,
}

impl Value {
    pub fn new(keypair: KeyPair, message: &[u8]) -> Self {
        Self {
            signature: keypair.signature(message),
        }
    }

    pub fn from_jcs(keypair: KeyPair, tojcs: impl ToJCS) -> Result<Self, DIDError> {
        let jcs = tojcs.to_jcs()?;
        let this = Self {
            signature: keypair.signature(jcs.as_bytes()),
        };

        Ok(this)
    }

    pub fn transform(keypair: KeyPair, unsecured: impl ToJCS) -> Result<(Hash, String), DIDError> {
        let tojcs = unsecured.to_jcs().map_err(|err| match err {
            DIDError::GenerateVCError(msg) => DIDError::GenerateJSONJCSError(msg.to_string()),
            _ => {
                DIDError::GenerateJSONJCSError("unable to generate canonicalized json".to_string())
            }
        })?;

        let toblake = blake3::hash(tojcs.as_bytes());
        let value = Value::new(keypair, toblake.as_bytes());
        Ok((toblake, value.generate()))
    }

    pub fn transform_verifier(
        keypair: KeyPair,
        unsecured: impl ToJCS,
        sig: String,
    ) -> Result<bool, DIDError> {
        let (hashed, sig_generated) = Value::transform(keypair.clone(), unsecured)?;
        if sig_generated != sig {
            return Ok(false);
        }

        let public_key = keypair.pub_key();
        public_key
            .verify(hashed.as_bytes(), sig)
            .map_err(|_| DIDError::ProofInvalid)
    }

    pub fn verify_proof(
        public_key: PubKey,
        unsecured: impl ToJCS,
        sig: String,
    ) -> Result<bool, DIDError> {
        let tojcs = unsecured.to_jcs().map_err(|err| match err {
            DIDError::GenerateVCError(msg) => DIDError::GenerateJSONJCSError(msg.to_string()),
            _ => {
                DIDError::GenerateJSONJCSError("unable to generate canonicalized json".to_string())
            }
        })?;

        let hashed = blake3::hash(tojcs.as_bytes());
        public_key
            .verify(hashed.as_bytes(), sig)
            .map_err(|_| DIDError::ProofInvalid)
    }

    pub fn generate(&self) -> String {
        self.signature.to_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use prople_crypto::eddsa::types::errors::EddsaError;
    use rst_common::standard::serde_json;
    use rst_common::standard::uuid;
    use rst_common::with_cryptography::hex;

    use crate::types::ToJCS;
    use crate::verifiable::objects::{VC, VP};

    #[derive(Serialize, Deserialize)]
    #[serde(crate = "self::serde")]
    struct FakeCredentialProperties {
        pub user_agent: String,
        pub user_did: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(crate = "self::serde")]
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
        let mut vc = VC::new(String::from("id"), String::from("issuer"));
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
    fn test_generate_and_verify_vc_with_split_proof() {
        let mut vc = VC::new(String::from("id"), String::from("issuer"));
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

        let mut proof = Proof::new(uuid::Uuid::new_v4().to_string());

        let keypair = KeyPair::generate();
        let value = Value::transform(keypair.clone(), vc.clone());
        assert!(!value.is_err());

        let (_, sig) = value.unwrap();
        proof.set_signature_as_string(sig.clone());
        vc.proof(proof);

        let (vc_splitted, proof_splitted) = vc.split_proof();
        assert!(!proof_splitted.is_none());

        let verified = Value::transform_verifier(keypair, vc_splitted, sig);
        assert!(!verified.is_err());
        assert!(verified.unwrap());
    }

    #[test]
    fn test_generate_and_verify_vc_with_split_proof_invalid() {
        let mut vc = VC::new(String::from("id"), String::from("issuer"));
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

        let mut proof = Proof::new(uuid::Uuid::new_v4().to_string());

        let keypair = KeyPair::generate();
        let value = Value::transform(keypair.clone(), vc.clone());
        assert!(!value.is_err());

        let (_, sig) = value.unwrap();
        proof.set_signature_as_string(sig.clone());
        vc.proof(proof);

        let verified = Value::transform_verifier(keypair, vc, sig);
        assert!(!verified.is_err());
        assert!(!verified.unwrap())
    }

    #[test]
    fn test_generate_value_from_vc() {
        let mut vc = VC::new(String::from("id"), String::from("issuer"));
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
        let value = Value::from_jcs(keypair, vc);
        assert!(!value.is_err());
    }

    #[test]
    fn test_generate_and_verify_vp_proof() {
        let vc = VC::new(String::from("id"), String::from("issuer"));
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
    fn test_generate_and_verify_vp_proof_with_internal_method() {
        let vc = VC::new(String::from("id"), String::from("issuer"));
        let mut vp = VP::new();

        vp.add_context("context1".to_string());
        vp.add_context("context2".to_string());
        vp.add_type("type".to_string());
        vp.add_credential(vc);

        let keypair = KeyPair::generate();
        let mut proof = Proof::new(uuid::Uuid::new_v4().to_string());

        let value = Value::transform(keypair.clone(), vp.clone());
        assert!(!value.is_err());

        let (_, sig) = value.unwrap();
        proof.set_signature_as_string(sig.clone());
        vp.add_proof(proof.clone());

        let (vp_orig, proof_orig) = vp.split_proof();
        assert!(proof_orig.is_some());

        let verified = Value::verify_proof(keypair.pub_key(), vp_orig, proof.proof_value);
        assert!(!verified.is_err());
        assert!(verified.unwrap());
    }

    #[test]
    fn test_transform_from_vp() {
        let vc = VC::new(String::from("id"), String::from("issuer"));
        let mut vp = VP::new();

        vp.add_context("context1".to_string());
        vp.add_context("context2".to_string());
        vp.add_type("type".to_string());
        vp.add_credential(vc);

        let keypair = KeyPair::generate();
        let try_transformed = Value::transform(keypair.clone(), vp);
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
        let mut vc = VC::new(String::from("id"), String::from("issuer"));
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
        let try_transformed = Value::transform(keypair.clone(), vc);
        assert!(!try_transformed.is_err());

        let transformed = try_transformed.unwrap();
        let hashed = transformed.clone().0;
        let signature = transformed.clone().1;

        let pubkey = keypair.clone().pub_key();
        let try_verify_value = pubkey.verify(hashed.clone().as_bytes(), signature.clone());
        assert!(!try_verify_value.is_err());
    }
}
