//! `types` contains all of public base types used on this crate

use std::fmt::Debug;

use rst_common::{
    standard::serde::Serialize,
    with_errors::thiserror::{self, Error},
};

pub type DIDSyntax = String;
pub type DIDController = String;
pub type DIDMultibase = String;
pub type DIDVerificationKeyType = String;
pub type DIDContext = String;

pub const DID_SYNTAX_MARK: char = ':';
pub const DID_SYNTAX_SCHEME: &str = "did";
pub const DID_SYNTAX_METHOD: &str = "prople";

pub const CONTEXT_DEFAULT: &str = "https://www.w3.org/ns/did/v1";
pub const CONTEXT_ED25519: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
pub const CONTEXT_X25519: &str = "https://w3id.org/security/suites/x25519-2020/v1";
pub const CONTEXT_VC_V2: &str = "https://www.w3.org/ns/credentials/v2";
pub const CONTEXT_VC: &str = "https://www.w3.org/2018/credentials/#VerifiableCredential";

pub const VERIFICATION_TYPE_ED25519: &str = "Ed25519VerificationKey2020";
pub const VERIFICATION_TYPE_X25519: &str = "X25519KeyAgreementKey2020";

pub const JSON_MIME_TYPE: &str = "application/json";

/// `BLAKE3_HASH_CODE` is our default used hash function
/// The code itself taken from here: https://github.com/multiformats/multicodec/blob/master/table.csv#L21
pub const BLAKE3_HASH_CODE: u64 = 0x1e;

/// `DIDError` define all possible errors that will be happened from all available components
#[derive(Debug, PartialEq, Error, Clone)]
pub enum DIDError {
    #[error("invalid did")]
    InvalidDID,

    #[error("invalid pem")]
    InvalidPEM,

    #[error("invalid keysecure: {0}")]
    InvalidKeysecure(String),

    #[error("error generate multiaddr: {0}")]
    GenerateMultiAddrError(String),

    #[error("error generate DID DOC: {0}")]
    GenerateDocError(String),

    #[error("error generate JSON: {0}")]
    GenerateJSONError(String),

    #[error("error generate JCS: {0}")]
    GenerateJSONJCSError(String),

    #[error("error generate VC: {0}")]
    GenerateVCError(String),

    #[error("error generate hashlink: {0}")]
    GenerateHashLinkError(String),

    #[error("error build proof: {0}")]
    BuildProofError(String),

    #[error("error build payload: {0}")]
    BuildPayloadError(String),

    #[error("validation error: {0}")]
    ValidateError(String),

    #[error("error decode json value: {0}")]
    DecodeJSONError(String),

    #[error("unable to get JSON from bytes: {0}")]
    InvalidJSONBytes(String),

    #[error("error decode public key: {0}")]
    DecodePubKeyError(String),

    #[error("error hashlink: {0}")]
    HashLinkError(String),

    #[error("error parse uri: {0}")]
    ParseURIError(String),

    #[error("error build auth")]
    BuildAuthError,

    #[error("error build assertion")]
    BuildAssertionError,

    #[error("error build DID uri")]
    BuildURIError,

    #[error("error build DID DOC")]
    BuildDocError,

    #[error("unable to save key secure")]
    SaveSecureKeysError,

    #[error("proof: signature invalid")]
    ProofInvalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JSONValue(String);

impl JSONValue {
    pub fn mime_type(&self) -> &str {
        JSON_MIME_TYPE
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let out = self.0.as_bytes();
        out.to_vec()
    }
}

impl From<String> for JSONValue {
    fn from(value: String) -> Self {
        JSONValue(value)
    }
}

impl From<&str> for JSONValue {
    fn from(value: &str) -> Self {
        JSONValue(value.to_string())
    }
}

impl ToString for JSONValue {
    fn to_string(&self) -> String {
        self.0.to_owned()
    }
}

impl TryFrom<Vec<u8>> for JSONValue {
    type Error = DIDError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let out =
            String::from_utf8(value).map_err(|err| DIDError::InvalidJSONBytes(err.to_string()))?;

        Ok(JSONValue(out))
    }
}

/// `ToJSON` is a simple trait used to any objects that want to conver it's properties
/// to JSON encoding format
pub trait ToJSON: Serialize + Clone + Debug {
    fn to_json(&self) -> Result<JSONValue, DIDError>;
}

/// `ToJCS` is a trait used that indicate an object that should be
/// able to convert to `JCS (JSON Canonicalization Scheme)`
///
/// Ref: <https://www.rfc-editor.org/rfc/rfc8785>
pub trait ToJCS: Serialize + Clone + Debug {
    fn to_jcs(&self) -> Result<String, DIDError>;
}

/// `Validator` is a simple trait used to any objects that need to [`Validator::validate`]
pub trait Validator {
    fn validate(&self) -> Result<(), DIDError>;
}
