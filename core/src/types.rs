//! `types` contains all of public base types used on this crate

use rst_common::with_errors::thiserror::{self, Error};

pub type DID = String;
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
pub const CONTEXT_VC: &str = "https://www.w3.org/2018/credentials/#VerifiableCredential";

pub const VERIFICATION_TYPE_ED25519: &str = "Ed25519VerificationKey2020";
pub const VERIFICATION_TYPE_X25519: &str = "X25519KeyAgreementKey2020";

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

    #[error("error hashlink: {0}")]
    HashLinkError(String),

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
}

/// `ToJSON` is a simple trait used to any objects that want to conver it's properties
/// to JSON encoding format
pub trait ToJSON {
    fn to_json(&self) -> Result<String, DIDError>;
}

/// `ToJCS` is a trait used that indicate an object that should be
/// able to convert to `JCS (JSON Canonicalization Scheme)`
///
/// Ref: <https://www.rfc-editor.org/rfc/rfc8785>
pub trait ToJCS {
    fn to_jcs(&self) -> Result<String, DIDError>;
}

/// `Validator` is a simple trait used to any objects that need to [`Validator::validate`]
pub trait Validator {
    fn validate(&self) -> Result<(), DIDError>;
}
