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

#[derive(Debug, PartialEq, Error)]
pub enum DIDError {
    #[error("invalid did")]
    InvalidDID,

    #[error("error generate DID DOC: {0}")]
    GenerateDocError(String),

    #[error("error generate JSON: {0}")]
    GenerateJSONError(String),

    #[error("error generate JCS: {0}")]
    GenerateJSONJCSError(String),

    #[error("error generate VC: {0}")]
    GenerateVCError(String),

    #[error("error build proof: {0}")]
    BuildProofError(String),

    #[error("error build auth")]
    BuildAuthError,
    
    #[error("error build assertion")]
    BuildAssertionError,
    
    #[error("error build DID DOC")]
    BuildDocError,
    
    #[error("unable to save key secure")]
    SaveSecureKeysError,
}

pub trait ToJSON {
    fn to_json(&self) -> Result<String, DIDError>;
}

pub trait ToJCS {
    fn to_jcs(&self) -> Result<String, DIDError>;
}