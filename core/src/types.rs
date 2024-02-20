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

pub const VERIFICATION_TYPE_ED25519: &str = "Ed25519VerificationKey2020";
pub const VERIFICATION_TYPE_X25519: &str = "X25519KeyAgreementKey2020";

pub const STORAGE_COLUMN_DID: &str = "_did";
pub const STORAGE_COLUMN_DID_DOC: &str = "_did_doc";
pub const STORAGE_COLUMN_DID_KEY_SECURES: &str = "_did_key_secures";

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidDID,
    GenerateDocError(String),
    GenerateJSONError(String),
    GenerateJSONJCSError(String),
    GenerateVCError(String),
    BuildProofError(String),
    BuildAuthError,
    BuildAssertionError,
    BuildDocError,
    SaveSecureKeysError,
}
