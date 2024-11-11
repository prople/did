use std::fmt::Debug;

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::with_errors::thiserror::{self, Error};

use super::Proof;
use crate::types::{ToJCS, ToJSON, Validator};

/// DEFAULT_PROOF_CRYPTOSUITE is an identifier used to verify the proof
///
/// Ref: https://www.w3.org/TR/vc-data-integrity/#proofs
pub const DEFAULT_PROOF_CRYPTOSUITE: &str = "eddsa-jcs-2022";

/// DEFAULT_PROOF_TYPE is a specific type of proof
///
/// Possible values:
/// - DataIntegrityProof (by default we're using this type)
/// - Ed25519Signature2020
///
/// Ref: https://www.w3.org/TR/vc-data-integrity/#proofs
pub const DEFAULT_PROOF_TYPE: &str = "DataIntegrityProof";

/// ProofPurpose used to represent the purposes of proof itself
///
/// Spec: https://www.w3.org/TR/vc-data-integrity/#data-model
/// Spec: https://www.w3.org/TR/vc-data-integrity/#proof-purposes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(untagged)]
pub enum ProofPurpose {
    #[serde(rename = "assertionMethod")]
    AssertionMethod,

    #[serde(rename = "authentication")]
    Authentication,

    #[serde(rename = "keyAgreement")]
    KeyAgreement,

    #[serde(rename = "capabilityDelegation")]
    CapabilityDelegation,

    #[serde(rename = "capabilityInvocation")]
    CapabilityInvocation,

    #[serde(rename = "unknown")]
    Unknown,
}

impl ToString for ProofPurpose {
    fn to_string(&self) -> String {
        match self {
            Self::AssertionMethod => "assertionMethod".to_string(),
            Self::Authentication => "authentication".to_string(),
            Self::KeyAgreement => "keyAgreement".to_string(),
            Self::CapabilityDelegation => "capabilityDelegation".to_string(),
            Self::CapabilityInvocation => "capabilityInvocation".to_string(),
            Self::Unknown => "unknown".to_string(),
        }
    }
}

impl From<String> for ProofPurpose {
    fn from(value: String) -> Self {
        match value.as_str() {
            "assertionMethod" => Self::AssertionMethod,
            "authentication" => Self::Authentication,
            "keyAgreement" => Self::KeyAgreement,
            "capabilityDelegation" => Self::CapabilityDelegation,
            "capabilityInvocation" => Self::CapabilityInvocation,
            _ => Self::Unknown,
        }
    }
}

/// ProofError provides specific custom error types for the proof processes
///
/// It also follows the formal specification error types
///
/// Ref: https://www.w3.org/TR/vc-data-integrity/#processing-errors
#[derive(Debug, Clone, Error)]
pub enum ProofError {
    #[error("proof generation error: {0}")]
    ProofGenerationError(String),

    #[error("proof verification error: {0}")]
    ProofVerificationError(String),

    #[error("proof transformation error: {0}")]
    ProofTransformationError(String),

    #[error("invalid domain error: {0}")]
    InvalidDomainError(String),

    #[error("invalid challenge error: {0}")]
    InvalidChallengeError(String),
}

/// ProofOptionsValidator used to validate primary fields for the proof_options
/// that contains two things: proof_type & proof_cryptosuite
///
/// This trait is a main trait for all proof options and other necessary traits
/// should be inherit this trait, such as for the [`ProofConfigValidator`]
pub trait ProofOptionsValidator {
    fn validate_type(&self) -> Result<(), ProofError>;
    fn validate_cryptosuite(&self) -> Result<(), ProofError>;
}

/// ProofConfigValidator is a trait built by following algorithm defined at its
/// formal spec to create proof configuration
///
/// This trait must be implemented by [`Proof`] object
///
/// Spec: https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
pub trait ProofConfigValidator: ProofOptionsValidator {
    fn validate_created(&self) -> Result<(), ProofError>;
}

/// Proofable is a trait behavior that must be implemented by any objects
/// that need a [`Proof`] on its properties
///
/// The behavior actually is simple, it only needs to implemenent these two primary
/// methods to adding and split the proof. The split proof itself means, the object
/// must be able to remove or emptied the proof property from its object fields
///
/// This trait also need to inherit behavior from the [`ToJCS`], to make sure that the
/// implementer object already implement the JCS trait. It means that the implementer object
/// should be serializable or able to convert it self into JCS format in string
pub trait Proofable: ToJSON + ToJCS + Validator {
    fn get_proof(&self) -> Option<Proof>;
    fn get_proof_purpose(&self) -> ProofPurpose;
    fn setup_proof(&self, proof: Proof) -> Self;
    fn split_proof(&self) -> (Self, Option<Proof>);
    fn parse_json_bytes(bytes: Vec<u8>) -> Result<Self, ProofError>;
}

/// CryptosuiteVerificationResult used as a result of `verifyProof`
///
/// The formal specification only tells that the required `document` is a map that represents
/// the secured data document which contains one or more proof values
///
/// Spec: https://www.w3.org/TR/vc-data-integrity/#dfn-secured-data-document
/// Spec: https://www.w3.org/TR/vc-data-integrity/#dfn-cryptosuite-verification-result
#[derive(Debug, Clone)]
pub struct CryptoSuiteVerificationResult<T>
where
    T: Clone + Debug + Serialize,
{
    pub verified: bool,
    pub document: Option<T>,
}

pub trait CryptoSuiteBuilder<T>: Clone
where
    T: Proofable,
{
    type ProofOptions: Clone + Debug;

    fn create_proof(
        &self,
        unsecurd_document: T,
        opts: Option<Self::ProofOptions>,
    ) -> Result<Proof, ProofError>;

    fn verify_proof(
        &self,
        secured_document: T,
    ) -> Result<CryptoSuiteVerificationResult<T>, ProofError>;
}

pub trait Hasher: Clone {
    fn hash(&self) -> Result<Vec<u8>, ProofError>;
}
