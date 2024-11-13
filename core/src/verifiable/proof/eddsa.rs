use prople_crypto::eddsa::keypair::KeyPair;

use super::types::{CryptoSuiteBuilder, CryptoSuiteVerificationResult, ProofError, Proofable};
use super::Proof;

use super::config::generate_proof_config;
use super::hash::generate_hash;
use super::serialize::serialize_hashed_data;
use super::transform::transform_document;

/// EddsaJcs2022 is an implementation of [`CryptoSuiteBuilder`] trait abstraction, that focus only for the
/// cryptosuite type of `eddsa-jcs-2022`
#[derive(Clone, Debug)]
pub struct EddsaJcs2022 {
    keypair: KeyPair,
}

impl EddsaJcs2022 {
    pub fn new(keypair: KeyPair) -> Self {
        Self { keypair }
    }
}

impl<T> CryptoSuiteBuilder<T> for EddsaJcs2022
where
    T: Proofable,
{
    /// Formal spec: https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
    fn create_proof(&self, unsecured_document: T, opts: Proof) -> Result<Proof, ProofError> {
        let mut cloned_proof = opts.clone();

        let proof_config = generate_proof_config(opts.clone())?;
        let transformed_data = transform_document(unsecured_document, opts.clone())?;
        let hashed_data = generate_hash(transformed_data, proof_config)?;
        let proof_bytes = serialize_hashed_data(hashed_data, self.keypair.to_owned());
        let proof_encoded = proof_bytes.encode();

        cloned_proof.set_signature_as_string(proof_encoded.get());
        Ok(cloned_proof)
    }

    fn verify_proof(
        &self,
        _secured_document: T,
    ) -> Result<CryptoSuiteVerificationResult<T>, ProofError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Debug;
    use std::fmt::Formatter;
    use std::fmt::Result as FmtResult;

    use mockall::mock;
    use rst_common::standard::chrono::Utc;
    use rst_common::standard::serde::{self, Deserialize, Serialize};

    use crate::types::{DIDError, JSONValue, ToJCS, ToJSON, Validator};
    use crate::verifiable::proof::types::{ProofPurpose, Proofable};
    use crate::verifiable::proof::types::{DEFAULT_PROOF_CRYPTOSUITE, DEFAULT_PROOF_TYPE};

    #[derive(Serialize, Deserialize)]
    #[serde(crate = "self::serde")]
    struct WrapperProofable;

    mock!(
        FakeProofable {
            fn private_deserialize(deserializable: Result<WrapperProofable, ()>) -> Self;
            fn private_serialize(&self) -> WrapperProofable;
        }

        impl Clone for FakeProofable {
            fn clone(&self) -> Self;
        }

        impl Debug for FakeProofable {
            fn fmt<'a>(&self, f: &mut Formatter<'a>) -> FmtResult;
        }

        impl ToJCS for FakeProofable {
            fn to_jcs(&self) -> Result<String, DIDError>;
        }

        impl ToJSON for FakeProofable {
            fn to_json(&self) -> Result<JSONValue, DIDError>;
        }

        impl Validator for FakeProofable {
            fn validate(&self) -> Result<(), DIDError>;
        }

        impl Proofable for FakeProofable {
            fn get_proof(&self) -> Option<Proof>;
            fn get_proof_purpose(&self) -> ProofPurpose;
            fn setup_proof(&self, proof: Proof) -> Self;
            fn split_proof(&self) -> (Self, Option<Proof>);
            fn parse_json_bytes(bytes: Vec<u8>) -> Result<Self, ProofError>;
        }
    );

    impl Serialize for MockFakeProofable {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.private_serialize().serialize(serializer)
        }
    }

    impl<'a> Deserialize<'a> for MockFakeProofable {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'a>,
        {
            let serializable = WrapperProofable::deserialize(deserializer).map_err(|_| ());
            Ok(MockFakeProofable::private_deserialize(serializable))
        }
    }

    mod test_create_proof {
        use super::*;

        mod expect_errors {
            use super::*;

            #[test]
            fn test_error_proof_config() {
                let proof = Proof::default();
                let mock_doc = MockFakeProofable::new();
                let keypair = KeyPair::generate();

                let eddsa_di = EddsaJcs2022::new(keypair);
                let try_create_proof = eddsa_di.create_proof(mock_doc, proof);

                assert!(try_create_proof.is_err());
                assert!(matches!(
                    try_create_proof.clone().unwrap_err(),
                    ProofError::ProofGenerationError(_)
                ));

                let err_msg = match try_create_proof.unwrap_err() {
                    ProofError::ProofGenerationError(msg) => msg,
                    _ => panic!("unknown error"),
                };

                assert!(err_msg.contains("invalid proof type"))
            }

            #[test]
            fn test_error_transform_document() {
                let mut proof = Proof::default();
                proof.typ(DEFAULT_PROOF_TYPE.to_string());
                proof.cryptosuite(DEFAULT_PROOF_CRYPTOSUITE.to_string());
                proof.created(Utc::now().to_string());

                let keypair = KeyPair::generate();

                let mut mock_doc = MockFakeProofable::new();
                mock_doc
                    .expect_to_jcs()
                    .once()
                    .returning(|| Err(DIDError::GenerateJSONJCSError("error jcs".to_string())));

                let eddsa_di = EddsaJcs2022::new(keypair);
                let try_create_proof = eddsa_di.create_proof(mock_doc, proof);

                assert!(try_create_proof.is_err());
                assert!(matches!(
                    try_create_proof.clone().unwrap_err(),
                    ProofError::ProofGenerationError(_)
                ));

                let err_msg = match try_create_proof.unwrap_err() {
                    ProofError::ProofGenerationError(msg) => msg,
                    _ => panic!("unknown error"),
                };

                assert!(err_msg.contains("error jcs"))
            }
        }

        mod expect_success {
            use super::*;

            #[test]
            fn test_create_proof_success() {
                let mut proof = Proof::default();
                proof.typ(DEFAULT_PROOF_TYPE.to_string());
                proof.cryptosuite(DEFAULT_PROOF_CRYPTOSUITE.to_string());
                proof.created(Utc::now().to_string());

                let mut mock_doc = MockFakeProofable::new();
                mock_doc
                    .expect_to_jcs()
                    .once()
                    .returning(|| Ok("fake-jcs".to_string()));

                let keypair = KeyPair::generate();

                let eddsa_di = EddsaJcs2022::new(keypair);
                let try_create_proof = eddsa_di.create_proof(mock_doc, proof);

                assert!(try_create_proof.is_ok());

                let proof_output = try_create_proof.unwrap();
                assert!(!proof_output.proof_value.is_empty());
            }
        }
    }
}
