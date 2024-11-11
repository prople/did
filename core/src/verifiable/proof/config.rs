use rst_common::with_cryptography::sha2::{Digest, Sha256};

use super::types::{Hasher, ProofConfigValidator, ProofError};
use crate::types::ToJCS;

#[derive(Clone, Debug)]
pub(crate) struct ProofConfig(String);

impl From<String> for ProofConfig {
    fn from(value: String) -> Self {
        ProofConfig(value)
    }
}

impl ToString for ProofConfig {
    fn to_string(&self) -> String {
        self.0.to_owned()
    }
}

impl Hasher for ProofConfig {
    fn hash(&self) -> Result<Vec<u8>, ProofError> {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());

        let hashed = hasher.finalize();
        Ok(hashed.to_vec())
    }
}

/// generate_proof_config build based on algorithm from the `eddsa-jcs-2022` from
/// its formal spec
///
/// The algorithm specific only to generate canonical config based on JCS
/// Spec: https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
pub(crate) fn generate_proof_config<T>(options: T) -> Result<ProofConfig, ProofError>
where
    T: ProofConfigValidator + ToJCS,
{
    // Let proofConfig be a clone of the options object
    let proof_config = options.clone();

    // If proofConfig.type is not set to DataIntegrityProof or proofConfig.cryptosuite is not set to eddsa-jcs-2022,
    // an error MUST be raised that SHOULD convey an error type of PROOF_GENERATION_ERROR
    let _ = proof_config.validate_type()?;
    let _ = proof_config.validate_cryptosuite()?;
    let _ = proof_config.validate_created()?;

    // Let canonicalProofConfig be the result of applying the JSON Canonicalization Scheme [RFC8785] to the proofConfig
    let canonical_proof_config = proof_config
        .to_jcs()
        .map_err(|err| ProofError::ProofGenerationError(err.to_string()))?;

    Ok(ProofConfig::from(canonical_proof_config))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Debug;
    use std::fmt::Formatter;
    use std::fmt::Result as FmtResult;

    use mockall::mock;

    use rst_common::standard::serde::Deserialize;
    use rst_common::standard::serde::{self, Serialize};

    use crate::types::{DIDError, ToJCS};
    use crate::verifiable::proof::types::ProofOptionsValidator;

    #[derive(Serialize, Deserialize)]
    #[serde(crate = "self::serde")]
    struct ProofOptions;

    mock!(
        FakeProofOptions {
            fn private_deserialize(deserializable: Result<ProofOptions, ()>) -> Self;
            fn private_serialize(&self) -> ProofOptions;
        }

        impl Clone for FakeProofOptions {
            fn clone(&self) -> Self;
        }

        impl Debug for FakeProofOptions {
            fn fmt<'a>(&self, f: &mut Formatter<'a>) -> FmtResult;
        }

        impl ToJCS for FakeProofOptions {
            fn to_jcs(&self) -> Result<String, DIDError>;
        }

        impl ProofOptionsValidator for FakeProofOptions {
            fn validate_type(&self) -> Result<(), ProofError>;
            fn validate_cryptosuite(&self) -> Result<(), ProofError>;
        }

        impl ProofConfigValidator for FakeProofOptions {
            fn validate_created(&self) -> Result<(), ProofError>;
        }
    );

    impl Serialize for MockFakeProofOptions {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.private_serialize().serialize(serializer)
        }
    }

    impl<'a> Deserialize<'a> for MockFakeProofOptions {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'a>,
        {
            let serializable = ProofOptions::deserialize(deserializer).map_err(|_| ());
            Ok(MockFakeProofOptions::private_deserialize(serializable))
        }
    }

    mod error_validations {
        use super::*;

        #[test]
        fn test_invalid_type() {
            let mut proof_options = MockFakeProofOptions::new();
            proof_options.expect_clone().returning(|| {
                let mut out = MockFakeProofOptions::new();
                out.expect_fmt()
                    .returning(|formatter| formatter.write_str("hello fmt"));

                out.expect_validate_type().once().returning(|| {
                    Err(ProofError::ProofGenerationError("invalid type".to_string()))
                });

                out
            });

            let try_proof_config = generate_proof_config(proof_options);
            assert!(try_proof_config.is_err());
            assert!(matches!(
                try_proof_config.clone().unwrap_err(),
                ProofError::ProofGenerationError(_)
            ));

            let err_msg = match try_proof_config.unwrap_err() {
                ProofError::ProofGenerationError(msg) => msg,
                _ => panic!("unknown error"),
            };

            assert!(err_msg.contains("invalid type"))
        }

        #[test]
        fn test_invalid_cryptosuite() {
            let mut proof_options = MockFakeProofOptions::new();
            proof_options.expect_clone().returning(|| {
                let mut out = MockFakeProofOptions::new();
                out.expect_fmt()
                    .returning(|formatter| formatter.write_str("hello fmt"));

                out.expect_validate_type().once().returning(|| Ok(()));

                out.expect_validate_cryptosuite().once().returning(|| {
                    Err(ProofError::ProofGenerationError(
                        "invalid cryptosuite".to_string(),
                    ))
                });

                out
            });

            let try_proof_config = generate_proof_config(proof_options);
            assert!(try_proof_config.is_err());
            assert!(matches!(
                try_proof_config.clone().unwrap_err(),
                ProofError::ProofGenerationError(_)
            ));

            let err_msg = match try_proof_config.unwrap_err() {
                ProofError::ProofGenerationError(msg) => msg,
                _ => panic!("unknown error"),
            };

            assert!(err_msg.contains("invalid cryptosuite"))
        }

        #[test]
        fn test_invalid_created() {
            let mut proof_options = MockFakeProofOptions::new();
            proof_options.expect_clone().returning(|| {
                let mut out = MockFakeProofOptions::new();
                out.expect_fmt()
                    .returning(|formatter| formatter.write_str("hello fmt"));

                out.expect_validate_type().once().returning(|| Ok(()));

                out.expect_validate_cryptosuite()
                    .once()
                    .returning(|| Ok(()));

                out.expect_validate_created().once().returning(|| {
                    Err(ProofError::ProofGenerationError(
                        "invalid created at".to_string(),
                    ))
                });
                out
            });

            let try_proof_config = generate_proof_config(proof_options);
            assert!(try_proof_config.is_err());
            assert!(matches!(
                try_proof_config.clone().unwrap_err(),
                ProofError::ProofGenerationError(_)
            ));

            let err_msg = match try_proof_config.unwrap_err() {
                ProofError::ProofGenerationError(msg) => msg,
                _ => panic!("unknown error"),
            };

            assert!(err_msg.contains("invalid created at"))
        }
    }

    mod error_jcs {
        use super::*;

        #[test]
        fn test_error_jcs() {
            let mut proof_options = MockFakeProofOptions::new();
            proof_options.expect_clone().returning(|| {
                let mut out = MockFakeProofOptions::new();
                out.expect_fmt()
                    .returning(|formatter| formatter.write_str("hello fmt"));

                out.expect_validate_type().once().returning(|| Ok(()));

                out.expect_validate_cryptosuite()
                    .once()
                    .returning(|| Ok(()));

                out.expect_validate_created().once().returning(|| Ok(()));

                out.expect_to_jcs()
                    .once()
                    .returning(|| Err(DIDError::GenerateJSONJCSError("error to jcs".to_string())));

                out
            });

            let try_proof_config = generate_proof_config(proof_options);
            assert!(try_proof_config.is_err());
            assert!(matches!(
                try_proof_config.clone().unwrap_err(),
                ProofError::ProofGenerationError(_)
            ));

            let err_msg = match try_proof_config.unwrap_err() {
                ProofError::ProofGenerationError(msg) => msg,
                _ => panic!("unknown error"),
            };

            assert!(err_msg.contains("error to jcs"))
        }
    }

    #[test]
    fn test_success() {
        let mut proof_options = MockFakeProofOptions::new();
        proof_options.expect_clone().returning(|| {
            let mut out = MockFakeProofOptions::new();
            out.expect_fmt()
                .returning(|formatter| formatter.write_str("hello fmt"));

            out.expect_validate_type().once().returning(|| Ok(()));

            out.expect_validate_cryptosuite()
                .once()
                .returning(|| Ok(()));

            out.expect_validate_created().once().returning(|| Ok(()));

            out.expect_to_jcs()
                .once()
                .returning(|| Ok(String::from("testing")));

            out
        });

        let try_proof_config = generate_proof_config(proof_options);
        assert!(try_proof_config.is_ok())
    }
}
