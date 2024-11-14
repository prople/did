use super::types::{Hasher, ProofError, ProofOptionsValidator};
use rst_common::with_cryptography::sha2::{Digest, Sha256};

use crate::types::ToJCS;

#[derive(Clone, Debug)]
pub(crate) struct TransformedDoc(String);

impl From<String> for TransformedDoc {
    fn from(value: String) -> Self {
        TransformedDoc(value)
    }
}

impl ToString for TransformedDoc {
    fn to_string(&self) -> String {
        self.0.to_owned()
    }
}

impl Hasher for TransformedDoc {
    fn hash(&self) -> Result<Vec<u8>, ProofError> {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());

        let hashed = hasher.finalize();
        Ok(hashed.to_vec())
    }
}

/// transform_document used to transform given unsecured document into "secured document"
///
/// The definition of "transform" actually apply the JCS standard into unsecured document, with
/// the expected output is string value of JCS
///
/// Spec: https://www.w3.org/TR/vc-di-eddsa/#transformation-eddsa-jcs-2022
pub(crate) fn transform_document<TDoc, TOpts>(
    doc: TDoc,
    opts: TOpts,
) -> Result<TransformedDoc, ProofError>
where
    TDoc: ToJCS,
    TOpts: ProofOptionsValidator,
{
    let _ = opts.validate_type()?;
    let _ = opts.validate_cryptosuite()?;

    let canonical_document = doc
        .to_jcs()
        .map_err(|err| ProofError::ProofGenerationError(err.to_string()))?;

    Ok(TransformedDoc::from(canonical_document))
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

    use crate::types::{DIDError, JSONValue, ToJCS, ToJSON, Validator};
    use crate::verifiable::proof::types::Proofable;
    use crate::verifiable::proof::Proof;

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
            fn setup_proof(&mut self, proof: Proof) -> &mut Self;
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

    mod expect_errors {
        use super::*;

        mod error_validations {
            use super::*;

            #[test]
            fn test_invalid_type() {
                let mock_doc = MockFakeProofable::new();

                let mut mock_options = MockFakeProofOptions::new();
                mock_options.expect_validate_type().once().returning(|| {
                    Err(ProofError::ProofGenerationError("invalid type".to_string()))
                });

                let try_transform_doc = transform_document(mock_doc, mock_options);
                assert!(try_transform_doc.is_err());

                assert!(matches!(
                    try_transform_doc.clone().unwrap_err(),
                    ProofError::ProofGenerationError(_)
                ));

                let err_msg = match try_transform_doc.unwrap_err() {
                    ProofError::ProofGenerationError(msg) => msg,
                    _ => panic!("unknown error"),
                };

                assert!(err_msg.contains("invalid type"))
            }

            #[test]
            fn test_invalid_cryptosuite() {
                let mock_doc = MockFakeProofable::new();

                let mut mock_options = MockFakeProofOptions::new();
                mock_options
                    .expect_validate_type()
                    .once()
                    .returning(|| Ok(()));
                mock_options
                    .expect_validate_cryptosuite()
                    .once()
                    .returning(|| {
                        Err(ProofError::ProofGenerationError(
                            "invalid cryptosuite".to_string(),
                        ))
                    });

                let try_transform_doc = transform_document(mock_doc, mock_options);
                assert!(try_transform_doc.is_err());

                assert!(matches!(
                    try_transform_doc.clone().unwrap_err(),
                    ProofError::ProofGenerationError(_)
                ));

                let err_msg = match try_transform_doc.unwrap_err() {
                    ProofError::ProofGenerationError(msg) => msg,
                    _ => panic!("unknown error"),
                };

                assert!(err_msg.contains("invalid cryptosuite"))
            }
        }

        mod error_document {
            use super::*;

            #[test]
            fn test_error_to_jcs() {
                let mut mock_doc = MockFakeProofable::new();
                mock_doc
                    .expect_to_jcs()
                    .once()
                    .returning(|| Err(DIDError::GenerateJSONJCSError("error jcs".to_string())));

                let mut mock_options = MockFakeProofOptions::new();
                mock_options
                    .expect_validate_type()
                    .once()
                    .returning(|| Ok(()));
                mock_options
                    .expect_validate_cryptosuite()
                    .once()
                    .returning(|| Ok(()));

                let try_transform_doc = transform_document(mock_doc, mock_options);
                assert!(try_transform_doc.is_err());

                assert!(matches!(
                    try_transform_doc.clone().unwrap_err(),
                    ProofError::ProofGenerationError(_)
                ));

                let err_msg = match try_transform_doc.unwrap_err() {
                    ProofError::ProofGenerationError(msg) => msg,
                    _ => panic!("unknown error"),
                };

                assert!(err_msg.contains("error jcs"))
            }
        }
    }

    mod expect_success {
        use super::*;

        #[test]
        fn test_success() {
            let mut mock_doc = MockFakeProofable::new();
            mock_doc
                .expect_to_jcs()
                .once()
                .returning(|| Ok("jcs".to_string()));

            let mut mock_options = MockFakeProofOptions::new();
            mock_options
                .expect_validate_type()
                .once()
                .returning(|| Ok(()));
            mock_options
                .expect_validate_cryptosuite()
                .once()
                .returning(|| Ok(()));

            let try_transform_doc = transform_document(mock_doc, mock_options);
            assert!(try_transform_doc.is_ok());

            let output = try_transform_doc.unwrap();
            assert_eq!(output.to_string(), "jcs".to_string())
        }
    }
}
