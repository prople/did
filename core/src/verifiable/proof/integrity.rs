use std::marker::PhantomData;

use crate::types::Validator;

use super::types::{
    CryptoSuiteBuilder, CryptoSuiteVerificationResult, ProofError, ProofPurpose, Proofable,
};

#[derive(Clone, Debug)]
pub struct Integrity<TDoc, TCs, TOpts>
where
    TDoc: Proofable,
    TCs: CryptoSuiteBuilder<TDoc, ProofOptions = TOpts>,
{
    cryptosuite_instance: TCs,
    _phantom_doc: PhantomData<TDoc>,
}

impl<TDoc, TCs, TOpts> Integrity<TDoc, TCs, TOpts>
where
    TDoc: Proofable,
    TCs: CryptoSuiteBuilder<TDoc, ProofOptions = TOpts>,
{
    pub fn new(instance: TCs) -> Self {
        Self {
            cryptosuite_instance: instance,
            _phantom_doc: PhantomData,
        }
    }

    /// `add_proof` is a part of algorithm that already described by the `VC Data Integrity`
    ///
    /// The difference with the formal spec is, our cryptosuite instance is not part of input parameter
    /// because it already been set on [`Integrity::new`] method
    ///
    /// Spec: https://www.w3.org/TR/vc-data-integrity/#add-proof
    pub fn add_proof(&self, doc: TDoc, opts: Option<TOpts>) -> Result<TDoc, ProofError> {
        let proof = self.cryptosuite_instance.create_proof(doc.clone(), opts)?;
        let _ = proof
            .validate()
            .map_err(|err| ProofError::ProofGenerationError(err.to_string()))?;

        // Let securedDataDocument be a copy of inputDocument
        // Set securedDataDocument.proof to the value of proof.
        Ok(doc.clone().setup_proof(proof))
    }

    pub fn verify_proof(
        &self,
        document_bytes: Vec<u8>,
        expected_proof_purpose: ProofPurpose,
    ) -> Result<CryptoSuiteVerificationResult<TDoc>, ProofError> {
        // Let securedDocument be the result of running parse JSON bytes to an Infra value on documentBytes.
        let secured_doc = TDoc::parse_json_bytes(document_bytes)?;

        // If either securedDocument is not a map or securedDocument.proof is not a map, an error MUST be
        // raised and SHOULD convey an error type of PARSING_ERROR.
        // Let proof be securedDocument.proof.
        let proof_doc = secured_doc
            .get_proof()
            .ok_or(ProofError::ProofVerificationError(
                "missing document proof".to_string(),
            ))?;

        // If one or more of proof.type, proof.verificationMethod, and proof.proofPurpose does not exist,
        // an error MUST be raised and SHOULD convey an error type of PROOF_VERIFICATION_ERROR
        let _ = proof_doc
            .validate()
            .map_err(|err| ProofError::ProofVerificationError(err.to_string()))?;

        // If expectedProofPurpose was given, and it does not match proof.proofPurpose, an error MUST be
        // raised and SHOULD convey an error type of PROOF_VERIFICATION_ERROR
        if proof_doc.proof_purpose != expected_proof_purpose {
            return Err(ProofError::ProofVerificationError(
                "mismatch proof purpose".to_string(),
            ));
        }

        // Let cryptosuiteVerificationResult be the result of running the cryptosuite.verifyProof algorithm
        // with securedDocument provided as input
        self.cryptosuite_instance.verify_proof(secured_doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Debug;
    use std::fmt::Formatter;
    use std::fmt::Result as FmtResult;

    use mockall::mock;
    use mockall::predicate;

    use rst_common::standard::serde::Deserialize;
    use rst_common::standard::serde::{self, Serialize};

    use crate::types::{DIDError, JSONValue, ToJCS, ToJSON};
    use crate::verifiable::proof::Proof;

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

    #[derive(Clone, Debug, PartialEq)]
    struct FakeOptions;

    mock!(
        FakeCryptoSuite{}

        impl Clone for FakeCryptoSuite {
            fn clone(&self) -> Self;
        }

        impl CryptoSuiteBuilder<MockFakeProofable> for FakeCryptoSuite {
            type ProofOptions = FakeOptions;

            fn create_proof(
                &self,
                unsecurd_document: MockFakeProofable,
                opts: Option<FakeOptions>,
            ) -> Result<Proof, ProofError>;

            fn verify_proof(
                &self,
                secured_document: MockFakeProofable,
            ) -> Result<CryptoSuiteVerificationResult<MockFakeProofable>, ProofError>;
        }
    );

    mod add_proof {
        use super::*;

        mod expect_errors {
            use super::*;

            #[test]
            fn test_error_create_proof_error() {
                let mut mock_doc = MockFakeProofable::new();
                mock_doc.expect_clone().returning(|| {
                    let mut out = MockFakeProofable::new();
                    out.expect_fmt()
                        .returning(|formatter| formatter.write_str("test"));

                    out
                });

                let mut mock_crypto_instance = MockFakeCryptoSuite::new();
                mock_crypto_instance
                    .expect_create_proof()
                    .with(predicate::always(), predicate::eq(Some(FakeOptions {})))
                    .returning(|_, _| {
                        Err(ProofError::ProofGenerationError(
                            "unable to create proof".to_string(),
                        ))
                    });

                let integrity = Integrity::new(mock_crypto_instance);
                let try_add_proof = integrity.add_proof(mock_doc, Some(FakeOptions));

                assert!(try_add_proof.is_err());
                assert!(matches!(
                    try_add_proof.clone().unwrap_err(),
                    ProofError::ProofGenerationError(_)
                ));

                let err_msg = match try_add_proof.unwrap_err() {
                    ProofError::ProofGenerationError(msg) => msg,
                    _ => panic!("unknown error"),
                };
                assert!(err_msg.contains("unable to create proof"))
            }

            mod validation {
                use super::*;

                #[test]
                fn test_validation_error_missing_type() {
                    let mut mock_doc = MockFakeProofable::new();
                    mock_doc.expect_clone().returning(|| {
                        let mut out = MockFakeProofable::new();
                        out.expect_fmt()
                            .returning(|formatter| formatter.write_str("test"));

                        out
                    });

                    let mut mock_crypto_instance = MockFakeCryptoSuite::new();
                    mock_crypto_instance
                        .expect_create_proof()
                        .with(predicate::always(), predicate::eq(Some(FakeOptions {})))
                        .returning(|_, _| {
                            let proof = Proof::default();
                            Ok(proof)
                        });

                    let integrity = Integrity::new(mock_crypto_instance);
                    let try_add_proof = integrity.add_proof(mock_doc, Some(FakeOptions));

                    assert!(try_add_proof.is_err());
                    assert!(matches!(
                        try_add_proof.clone().unwrap_err(),
                        ProofError::ProofGenerationError(_)
                    ));

                    let err_msg = match try_add_proof.unwrap_err() {
                        ProofError::ProofGenerationError(msg) => msg,
                        _ => panic!("unknown error"),
                    };
                    assert!(err_msg.contains("missing type"))
                }

                #[test]
                fn test_validation_error_missing_verification_method() {
                    let mut mock_doc = MockFakeProofable::new();
                    mock_doc.expect_clone().returning(|| {
                        let mut out = MockFakeProofable::new();
                        out.expect_fmt()
                            .returning(|formatter| formatter.write_str("test"));

                        out
                    });

                    let mut mock_crypto_instance = MockFakeCryptoSuite::new();
                    mock_crypto_instance
                        .expect_create_proof()
                        .with(predicate::always(), predicate::eq(Some(FakeOptions {})))
                        .returning(|_, _| {
                            let mut proof = Proof::default();
                            proof.typ("fake-type".to_string());

                            Ok(proof)
                        });

                    let integrity = Integrity::new(mock_crypto_instance);
                    let try_add_proof = integrity.add_proof(mock_doc, Some(FakeOptions));

                    assert!(try_add_proof.is_err());
                    assert!(matches!(
                        try_add_proof.clone().unwrap_err(),
                        ProofError::ProofGenerationError(_)
                    ));

                    let err_msg = match try_add_proof.unwrap_err() {
                        ProofError::ProofGenerationError(msg) => msg,
                        _ => panic!("unknown error"),
                    };
                    assert!(err_msg.contains("missing verification method"))
                }

                #[test]
                fn test_validation_error_unknown_purpose() {
                    let mut mock_doc = MockFakeProofable::new();
                    mock_doc.expect_clone().returning(|| {
                        let mut out = MockFakeProofable::new();
                        out.expect_fmt()
                            .returning(|formatter| formatter.write_str("test"));

                        out
                    });

                    let mut mock_crypto_instance = MockFakeCryptoSuite::new();
                    mock_crypto_instance
                        .expect_create_proof()
                        .with(predicate::always(), predicate::eq(Some(FakeOptions {})))
                        .returning(|_, _| {
                            let mut proof = Proof::default();
                            proof.typ("fake-type".to_string());
                            proof.method("fake-verification-method".to_string());

                            Ok(proof)
                        });

                    let integrity = Integrity::new(mock_crypto_instance);
                    let try_add_proof = integrity.add_proof(mock_doc, Some(FakeOptions));

                    assert!(try_add_proof.is_err());
                    assert!(matches!(
                        try_add_proof.clone().unwrap_err(),
                        ProofError::ProofGenerationError(_)
                    ));

                    let err_msg = match try_add_proof.unwrap_err() {
                        ProofError::ProofGenerationError(msg) => msg,
                        _ => panic!("unknown error"),
                    };
                    assert!(err_msg.contains("unknown proof purpose"))
                }
            }
        }

        mod expect_success {
            use super::*;

            #[test]
            fn test_success_create_proof() {
                let mut proof = Proof::new("fake-id".to_string());
                proof.method("fake-method".to_string());
                proof.purpose(ProofPurpose::AssertionMethod.to_string());

                let mock_proof_1 = proof.clone();
                let mock_proof_2 = proof.clone();
                let mock_proof_3 = proof.clone();

                let mut mock_doc = MockFakeProofable::new();
                mock_doc.expect_clone().returning(move || {
                    let copy_proof_1 = mock_proof_1.clone();
                    let copy_proof_2 = mock_proof_2.clone();

                    let mut out = MockFakeProofable::new();
                    out.expect_fmt()
                        .returning(|formatter| formatter.write_str("test"));

                    out.expect_setup_proof()
                        .with(predicate::eq(copy_proof_1.clone()))
                        .returning(move |_| {
                            let mut copied = MockFakeProofable::new();
                            let copy_proof = copy_proof_2.clone();

                            copied
                                .expect_get_proof()
                                .returning(move || Some(copy_proof.clone()));

                            copied
                        });

                    out
                });

                let mut mock_crypto_instance = MockFakeCryptoSuite::new();
                mock_crypto_instance
                    .expect_create_proof()
                    .with(predicate::always(), predicate::eq(Some(FakeOptions {})))
                    .return_once(|_, _| Ok(proof));

                let integrity = Integrity::new(mock_crypto_instance);
                let try_add_proof = integrity.add_proof(mock_doc, Some(FakeOptions));

                assert!(try_add_proof.is_ok());
                let proofable = try_add_proof.unwrap();
                assert!(proofable.get_proof().is_some());

                let proof_doc = proofable.get_proof().unwrap();
                assert_eq!(proof_doc, mock_proof_3)
            }
        }
    }

    mod verify_proof {
        use super::*;

        use std::sync::Mutex;
        static LOCKER: Mutex<()> = Mutex::new(());

        mod expect_errors {
            use super::*;

            mod validations {
                use super::*;

                #[test]
                fn test_missing_type() {
                    let _l = LOCKER.lock();

                    let proof = Proof::default();
                    let fake_proof_1 = proof.clone();

                    let mut mock_doc = MockFakeProofable::new();
                    mock_doc.expect_clone().returning(move || {
                        let fake_proof_1 = fake_proof_1.clone();

                        let mut out = MockFakeProofable::new();
                        out.expect_fmt()
                            .returning(|formatter| formatter.write_str("test"));

                        out.expect_get_proof()
                            .return_once(move || Some(fake_proof_1));
                        out
                    });

                    mock_doc
                        .expect_to_json()
                        .returning(|| Ok(JSONValue::from("hello world")));

                    let mock_doc_1 = mock_doc.clone();

                    let ctx = MockFakeProofable::parse_json_bytes_context();
                    ctx.expect().once().return_once(move |_| Ok(mock_doc_1));

                    let mock_crypto_instance = MockFakeCryptoSuite::new();
                    let integrity = Integrity::new(mock_crypto_instance);
                    let mock_bytes = mock_doc.to_json().unwrap().to_bytes();

                    let try_verify =
                        integrity.verify_proof(mock_bytes, ProofPurpose::AssertionMethod);
                    assert!(try_verify.is_err());
                    assert!(matches!(
                        try_verify.clone().unwrap_err(),
                        ProofError::ProofVerificationError(_)
                    ));

                    let err_msg = match try_verify.unwrap_err() {
                        ProofError::ProofVerificationError(msg) => msg,
                        _ => panic!("unknown error type"),
                    };
                    assert!(err_msg.contains("missing type"))
                }

                #[test]
                fn test_missing_method() {
                    let _l = LOCKER.lock();

                    let mut proof = Proof::default();
                    proof.typ("fake type".to_string());

                    let fake_proof_1 = proof.clone();

                    let mut mock_doc = MockFakeProofable::new();
                    mock_doc.expect_clone().returning(move || {
                        let fake_proof_1 = fake_proof_1.clone();

                        let mut out = MockFakeProofable::new();
                        out.expect_fmt()
                            .returning(|formatter| formatter.write_str("test"));

                        out.expect_get_proof()
                            .return_once(move || Some(fake_proof_1));
                        out
                    });

                    mock_doc
                        .expect_to_json()
                        .returning(|| Ok(JSONValue::from("hello world")));

                    let mock_doc_1 = mock_doc.clone();

                    let ctx = MockFakeProofable::parse_json_bytes_context();
                    ctx.expect().once().return_once(move |_| Ok(mock_doc_1));

                    let mock_crypto_instance = MockFakeCryptoSuite::new();
                    let integrity = Integrity::new(mock_crypto_instance);
                    let mock_bytes = mock_doc.to_json().unwrap().to_bytes();

                    let try_verify =
                        integrity.verify_proof(mock_bytes, ProofPurpose::AssertionMethod);
                    assert!(try_verify.is_err());
                    assert!(matches!(
                        try_verify.clone().unwrap_err(),
                        ProofError::ProofVerificationError(_)
                    ));

                    let err_msg = match try_verify.unwrap_err() {
                        ProofError::ProofVerificationError(msg) => msg,
                        _ => panic!("unknown error type"),
                    };
                    assert!(err_msg.contains("missing verification method"))
                }

                #[test]
                fn test_unknown_purpose() {
                    let _l = LOCKER.lock();

                    let mut proof = Proof::default();
                    proof.typ("fake type".to_string());
                    proof.method("fake-method".to_string());

                    let fake_proof_1 = proof.clone();

                    let mut mock_doc = MockFakeProofable::new();
                    mock_doc.expect_clone().returning(move || {
                        let fake_proof_1 = fake_proof_1.clone();

                        let mut out = MockFakeProofable::new();
                        out.expect_fmt()
                            .returning(|formatter| formatter.write_str("test"));

                        out.expect_get_proof()
                            .return_once(move || Some(fake_proof_1));
                        out
                    });

                    mock_doc
                        .expect_to_json()
                        .returning(|| Ok(JSONValue::from("hello world")));

                    let mock_doc_1 = mock_doc.clone();

                    let ctx = MockFakeProofable::parse_json_bytes_context();
                    ctx.expect().once().return_once(move |_| Ok(mock_doc_1));

                    let mock_crypto_instance = MockFakeCryptoSuite::new();
                    let integrity = Integrity::new(mock_crypto_instance);
                    let mock_bytes = mock_doc.to_json().unwrap().to_bytes();

                    let try_verify =
                        integrity.verify_proof(mock_bytes, ProofPurpose::AssertionMethod);
                    assert!(try_verify.is_err());
                    assert!(matches!(
                        try_verify.clone().unwrap_err(),
                        ProofError::ProofVerificationError(_)
                    ));

                    let err_msg = match try_verify.unwrap_err() {
                        ProofError::ProofVerificationError(msg) => msg,
                        _ => panic!("unknown error type"),
                    };
                    assert!(err_msg.contains("unknown proof purpose"))
                }
            }

            #[test]
            fn test_error_parse_doc_bytes() {
                let _l = LOCKER.lock();

                let mut mock_doc = MockFakeProofable::new();
                mock_doc.expect_clone().returning(|| {
                    let mut out = MockFakeProofable::new();
                    out.expect_fmt()
                        .returning(|formatter| formatter.write_str("test"));

                    out
                });

                mock_doc
                    .expect_to_json()
                    .returning(|| Ok(JSONValue::from("hello world")));

                let ctx = MockFakeProofable::parse_json_bytes_context();
                ctx.expect().once().returning(|_| {
                    Err(ProofError::ProofVerificationError(
                        "error parse doc bytes".to_string(),
                    ))
                });

                let mock_crypto_instance = MockFakeCryptoSuite::new();
                let integrity = Integrity::new(mock_crypto_instance);
                let mock_bytes = mock_doc.to_json().unwrap().to_bytes();

                let try_verify = integrity.verify_proof(mock_bytes, ProofPurpose::AssertionMethod);
                assert!(try_verify.is_err());
                assert!(matches!(
                    try_verify.clone().unwrap_err(),
                    ProofError::ProofVerificationError(_)
                ));

                let err_msg = match try_verify.unwrap_err() {
                    ProofError::ProofVerificationError(msg) => msg,
                    _ => panic!("unknown error type"),
                };
                assert!(err_msg.contains("error parse doc bytes"))
            }

            #[test]
            fn test_error_missing_proof_doc() {
                let _l = LOCKER.lock();

                let mut mock_doc = MockFakeProofable::new();
                mock_doc.expect_clone().returning(|| {
                    let mut out = MockFakeProofable::new();
                    out.expect_fmt()
                        .returning(|formatter| formatter.write_str("test"));

                    out.expect_get_proof().returning(|| None);
                    out
                });

                mock_doc
                    .expect_to_json()
                    .returning(|| Ok(JSONValue::from("hello world")));

                let mock_doc_1 = mock_doc.clone();

                let ctx = MockFakeProofable::parse_json_bytes_context();
                ctx.expect().once().return_once(move |_| Ok(mock_doc_1));

                let mock_crypto_instance = MockFakeCryptoSuite::new();
                let integrity = Integrity::new(mock_crypto_instance);
                let mock_bytes = mock_doc.to_json().unwrap().to_bytes();

                let try_verify = integrity.verify_proof(mock_bytes, ProofPurpose::AssertionMethod);
                assert!(try_verify.is_err());
                assert!(matches!(
                    try_verify.clone().unwrap_err(),
                    ProofError::ProofVerificationError(_)
                ));

                let err_msg = match try_verify.unwrap_err() {
                    ProofError::ProofVerificationError(msg) => msg,
                    _ => panic!("unknown error type"),
                };
                assert!(err_msg.contains("missing document proof"))
            }

            #[test]
            fn test_error_mismatch_proof_purpose() {
                let _l = LOCKER.lock();

                let mut proof = Proof::new("fake-id".to_string());
                proof.method("fake-method".to_string());
                proof.purpose(ProofPurpose::Authentication.to_string());

                let fake_proof_1 = proof.clone();

                let mut mock_doc = MockFakeProofable::new();
                mock_doc.expect_clone().returning(move || {
                    let fake_proof_1 = fake_proof_1.clone();

                    let mut out = MockFakeProofable::new();
                    out.expect_fmt()
                        .returning(|formatter| formatter.write_str("test"));

                    out.expect_get_proof()
                        .return_once(move || Some(fake_proof_1));
                    out
                });

                mock_doc
                    .expect_to_json()
                    .returning(|| Ok(JSONValue::from("hello world")));

                let mock_doc_1 = mock_doc.clone();

                let ctx = MockFakeProofable::parse_json_bytes_context();
                ctx.expect().once().return_once(move |_| Ok(mock_doc_1));

                let mock_crypto_instance = MockFakeCryptoSuite::new();
                let integrity = Integrity::new(mock_crypto_instance);
                let mock_bytes = mock_doc.to_json().unwrap().to_bytes();

                let try_verify = integrity.verify_proof(mock_bytes, ProofPurpose::AssertionMethod);
                assert!(try_verify.is_err());
                assert!(matches!(
                    try_verify.clone().unwrap_err(),
                    ProofError::ProofVerificationError(_)
                ));

                let err_msg = match try_verify.unwrap_err() {
                    ProofError::ProofVerificationError(msg) => msg,
                    _ => panic!("unknown error type"),
                };
                assert!(err_msg.contains("mismatch proof purpose"))
            }
        }

        mod expect_success {
            use super::*;

            #[test]
            fn test_verify_success() {
                let _l = LOCKER.lock();

                let mut proof = Proof::new("fake-id".to_string());
                proof.method("fake-method".to_string());
                proof.purpose(ProofPurpose::AssertionMethod.to_string());

                let fake_proof_1 = proof.clone();

                let mut mock_doc = MockFakeProofable::new();
                mock_doc.expect_clone().returning(move || {
                    let fake_proof_1 = fake_proof_1.clone();

                    let mut out = MockFakeProofable::new();
                    out.expect_fmt()
                        .returning(|formatter| formatter.write_str("test"));

                    out.expect_get_proof()
                        .return_once(move || Some(fake_proof_1));
                    out
                });

                mock_doc
                    .expect_to_json()
                    .returning(|| Ok(JSONValue::from("hello world")));

                let mock_doc_1 = mock_doc.clone();

                let ctx = MockFakeProofable::parse_json_bytes_context();
                ctx.expect().once().return_once(move |_| Ok(mock_doc_1));

                let verification_result = CryptoSuiteVerificationResult{
                    verified: true,
                    document: Some(mock_doc.clone()) 
                };

                let mut mock_crypto_instance = MockFakeCryptoSuite::new();
                mock_crypto_instance.expect_verify_proof().return_once(move |_| {
                    Ok(verification_result)
                });

                let integrity = Integrity::new(mock_crypto_instance);
                let mock_bytes = mock_doc.to_json().unwrap().to_bytes();

                let try_verify = integrity.verify_proof(mock_bytes, ProofPurpose::AssertionMethod);
                assert!(try_verify.is_ok());

                let verify_result = try_verify.unwrap();
                assert!(verify_result.verified);
                assert!(verify_result.document.is_some());
            }
        }
    }
}
