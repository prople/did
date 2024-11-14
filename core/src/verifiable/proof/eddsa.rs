use multibase;
use prople_crypto::eddsa::keypair::KeyPair;

use super::types::{CryptoSuiteBuilder, CryptoSuiteVerificationResult, ProofError, Proofable};
use super::Proof;

use super::config::generate_proof_config;
use super::hash::generate_hash;
use super::serialize::{serialize_hashed_data, ProofByte};
use super::transform::transform_document;
use super::verifier::verify_signature;

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
        // Let proof be a clone of the proof options, options
        let mut cloned_proof = opts.clone();

        // Let proofConfig be the result of running the algorithm in Section 3.3.5 Proof Configuration (eddsa-jcs-2022)
        // with proof passed as the proof options parameter
        let proof_config = generate_proof_config(opts.clone())?;

        // Let transformedData be the result of running the algorithm in Section 3.3.3 Transformation (eddsa-jcs-2022)
        // with unsecuredDocument and options passed as parameters
        let transformed_data = transform_document(unsecured_document, opts.clone())?;

        // Let hashData be the result of running the algorithm in Section 3.3.4 Hashing (eddsa-jcs-2022) with
        // transformedData and proofConfig passed as a parameters
        let hashed_data = generate_hash(transformed_data, proof_config)?;

        // Let proofBytes be the result of running the algorithm in Section 3.3.6 Proof Serialization (eddsa-jcs-2022)
        // with hashData and options passed as parameters
        let proof_bytes = serialize_hashed_data(hashed_data, self.keypair.to_owned());

        // Let proof.proofValue be a base58-btc-encoded Multibase value of the proofBytes
        let proof_encoded = proof_bytes.encode();
        cloned_proof.set_signature_as_string(proof_encoded.get());

        // Return proof as the data integrity proof
        Ok(cloned_proof)
    }

    /// Formal spec: https://www.w3.org/TR/vc-di-eddsa/#verify-proof-eddsa-jcs-2022
    fn verify_proof(
        &self,
        secured_document: T,
    ) -> Result<CryptoSuiteVerificationResult<T>, ProofError> {
        // Let unsecuredDocument be a copy of securedDocument with the proof value removed
        let unsecured_doc = secured_document.clone();
        let proof_doc = secured_document
            .get_proof()
            .ok_or(ProofError::ProofVerificationError(
                "missing proof from given document".to_string(),
            ))?;

        // Let proofOptions be the result of a copy of securedDocument.proof with proofValue removed
        let mut proof_options = proof_doc.clone();
        proof_options.remove_proof_value();

        // Let proofBytes be the Multibase decoded base58-btc value in securedDocument.proof.proofValue
        let proof_value = proof_doc.proof_value;
        let (_, proof_bytes) = multibase::decode(proof_value)
            .map_err(|err| ProofError::ProofVerificationError(err.to_string()))?;

        // Let transformedData be the result of running the algorithm in Section 3.3.3 Transformation (eddsa-jcs-2022)
        // with unsecuredDocument and proofOptions passed as parameters
        let transformed_data = transform_document(unsecured_doc.clone(), proof_options.clone())?;

        // Let proofConfig be the result of running the algorithm in Section 3.3.5 Proof Configuration (eddsa-jcs-2022)
        // with proofOptions passed as the parameter
        let proof_config = generate_proof_config(proof_options.clone())?;

        // Let hashData be the result of running the algorithm in Section 3.3.4 Hashing (eddsa-jcs-2022)
        // with transformedData and proofConfig passed as a parameters
        let hashed_data = generate_hash(transformed_data, proof_config)?;

        // Let verified be the result of running the algorithm in Section 3.3.7 Proof Verification (eddsa-jcs-2022)
        // on hashData, proofBytes, and proofConfig
        let is_verified = verify_signature(
            self.keypair.to_owned(),
            hashed_data,
            ProofByte::from(proof_bytes),
        )?;

        // Return a verification result
        let result = CryptoSuiteVerificationResult::result(is_verified, unsecured_doc);
        Ok(result)
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
    use crate::verifiable::proof::types::Proofable;
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
                mock_doc.expect_clone().returning(|| {
                    let mut cloned = MockFakeProofable::new();
                    cloned
                        .expect_to_jcs()
                        .once()
                        .returning(|| Ok("fake-jcs".to_string()));

                    cloned
                });

                mock_doc
                    .expect_to_jcs()
                    .once()
                    .returning(|| Ok("fake-jcs".to_string()));

                let keypair = KeyPair::generate();

                let eddsa_di = EddsaJcs2022::new(keypair.clone());
                let try_create_proof = eddsa_di.create_proof(mock_doc.clone(), proof.clone());

                assert!(try_create_proof.is_ok());

                let proof_output = try_create_proof.unwrap();
                let proof_value = proof_output.proof_value;
                assert!(!proof_value.is_empty());

                // proof_value MUST BE able to decode back to its bytes
                let try_decode_value = multibase::decode(proof_value.clone());
                assert!(try_decode_value.is_ok());

                // all generated output should be a deterministic output meaning that
                // if we generate using same input, it should produce same output
                // we need to test generate manually and compare the result
                let try_proof_config = generate_proof_config(proof.clone());
                assert!(try_proof_config.is_ok());

                let try_transform_doc = transform_document(mock_doc, proof.clone());
                assert!(try_transform_doc.is_ok());

                let try_hash = generate_hash(try_transform_doc.unwrap(), try_proof_config.unwrap());
                assert!(try_hash.clone().is_ok());

                let serialized = serialize_hashed_data(try_hash.clone().unwrap(), keypair.clone());
                let encoded = serialized.encode();
                assert_eq!(proof_value.clone(), encoded.get());

                // now we need to make sure that generated signature bytes, should be able to verify
                // through keypair public key
                let try_decode = multibase::decode(proof_value);
                assert!(try_decode.is_ok());

                let public_key = keypair.pub_key();
                let hashed = try_hash.unwrap();

                // this test must be success meaning that generated signature already in synced with the value we've already
                // build and must be verified through same keypair
                let try_verify = public_key.verify(hashed.to_bytes(), serialized.to_hex());
                assert!(try_verify.is_ok());

                // now, we need to test through decoded base64 and use verify_signature
                // the expectation should be same between through this function or manually check
                let (_, proof_byte) = try_decode.unwrap();
                let try_verify_2 = verify_signature(keypair, hashed, ProofByte::from(proof_byte));
                assert!(try_verify_2.is_ok());
                assert!(try_verify_2.unwrap())
            }
        }
    }

    mod test_verify_proof {
        use super::*;

        mod expect_success {
            use super::*;

            #[test]
            fn test_verify_success() {
                let mut proof = Proof::default();
                proof.typ(DEFAULT_PROOF_TYPE.to_string());
                proof.cryptosuite(DEFAULT_PROOF_CRYPTOSUITE.to_string());
                proof.created(Utc::now().to_string());

                let mut mock_doc = MockFakeProofable::new();
                mock_doc.expect_clone().returning(|| {
                    let mut cloned = MockFakeProofable::new();
                    cloned
                        .expect_to_jcs()
                        .returning(|| Ok("fake-jcs".to_string()));

                    cloned
                });

                mock_doc
                    .expect_to_jcs()
                    .returning(|| Ok("fake-jcs".to_string()));

                let keypair = KeyPair::generate();
                let eddsa_di = EddsaJcs2022::new(keypair);
                let try_create_proof = eddsa_di.create_proof(mock_doc.clone(), proof);
                assert!(try_create_proof.is_ok());

                let mut secured_doc = mock_doc.clone();
                secured_doc.expect_clone().returning(move || {
                    let mut cloned = MockFakeProofable::new();
                    cloned
                        .expect_to_jcs()
                        .returning(|| Ok("fake-jcs".to_string()));

                    cloned.expect_clone().returning(|| {
                        let mut cloned = MockFakeProofable::new();
                        cloned
                            .expect_to_jcs()
                            .returning(|| Ok("fake-jcs".to_string()));

                        cloned
                    });

                    cloned
                });

                let generated_proof = try_create_proof.unwrap();
                secured_doc.expect_get_proof().once().returning(move || {
                    let cloned_generated_proof = generated_proof.clone();
                    Some(cloned_generated_proof)
                });

                secured_doc
                    .expect_to_jcs()
                    .returning(|| Ok("fake-jcs".to_string()));

                let try_verify_proof = eddsa_di.verify_proof(secured_doc);
                assert!(try_verify_proof.is_ok());

                // although the process return without any errors, we also need to make sure that
                // the cryptosuite verification result also at the verified state (boolean -> true)
                let result = try_verify_proof.unwrap();
                assert!(result.verified)
            }
        }
    }
}
