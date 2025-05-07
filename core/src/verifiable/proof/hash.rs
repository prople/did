use super::types::{Hasher, ProofError};

/// HashedData is a new type to represent hashed data that contains a concatenation
/// between proof config and its transformed document
#[derive(Clone, Debug)]
pub(crate) struct HashedData(Vec<u8>);

impl HashedData {
    pub(crate) fn to_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<&[u8]> for HashedData {
    fn from(value: &[u8]) -> Self {
        HashedData(value.to_vec())
    }
}

impl From<Vec<u8>> for HashedData {
    fn from(value: Vec<u8>) -> Self {
        HashedData(value)
    }
}

/// generate_hash used to hashing given `transformed_document` and also for the `proof_config`
/// following its formal specification
///
/// The result is a concatenation between `proof_config` and `transformed_document` after both of them
/// applied with SHA256
///
/// Spec: https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
pub(crate) fn generate_hash(
    transformed_doc: impl Hasher,
    proof_config: impl Hasher,
) -> Result<HashedData, ProofError> {
    let document_hash = transformed_doc
        .hash()
        .map_err(|err| ProofError::ProofGenerationError(err.to_string()))?;

    let config_hash = proof_config
        .hash()
        .map_err(|err| ProofError::ProofGenerationError(err.to_string()))?;

    let document_hash_bytes = document_hash.as_slice();
    let config_hash_bytes = config_hash.as_slice();

    let hash_data = [config_hash_bytes, document_hash_bytes].concat();
    Ok(HashedData::from(hash_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    use mockall::mock;

    mock!(
        FakeHasher{}

        impl Clone for FakeHasher {
            fn clone(&self) -> Self;
        }

        impl Hasher for FakeHasher {
            fn hash(&self) -> Result<Vec<u8>, ProofError>;
        }
    );

    mod expect_errors {
        use super::*;

        #[test]
        fn test_error_hash_document() {
            let mut mock_document_hasher = MockFakeHasher::new();
            mock_document_hasher.expect_hash().once().returning(|| {
                Err(ProofError::ProofGenerationError(
                    "error document hash".to_string(),
                ))
            });

            let mock_proof_config = MockFakeHasher::new();
            let try_hash = generate_hash(mock_document_hasher, mock_proof_config);

            assert!(try_hash.is_err());
            assert!(matches!(
                try_hash.clone().unwrap_err(),
                ProofError::ProofGenerationError(_)
            ));

            let err_msg = match try_hash.unwrap_err() {
                ProofError::ProofGenerationError(msg) => msg,
                _ => panic!("unknown error"),
            };

            assert!(err_msg.contains("error document hash"))
        }

        #[test]
        fn test_error_proof_config() {
            let mut mock_document_hasher = MockFakeHasher::new();
            mock_document_hasher
                .expect_hash()
                .once()
                .returning(|| Ok(b"hello doc".to_vec()));

            let mut mock_proof_config = MockFakeHasher::new();
            mock_proof_config.expect_hash().once().returning(|| {
                Err(ProofError::ProofGenerationError(
                    "error config hash".to_string(),
                ))
            });

            let try_hash = generate_hash(mock_document_hasher, mock_proof_config);

            assert!(try_hash.is_err());
            assert!(matches!(
                try_hash.clone().unwrap_err(),
                ProofError::ProofGenerationError(_)
            ));

            let err_msg = match try_hash.unwrap_err() {
                ProofError::ProofGenerationError(msg) => msg,
                _ => panic!("unknown error"),
            };

            assert!(err_msg.contains("error config hash"))
        }
    }

    mod expect_success {
        use super::*;

        #[test]
        fn test_success() {
            let mut mock_document_hasher = MockFakeHasher::new();
            mock_document_hasher
                .expect_hash()
                .once()
                .returning(|| Ok(b"hello doc".to_vec()));

            let mut mock_proof_config = MockFakeHasher::new();
            mock_proof_config
                .expect_hash()
                .once()
                .returning(|| Ok(b"hello config".to_vec()));

            let try_hash = generate_hash(mock_document_hasher, mock_proof_config);
            assert!(try_hash.is_ok());

            let message_1 = b"hello doc".as_slice();
            let message_2 = b"hello config".as_slice();

            let compare_with: Vec<u8> = [message_2, message_1].concat();

            let out = try_hash.unwrap();
            let out_bytes = out.to_bytes();
            assert_eq!(out_bytes.len(), compare_with.as_slice().len());
            assert_eq!(out_bytes, compare_with.as_slice());
        }
    }
}
