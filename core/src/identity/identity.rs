use crate::doc::types::{Doc, Primary};
use crate::keys::{
    AggreementKey, AggreementPairs, IdentityPrivateKeyPairs, IdentityPrivateKeyPairsBuilder,
    KeySecureBuilder, KeySecureError, PrivateKeyPairs, VerificationKey, VerificationPairs,
};
use crate::types::*;

#[derive(Debug, Clone)]
struct VerificationMethod {
    pub verification_pairs: VerificationPairs,
    pub aggreement_pairs: AggreementPairs,
}

#[derive(Debug, Clone)]
pub struct Identity {
    identity: String,
    authentication: Option<VerificationMethod>,
    assertion: Option<VerificationMethod>,
}

impl Identity {
    pub fn new(val: String) -> Self {
        Self {
            identity: val,
            authentication: None,
            assertion: None,
        }
    }

    pub fn value(&self) -> String {
        self.identity.clone()
    }

    pub fn account(&self) -> Result<String, Error> {
        let identity = self.identity.clone();
        let value = identity.as_str().split(DID_SYNTAX_MARK);
        if value.clone().count() < 3 {
            return Err(Error::InvalidDID);
        }

        let try_account = value.clone().last();
        match try_account {
            Some(value) => Ok(value.to_string()),
            None => Err(Error::InvalidDID),
        }
    }

    pub fn build_auth_method(&mut self) -> Result<(), Error> {
        let verification_method = self
            .build_verification_method()
            .map_err(|_| Error::BuildAuthError)?;

        self.authentication = Some(verification_method);
        Ok(())
    }

    pub fn build_assertion_method(&mut self) -> Result<(), Error> {
        let verification_method = self
            .build_verification_method()
            .map_err(|_| Error::BuildAuthError)?;

        self.assertion = Some(verification_method);
        Ok(())
    }

    pub fn to_doc(&self) -> Doc {
        let auth_verification_id = format!("{}#key-auth-verification", self.identity);
        let auth_aggreement_id = format!("{}#key-auth-aggrement", self.identity);
        let assertion_verification_id = format!("{}#key-assertion-verification", self.identity);
        let assertion_aggreement_id = format!("{}#key-assertion-aggrement", self.identity);

        let mut doc = Doc::generate(self.identity.clone());
        doc.add_context(CONTEXT_ED25519.to_string())
            .add_context(CONTEXT_X25519.to_string());

        if let Some(auth) = &self.authentication {
            let auth_verification_primary = Primary {
                id: auth_verification_id,
                controller: self.identity.clone(),
                verification_type: VERIFICATION_TYPE_ED25519.to_string(),
                multibase: auth.verification_pairs.clone().pub_key,
            };

            let auth_aggreement_primary = Primary {
                id: auth_aggreement_id,
                controller: self.identity.clone(),
                verification_type: VERIFICATION_TYPE_X25519.to_string(),
                multibase: auth.aggreement_pairs.clone().pub_key,
            };

            doc.add_authentication(auth_verification_primary)
                .add_authentication(auth_aggreement_primary);
        }

        if let Some(assertion) = &self.assertion {
            let assertion_verification_primary = Primary {
                id: assertion_verification_id,
                controller: self.identity.clone(),
                verification_type: VERIFICATION_TYPE_ED25519.to_string(),
                multibase: assertion.verification_pairs.clone().pub_key,
            };

            let assertion_aggreement_primary = Primary {
                id: assertion_aggreement_id,
                controller: self.identity.clone(),
                verification_type: VERIFICATION_TYPE_X25519.to_string(),
                multibase: assertion.aggreement_pairs.clone().pub_key,
            };

            doc.add_assertion(assertion_verification_primary)
                .add_assertion(assertion_aggreement_primary);
        }

        doc
    }

    fn build_verification_method(&self) -> Result<VerificationMethod, Error> {
        let verification_key = VerificationKey::new();
        let verification_pairs = verification_key
            .generate()
            .map_err(|_| Error::BuildAuthError)?;

        let aggreement_key = AggreementKey::new();
        let aggreement_pairs = aggreement_key.generate();

        Ok(VerificationMethod {
            verification_pairs,
            aggreement_pairs,
        })
    }
}

impl IdentityPrivateKeyPairsBuilder for Identity {
    fn build_private_keys(
        &self,
        password: String,
    ) -> Result<IdentityPrivateKeyPairs, KeySecureError> {
        let mut pairs = IdentityPrivateKeyPairs::new(self.value());

        if let Some(authentication) = &self.authentication {
            let auth_verification_keysecure = authentication
                .verification_pairs
                .clone()
                .build_keysecure(password.clone())
                .map_err(|_| KeySecureError::BuildIdentityPrivateKeysError)?;

            let auth_aggrement_keysecure = authentication
                .aggreement_pairs
                .clone()
                .build_keysecure(password.clone())
                .map_err(|_| KeySecureError::BuildIdentityPrivateKeysError)?;

            pairs.authentication = Some(PrivateKeyPairs {
                verification: auth_verification_keysecure,
                aggrement: auth_aggrement_keysecure,
            })
        }

        if let Some(assertion) = &self.assertion {
            let assertion_verification_keysecure = assertion
                .verification_pairs
                .clone()
                .build_keysecure(password.clone())
                .map_err(|_| KeySecureError::BuildIdentityPrivateKeysError)?;

            let assertion_aggrement_keysecure = assertion
                .aggreement_pairs
                .clone()
                .build_keysecure(password.clone())
                .map_err(|_| KeySecureError::BuildIdentityPrivateKeysError)?;

            pairs.assertion = Some(PrivateKeyPairs {
                verification: assertion_verification_keysecure,
                aggrement: assertion_aggrement_keysecure,
            })
        }

        Ok(pairs)
    }
}
