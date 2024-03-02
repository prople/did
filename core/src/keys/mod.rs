//! `keys` is a module used to hold and store all generated `DID Data`, encrypt it and save it through [`secure::KeySecureBuilder]
mod agreement;
mod secure;
mod verification;

pub use agreement::{Key as AggreementKey, Pairs as AggreementPairs};

pub use verification::{
    Error as VerificationError, Key as VerificationKey, Pairs as VerificationPairs,
};

pub use secure::{
    Error as KeySecureError, IdentityPrivateKeyPairs, IdentityPrivateKeyPairsBuilder,
    KeySecureBuilder, PrivateKeyPairs,
};
