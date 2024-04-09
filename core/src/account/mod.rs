//! `account` is main module used to generate an [`Account`]
//!
//! The generated account will depends on `EdDSA` generated keypairs
//! and used data is the public key
mod account;

pub use account::Account;
