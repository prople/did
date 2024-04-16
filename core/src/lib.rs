#![doc = include_str!("../README.md")]

pub mod hashlink;
pub mod keys;
pub mod types;

pub mod account;
pub mod context;
pub mod did;
pub mod doc;
pub mod identity;
pub mod verifiable;

pub mod multi {
    pub use multiaddr as addr;
    pub use multibase as base;
    pub use multihash as hash;
}
