//! `identity` is a module used to generate an entity [`types::Identity`]
mod identity;

pub mod payload;

pub mod types {
    use super::*;

    pub use identity::Identity;
}
