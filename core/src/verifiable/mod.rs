//! `verifiable` is module designed to generate a `VC (Verifiable Credential)` and also `VP (Verifiable Presentation)`
mod proof;
mod vc;
mod vp;

pub mod types {
    use super::*;

    pub use vc::{Context, Type, ID, SRI};
}

pub mod objects {
    use super::*;

    pub use proof::{Proof, Value as ProofValue};
    pub use vc::VC;
    pub use vp::VP;
}
