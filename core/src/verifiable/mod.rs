mod base;
mod proof;
mod vc;
mod vp;

pub mod types {
    use super::*;

    pub use base::ToJCS;
    pub use vc::{Context, Type, ID, SRI};
}

pub mod objects {
    use super::*;

    pub use proof::{Proof, Value as ProofValue};
    pub use vc::VC;
    pub use vp::VP;
}
