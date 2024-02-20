use crate::types::Error;

pub trait ToJCS {
    fn to_jcs(&self) -> Result<String, Error>;
}
