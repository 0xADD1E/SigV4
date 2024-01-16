pub(crate) static ALGORITHM: ring::hmac::Algorithm = ring::hmac::HMAC_SHA256;
pub(crate) const ALGORITHM_LEN: usize = ring::digest::SHA256_OUTPUT_LEN;
pub(crate) type DigestBytes = [u8; ALGORITHM_LEN];

mod key_builder;
pub use key_builder::{DateKey, DateRegionKey, DateRegionServiceKey, KeyBuilder, SigningKey};

pub struct Signer(SigningKey);
impl From<SigningKey> for Signer {
    fn from(value: SigningKey) -> Self {
        Self(value)
    }
}
impl Signer {
    pub fn sign(&self, contents: impl AsRef<[u8]>) -> String {
        let tag = ring::hmac::sign(&self.0.into(), contents.as_ref());
        hex::encode(tag.as_ref())
    }
}

#[cfg(test)]
mod tests;
