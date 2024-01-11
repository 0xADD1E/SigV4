use std::io::Read;

use ring::hmac::{self, Tag};

pub struct Root(String);
impl<T> From<T> for Root
where
    String: From<T>,
{
    fn from(value: T) -> Self {
        Root(String::from(value))
    }
}
impl Default for Root {
    fn default() -> Self {
        Root::from("AWS4")
    }
}
pub struct DateKey(String);
pub struct DateRegionKey(String);
pub struct DateRegionServiceKey(String);
pub struct SigningKey(Tag);
pub trait Key {}
impl Key for Root {}
impl Key for DateKey {}
impl Key for DateRegionKey {}
impl Key for DateRegionServiceKey {}
impl Key for SigningKey {}

//type HmacSha256 = Hmac<Sha256>;
#[derive(Default)]
pub struct Signer<T: Key = Root> {
    key: T,
}

impl Signer<Root> {
    //fn _date_key(secret_access_key: impl Into<&[u8]>, date: impl Into<&[u8]>) {}
    //pub fn date_key(secret_access_key: impl Into<&[u8]>) {}

    pub fn signing_key(
        &self,
        secret_access_key: &str,
        date: &str,
        region: &str,
        service: &str,
    ) -> Signer<SigningKey> {
        use ring::hmac;
        let Root(root) = &self.key;
        let date_key = hmac::sign(
            &hmac::Key::new(
                hmac::HMAC_SHA256,
                format!("{root}{secret_access_key}").as_bytes(),
            ),
            date.as_bytes(),
        );
        let date_region_key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, date_key.as_ref()),
            region.as_bytes(),
        );
        let date_region_service_key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, date_region_key.as_ref()),
            service.as_bytes(),
        );
        let signing_key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, date_region_service_key.as_ref()),
            b"aws4_request",
        );
        Signer {
            key: SigningKey(signing_key),
        }
    }
}
impl Signer<SigningKey> {
    pub fn sign(&self, string_to_sign: &[u8]) -> String {
        hex::encode(
            hmac::sign(
                &hmac::Key::new(hmac::HMAC_SHA256, self.key.0.as_ref()),
                string_to_sign,
            )
            .as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let creq = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
        let time = "20150830";

        let signer = Signer::default().signing_key(secret, time, "us-east-1", "iam");
        let signature = signer.sign(creq.as_bytes());

        let expected = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";
        assert_eq!(expected, &signature);
    }
}
