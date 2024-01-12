use ring::hmac::{self, Algorithm};

static ALGORITHM: Algorithm = hmac::HMAC_SHA256;

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
pub struct DateKey(hmac::Key);
impl<T> From<T> for DateKey
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self(hmac::Key::new(ALGORITHM, value.as_ref()))
    }
}
pub struct DateRegionKey(hmac::Key);
impl<T> From<T> for DateRegionKey
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self(hmac::Key::new(ALGORITHM, value.as_ref()))
    }
}
pub struct DateRegionServiceKey(hmac::Key);
impl<T> From<T> for DateRegionServiceKey
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self(hmac::Key::new(ALGORITHM, value.as_ref()))
    }
}
pub struct SigningKey(hmac::Key);
impl<T> From<T> for SigningKey
where
    T: AsRef<[u8]>,
{
    fn from(value: T) -> Self {
        Self(hmac::Key::new(ALGORITHM, value.as_ref()))
    }
}
pub trait Key {}
impl Key for Root {}
impl Key for DateKey {}
impl Key for DateRegionKey {}
impl Key for DateRegionServiceKey {}
impl Key for SigningKey {}

pub struct Signer<T: Key = Root> {
    key: T,
}
impl<T> From<T> for Signer<Root>
where
    T: Into<String>,
{
    fn from(value: T) -> Self {
        Self {
            key: Root::from(value.into()),
        }
    }
}
impl Default for Signer<Root> {
    fn default() -> Self {
        Signer {
            key: Root::default(),
        }
    }
}

impl Signer<Root> {
    fn _date_key(&self, secret_access_key: &str, date: impl AsRef<[u8]>) -> DateKey {
        let root = &self.key.0;

        let key = format!("{root}{secret_access_key}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, key.as_bytes());
        DateKey::from(hmac::sign(&key, date.as_ref()))
    }
    pub fn date_key_for(
        &self,
        secret_access_key: &str,
        date: impl Into<time::Date>,
    ) -> Signer<DateKey> {
        let date: time::Date = date.into();
        let date = format!(
            "{:04}{:02}{:02}",
            date.year(),
            u8::from(date.month()),
            date.day()
        );

        Signer {
            key: self._date_key(secret_access_key, date),
        }
    }
    pub fn date_key(&self, secret_access_key: &str) -> Signer<DateKey> {
        self.date_key_for(secret_access_key, time::OffsetDateTime::now_utc().date())
    }

    pub fn signing_key(
        &self,
        secret_access_key: &str,
        date: &str,
        region: &str,
        service: &str,
    ) -> Signer<SigningKey> {
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
            key: SigningKey::from(signing_key),
        }
    }
}
impl Signer<DateKey> {
    pub fn date_region_key(&self, region: &str) -> Signer<DateRegionKey> {
        let date_region_key = hmac::sign(&self.key.0, region.as_bytes());
        Signer {
            key: DateRegionKey::from(date_region_key.as_ref()),
        }
    }
    pub fn signing_key(&self, region: &str, service: &str) -> Signer<SigningKey> {
        let date_region_key = hmac::sign(&self.key.0, region.as_bytes());
        let date_region_service_key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, date_region_key.as_ref()),
            service.as_bytes(),
        );
        let signing_key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, date_region_service_key.as_ref()),
            b"aws4_request",
        );
        Signer {
            key: SigningKey::from(signing_key),
        }
    }
}
impl Signer<DateRegionKey> {
    pub fn date_region_service_key(&self, service: &str) -> Signer<DateRegionServiceKey> {
        let date_region_service_key = hmac::sign(&self.key.0, service.as_bytes());
        Signer {
            key: DateRegionServiceKey::from(date_region_service_key.as_ref()),
        }
    }
}
impl Signer<DateRegionServiceKey> {
    pub fn signing_key(&self, signing_identifier: &str) -> Signer<SigningKey> {
        let signing_key = hmac::sign(&self.key.0, signing_identifier.as_bytes());
        Signer {
            key: SigningKey::from(signing_key.as_ref()),
        }
    }
    pub fn aws_signing_key(&self) -> Signer<SigningKey> {
        self.signing_key("aws4_request")
    }
}
impl Signer<SigningKey> {
    pub fn sign(&self, string_to_sign: &[u8]) -> String {
        hex::encode(hmac::sign(&self.key.0, string_to_sign).as_ref())
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
    #[test]
    fn it_works_nicely() {
        use time::{Date, Month};
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let creq = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
        let time = Date::from_calendar_date(2015, Month::August, 30).expect("Hardcoded date");

        let signer = Signer::default()
            .date_key_for(secret, time)
            .date_region_key("us-east-1")
            .date_region_service_key("iam")
            .aws_signing_key();

        let signature = signer.sign(creq.as_bytes());

        let expected = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";
        assert_eq!(expected, &signature);
    }

    #[test]
    fn watch_this() {
        use time::{Date, Month};
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let creq = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
        let time = Date::from_calendar_date(2015, Month::August, 30).expect("Hardcoded date");

        let signer = Signer::from("PROMPT4")
            .date_key_for(secret, time)
            .date_region_key("earth-1")
            .date_region_service_key("top")
            .signing_key("prompt4_request");

        panic!("{}", &signer.key.0.as_ref());
        let signature = signer.sign(creq.as_bytes());
    }
}
