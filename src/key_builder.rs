use crate::ALGORITHM;

use super::DigestBytes;
use ring::hmac;
use ring::hmac::Key;
use time::Date;

#[derive(Clone, Copy)]
pub struct DateKey(DigestBytes);
#[derive(Clone, Copy)]
pub struct DateRegionKey(DigestBytes);
#[derive(Clone, Copy)]
pub struct DateRegionServiceKey(DigestBytes);
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct SigningKey(DigestBytes);

impl Into<Key> for DateKey {
    fn into(self) -> Key {
        Key::new(ALGORITHM, &self.0)
    }
}
impl Into<Key> for DateRegionKey {
    fn into(self) -> Key {
        Key::new(ALGORITHM, &self.0)
    }
}
impl Into<Key> for DateRegionServiceKey {
    fn into(self) -> Key {
        Key::new(ALGORITHM, &self.0)
    }
}
impl Into<Key> for SigningKey {
    fn into(self) -> Key {
        Key::new(ALGORITHM, &self.0)
    }
}

impl SigningKey {
    pub fn hmac_key<'a>(&'a self) -> Key {
        Key::new(ALGORITHM, &self.0)
    }
}

pub struct DateKeyState<SecretAccessKeyT, DateT> {
    chain_start_identifier: String,
    secret_access_key: SecretAccessKeyT,
    date: DateT,
}

pub struct KeyBuilder<S: KeyBuilderState = DateKeyState<(), ()>> {
    state: S,
}
impl Default for KeyBuilder<DateKeyState<(), ()>> {
    fn default() -> KeyBuilder<DateKeyState<(), ()>> {
        KeyBuilder {
            state: DateKeyState {
                chain_start_identifier: String::from("AWS4"),
                secret_access_key: (),
                date: (),
            },
        }
    }
}
impl<T> From<T> for KeyBuilder<T>
where
    T: KeyBuilderState,
{
    fn from(value: T) -> Self {
        Self { state: value }
    }
}
impl KeyBuilder<DateKeyState<(), ()>> {
    pub fn new(chain_start_identifier: impl Into<String>) -> KeyBuilder<DateKeyState<(), ()>> {
        KeyBuilder {
            state: DateKeyState {
                chain_start_identifier: chain_start_identifier.into(),
                secret_access_key: (),
                date: (),
            },
        }
    }
}
impl<DateT> KeyBuilder<DateKeyState<(), DateT>> {
    pub fn secret_access_key(
        self,
        secret_access_key: impl Into<String>,
    ) -> KeyBuilder<DateKeyState<String, DateT>> {
        KeyBuilder {
            state: DateKeyState {
                secret_access_key: secret_access_key.into(),
                chain_start_identifier: self.state.chain_start_identifier,
                date: self.state.date,
            },
        }
    }
}
impl<SecretAccessKeyT> KeyBuilder<DateKeyState<SecretAccessKeyT, ()>> {
    pub fn date(self, date: impl Into<Date>) -> KeyBuilder<DateKeyState<SecretAccessKeyT, Date>> {
        KeyBuilder {
            state: DateKeyState {
                date: date.into(),
                chain_start_identifier: self.state.chain_start_identifier,
                secret_access_key: self.state.secret_access_key,
            },
        }
    }
}
impl KeyBuilder<DateKeyState<String, Date>> {
    pub fn date_key(self) -> DateKey {
        let key = format!(
            "{}{}",
            &self.state.chain_start_identifier, &self.state.secret_access_key
        );
        let key = hmac::Key::new(ALGORITHM, key.as_bytes());

        let date = format!(
            "{:04}{:02}{:02}",
            self.state.date.year(),
            u8::from(self.state.date.month()),
            self.state.date.day()
        );

        let tag = hmac::sign(&key, date.as_bytes());
        DateKey(
            tag.as_ref()
                .try_into()
                .expect("hash output is expected length"),
        )
    }
    pub fn region(self, region: impl Into<String>) -> KeyBuilder<DateRegionKey> {
        KeyBuilder::from(self.date_key()).region(region)
    }
}

impl KeyBuilder<DateKey> {
    pub fn date_key(self) -> DateKey {
        self.state
    }
    pub fn region(self, region: impl Into<String>) -> KeyBuilder<DateRegionKey> {
        let key = self.state.into();
        let tag = hmac::sign(&key, region.into().as_bytes());
        KeyBuilder::from(DateRegionKey(
            tag.as_ref()
                .try_into()
                .expect("hash output is expected length"),
        ))
    }
}
impl KeyBuilder<DateRegionKey> {
    pub fn date_region_key(self) -> DateRegionKey {
        self.state
    }
    pub fn service(self, service: impl Into<String>) -> KeyBuilder<DateRegionServiceKey> {
        let key = self.state.into();
        let tag = hmac::sign(&key, service.into().as_bytes());
        KeyBuilder::from(DateRegionServiceKey(
            tag.as_ref()
                .try_into()
                .expect("hash output is expected length"),
        ))
    }
}
impl KeyBuilder<DateRegionServiceKey> {
    pub fn date_region_service_key(self) -> DateRegionServiceKey {
        self.state
    }
    pub fn signing_key(self, finishing_identifier: impl Into<String>) -> SigningKey {
        let key = self.state.into();
        let tag = hmac::sign(&key, finishing_identifier.into().as_bytes());
        SigningKey(
            tag.as_ref()
                .try_into()
                .expect("hash output is expected length"),
        )
    }
    pub fn aws_signing_key(self) -> SigningKey {
        self.signing_key("aws4_request")
    }
}

pub trait KeyBuilderState {}
impl<KeyT, DateT> KeyBuilderState for DateKeyState<KeyT, DateT> {}
impl KeyBuilderState for DateKey {}
impl KeyBuilderState for DateRegionKey {}
impl KeyBuilderState for DateRegionServiceKey {}
