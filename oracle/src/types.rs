use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use nunchi_common::Address;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

/// Maximum UTF-8 byte length of a feed identifier.
pub const MAX_FEED_ID_BYTES: usize = 128;

/// Maximum byte length of one submitted feed payload.
pub const MAX_FEED_PAYLOAD_BYTES: usize = 64 * 1024;

/// Invalid feed identifier configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FeedIdError {
    #[error("feed id must not be empty")]
    Empty,
    #[error("feed id has {actual} bytes, but the maximum is {max}")]
    TooLong { max: usize, actual: usize },
}

/// Supported payload encodings for oracle feed bodies.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedPayloadEncoding {
    Raw = 0,
    Json = 1,
}

impl TryFrom<u8> for FeedPayloadEncoding {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Json),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl Write for FeedPayloadEncoding {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_u8(*self as u8);
    }
}

impl Read for FeedPayloadEncoding {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Self::try_from(u8::read(buf)?)
    }
}

impl EncodeSize for FeedPayloadEncoding {
    fn encode_size(&self) -> usize {
        1
    }
}

/// Typed feed identifier used for namespacing independently shaped feeds.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FeedId(String);

impl FeedId {
    pub fn new(value: impl Into<String>) -> Result<Self, FeedIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(FeedIdError::Empty);
        }
        let actual = value.len();
        if actual > MAX_FEED_ID_BYTES {
            return Err(FeedIdError::TooLong {
                max: MAX_FEED_ID_BYTES,
                actual,
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FeedId {
    type Error = FeedIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for FeedId {
    type Error = FeedIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Write for FeedId {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.as_bytes().write(buf);
    }
}

impl Read for FeedId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(1..=MAX_FEED_ID_BYTES), ()))?;
        let value = String::from_utf8(bytes)
            .map_err(|_| Error::Invalid("feed id", "feed id must be valid utf-8"))?;
        Self::new(value).map_err(|_| Error::Invalid("feed id", "invalid"))
    }
}

impl EncodeSize for FeedId {
    fn encode_size(&self) -> usize {
        self.0.as_bytes().encode_size()
    }
}

/// Invalid feed payload configuration.
#[derive(Debug, Error)]
pub enum FeedPayloadError {
    #[error("feed payload has {actual} bytes, but the maximum is {max}")]
    TooLarge { max: usize, actual: usize },
    #[error("feed payload JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("feed payload is encoded as {actual:?}, not {expected:?}")]
    WrongEncoding {
        expected: FeedPayloadEncoding,
        actual: FeedPayloadEncoding,
    },
}

/// Opaque oracle payload with an explicit encoding tag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeedPayload {
    pub encoding: FeedPayloadEncoding,
    pub body: Vec<u8>,
}

impl FeedPayload {
    pub fn new(
        encoding: FeedPayloadEncoding,
        body: impl Into<Vec<u8>>,
    ) -> Result<Self, FeedPayloadError> {
        let body = body.into();
        let actual = body.len();
        if actual > MAX_FEED_PAYLOAD_BYTES {
            return Err(FeedPayloadError::TooLarge {
                max: MAX_FEED_PAYLOAD_BYTES,
                actual,
            });
        }
        Ok(Self { encoding, body })
    }

    pub fn raw(body: impl Into<Vec<u8>>) -> Result<Self, FeedPayloadError> {
        Self::new(FeedPayloadEncoding::Raw, body)
    }

    pub fn json<T: Serialize>(value: &T) -> Result<Self, FeedPayloadError> {
        Self::new(FeedPayloadEncoding::Json, serde_json::to_vec(value)?)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn decode_json<T: DeserializeOwned>(&self) -> Result<T, FeedPayloadError> {
        if self.encoding != FeedPayloadEncoding::Json {
            return Err(FeedPayloadError::WrongEncoding {
                expected: FeedPayloadEncoding::Json,
                actual: self.encoding,
            });
        }
        Ok(serde_json::from_slice(&self.body)?)
    }
}

impl Write for FeedPayload {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.encoding.write(buf);
        self.body.write(buf);
    }
}

impl Read for FeedPayload {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            encoding: FeedPayloadEncoding::read(buf)?,
            body: Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=MAX_FEED_PAYLOAD_BYTES), ()))?,
        })
    }
}

impl EncodeSize for FeedPayload {
    fn encode_size(&self) -> usize {
        self.encoding.encode_size() + self.body.encode_size()
    }
}

/// Feed registration details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedDefinition {
    pub id: FeedId,
    pub owner: Address,
    pub metadata: FeedPayload,
}

impl Write for FeedDefinition {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.id.write(buf);
        self.owner.write(buf);
        self.metadata.write(buf);
    }
}

impl Read for FeedDefinition {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            id: FeedId::read(buf)?,
            owner: Address::read(buf)?,
            metadata: FeedPayload::read(buf)?,
        })
    }
}

impl EncodeSize for FeedDefinition {
    fn encode_size(&self) -> usize {
        self.id.encode_size() + self.owner.encode_size() + self.metadata.encode_size()
    }
}

/// Latest accepted feed body stored for a registered feed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedSubmission {
    pub observed_at_ms: u64,
    pub sequence: u64,
    pub payload: FeedPayload,
}

impl Write for FeedSubmission {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.observed_at_ms.write(buf);
        self.sequence.write(buf);
        self.payload.write(buf);
    }
}

impl Read for FeedSubmission {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            observed_at_ms: u64::read(buf)?,
            sequence: u64::read(buf)?,
            payload: FeedPayload::read(buf)?,
        })
    }
}

impl EncodeSize for FeedSubmission {
    fn encode_size(&self) -> usize {
        self.observed_at_ms.encode_size() + self.sequence.encode_size() + self.payload.encode_size()
    }
}

/// Convenience view containing a feed definition plus its latest accepted submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedRecord {
    pub definition: FeedDefinition,
    pub latest: Option<FeedSubmission>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use serde_json::json;

    #[test]
    fn feed_id_rejects_empty_and_oversized_values() {
        assert_eq!(FeedId::new("").unwrap_err(), FeedIdError::Empty);
        assert!(matches!(
            FeedId::new("x".repeat(MAX_FEED_ID_BYTES + 1)).unwrap_err(),
            FeedIdError::TooLong { .. }
        ));
    }

    #[test]
    fn json_payload_roundtrips() {
        let payload = FeedPayload::json(&json!({
            "price": "123.45",
            "legs": [{"symbol": "BTC"}, {"symbol": "USD"}]
        }))
        .unwrap();
        let decoded: serde_json::Value = payload.decode_json().unwrap();
        assert_eq!(decoded["price"], "123.45");
    }

    #[test]
    fn decode_rejects_oversized_payloads() {
        let mut encoded = Vec::new();
        FeedPayloadEncoding::Raw.write(&mut encoded);
        vec![0u8; MAX_FEED_PAYLOAD_BYTES + 1].write(&mut encoded);
        assert!(FeedPayload::decode(encoded.as_slice()).is_err());
    }

    #[test]
    fn feed_definition_roundtrips() {
        let definition = FeedDefinition {
            id: FeedId::new("btc/usd").unwrap(),
            owner: Address::external(&nunchi_crypto::PrivateKey::ed25519_from_seed(1).public_key()),
            metadata: FeedPayload::json(&json!({"kind": "price"})).unwrap(),
        };
        let decoded = FeedDefinition::decode(definition.encode()).unwrap();
        assert_eq!(decoded, definition);
    }
}
