use crate::{FeedObservation, PriceFeed};
use async_trait::async_trait;
use commonware_cryptography::sha256::Digest;
use commonware_formatting::from_hex;
use futures::{stream::BoxStream, StreamExt};
use nunchi_oracle::FeedId;
use reqwest::header::ACCEPT;
use serde::Deserialize;
use std::num::{ParseIntError, TryFromIntError};
use thiserror::Error;

/// Configuration for a live Hermes server-side event stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermesFeedConfig {
    /// Hermes endpoint root, for example `https://hermes.pyth.network`.
    pub endpoint: String,
    /// Pyth/Hermes price feed ID as 32-byte hex.
    pub price_id: String,
}

impl HermesFeedConfig {
    /// Create config for the public Pyth Hermes endpoint.
    pub fn public(price_id: impl Into<String>) -> Self {
        Self {
            endpoint: "https://hermes.pyth.network".to_string(),
            price_id: price_id.into(),
        }
    }
}

/// Live Hermes SSE price feed.
pub struct HermesFeed {
    price_id: String,
    stream: BoxStream<'static, reqwest::Result<bytes::Bytes>>,
    buffer: String,
}

impl HermesFeed {
    /// Connect to Hermes `/v2/updates/price/stream` with parsed Pyth prices enabled.
    pub async fn connect(config: HermesFeedConfig) -> Result<Self, HermesError> {
        let endpoint = config.endpoint.trim_end_matches('/');
        let url = format!("{endpoint}/v2/updates/price/stream");
        let response = reqwest::Client::new()
            .get(url)
            .header(ACCEPT, "text/event-stream")
            .query(&[("ids[]", config.price_id.as_str()), ("parsed", "true")])
            .send()
            .await?
            .error_for_status()?;

        Ok(Self {
            price_id: config.price_id,
            stream: response.bytes_stream().boxed(),
            buffer: String::new(),
        })
    }

    fn pop_event(&mut self) -> Option<String> {
        let index = self
            .buffer
            .find("\n\n")
            .or_else(|| self.buffer.find("\r\n\r\n"))?;
        let separator_len = if self.buffer[index..].starts_with("\r\n\r\n") {
            4
        } else {
            2
        };
        let event = self.buffer[..index].to_string();
        self.buffer.drain(..index + separator_len);
        Some(event)
    }
}

#[async_trait]
impl PriceFeed for HermesFeed {
    type Error = HermesError;

    async fn next(&mut self) -> Result<FeedObservation, Self::Error> {
        loop {
            while let Some(event) = self.pop_event() {
                if let Some(observation) = parse_sse_event(&event, &self.price_id)? {
                    return Ok(observation);
                }
            }

            let Some(chunk) = self.stream.next().await else {
                return Err(HermesError::StreamClosed);
            };
            let chunk = chunk?;
            let chunk = std::str::from_utf8(&chunk)?;
            self.buffer.push_str(chunk);
        }
    }
}

/// Errors from Hermes transport and payload normalization.
#[derive(Debug, Error)]
pub enum HermesError {
    #[error("hermes request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("hermes response was not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("hermes response was not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hermes integer field was invalid: {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("hermes price exponent is out of range: {0}")]
    ExponentRange(#[from] TryFromIntError),
    #[error("hermes integer conversion overflowed")]
    Overflow,
    #[error("hermes stream closed")]
    StreamClosed,
    #[error("hermes feed id must be 32 bytes of hex")]
    InvalidFeedId,
}

#[derive(Debug, Deserialize)]
struct HermesEnvelope {
    parsed: Vec<HermesParsedPrice>,
}

#[derive(Debug, Deserialize)]
struct HermesParsedPrice {
    id: String,
    price: HermesPrice,
}

#[derive(Debug, Deserialize)]
struct HermesPrice {
    price: String,
    conf: String,
    expo: i32,
    publish_time: u64,
}

/// Parse a Hermes JSON update and return the observation for `price_id`, if present.
pub fn parse_hermes_price_update(
    raw: &str,
    price_id: &str,
) -> Result<Option<FeedObservation>, HermesError> {
    let envelope: HermesEnvelope = serde_json::from_str(raw)?;
    for parsed in envelope.parsed {
        if parsed.id.eq_ignore_ascii_case(price_id) {
            return Ok(Some(parsed.price.try_into_observation()?));
        }
    }
    Ok(None)
}

/// Convert a 32-byte Hermes/Pyth price ID into the oracle feed identifier.
pub fn feed_id_from_hermes_id(price_id: &str) -> Result<FeedId, HermesError> {
    let raw = price_id.strip_prefix("0x").unwrap_or(price_id);
    let bytes = from_hex(raw).ok_or(HermesError::InvalidFeedId)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| HermesError::InvalidFeedId)?;
    Ok(FeedId(Digest(bytes)))
}

fn parse_sse_event(event: &str, price_id: &str) -> Result<Option<FeedObservation>, HermesError> {
    let mut data = String::new();
    for line in event.lines() {
        let line = line.trim_end_matches('\r');
        let Some(value) = line.strip_prefix("data:") else {
            continue;
        };
        if !data.is_empty() {
            data.push('\n');
        }
        data.push_str(value.trim_start());
    }
    if data.is_empty() {
        return Ok(None);
    }
    parse_hermes_price_update(&data, price_id)
}

impl HermesPrice {
    fn try_into_observation(self) -> Result<FeedObservation, HermesError> {
        let price = self.price.parse::<i128>()?;
        let confidence = self.conf.parse::<u128>()?;
        let publish_time_ms = self
            .publish_time
            .checked_mul(1_000)
            .ok_or(HermesError::Overflow)?;

        let (raw_value, confidence, raw_decimals) = if self.expo <= 0 {
            let decimals = u8::try_from(self.expo.checked_neg().ok_or(HermesError::Overflow)?)?;
            (price, confidence, decimals)
        } else {
            let multiplier = 10i128
                .checked_pow(u32::try_from(self.expo)?)
                .ok_or(HermesError::Overflow)?;
            let confidence_multiplier =
                u128::try_from(multiplier).map_err(|_| HermesError::Overflow)?;
            (
                price.checked_mul(multiplier).ok_or(HermesError::Overflow)?,
                confidence
                    .checked_mul(confidence_multiplier)
                    .ok_or(HermesError::Overflow)?,
                0,
            )
        };

        Ok(FeedObservation {
            raw_value,
            raw_decimals,
            publish_time_ms,
            confidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_id() -> String {
        "e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43".to_string()
    }

    #[test]
    fn parses_hermes_price_update() {
        let id = feed_id();
        let raw = format!(
            r#"{{
                "parsed": [{{
                    "id": "{id}",
                    "price": {{
                        "price": "123456789",
                        "conf": "1000",
                        "expo": -8,
                        "publish_time": 42
                    }}
                }}]
            }}"#
        );

        let observation = parse_hermes_price_update(&raw, &id).unwrap().unwrap();
        assert_eq!(
            observation,
            FeedObservation {
                raw_value: 123_456_789,
                raw_decimals: 8,
                publish_time_ms: 42_000,
                confidence: 1_000,
            }
        );
    }

    #[test]
    fn positive_exponent_is_scaled_to_integer_precision() {
        let id = feed_id();
        let raw = format!(
            r#"{{
                "parsed": [{{
                    "id": "{id}",
                    "price": {{
                        "price": "123",
                        "conf": "4",
                        "expo": 2,
                        "publish_time": 7
                    }}
                }}]
            }}"#
        );

        let observation = parse_hermes_price_update(&raw, &id).unwrap().unwrap();
        assert_eq!(
            observation,
            FeedObservation {
                raw_value: 12_300,
                raw_decimals: 0,
                publish_time_ms: 7_000,
                confidence: 400,
            }
        );
    }

    #[test]
    fn converts_hermes_feed_id() {
        let id = feed_id();
        let feed = feed_id_from_hermes_id(&id).unwrap();
        let expected: [u8; 32] = from_hex(&id).unwrap().try_into().unwrap();
        assert_eq!(feed.0 .0, expected);
    }
}
