//! Blocking JSON-RPC [`AggregatorClient`] for talking to a live aggregator /
//! gateway (`http` feature).
//!
//! This is the synchronous transport for production use: it speaks the same
//! JSON-RPC protocol as the reference SDKs (methods `certification_request` and
//! `get_inclusion_proof.v2`), authenticates with an optional `X-API-Key`, and
//! **polls** `get_inclusion_proof` until the aggregator has certified the state
//! (so the [`mint`](super::mint)/[`transfer`](super::transfer) helpers work
//! unchanged against live infrastructure).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroize;

use crate::api::certification_request::CertificationRequest;
use crate::api::inclusion_proof::InclusionProof;
use crate::api::{CertificationData, StateId};
use crate::cbor::Decoder;

use super::AggregatorClient;

const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_PROOF_HEX_CHARS: usize = MAX_RESPONSE_BODY_BYTES - 1024;

/// Errors from the HTTP aggregator client.
#[derive(Debug)]
pub enum HttpError {
    /// Unsafe or invalid client configuration.
    Configuration(String),
    /// Network/transport failure.
    Transport(String),
    /// Non-2xx HTTP response.
    Http {
        /// HTTP status code.
        status: u16,
        /// Response body.
        body: String,
    },
    /// JSON-RPC `error` object returned by the aggregator.
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// JSON-RPC error message.
        message: String,
    },
    /// A response could not be decoded.
    Decode(String),
    /// A response exceeded the explicit transport limit.
    ResponseTooLarge {
        /// Maximum accepted bytes.
        limit: usize,
    },
    /// The aggregator rejected the certification request (status != SUCCESS).
    Rejected(String),
    /// Polling for the inclusion proof exceeded the configured attempts.
    Timeout,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::Configuration(m) => write!(f, "configuration error: {m}"),
            HttpError::Transport(m) => write!(f, "transport error: {m}"),
            HttpError::Http { status, body } => write!(f, "http {status}: {body:?}"),
            HttpError::Rpc { code, message } => {
                write!(f, "json-rpc error {code}: {message:?}")
            }
            HttpError::Decode(m) => write!(f, "decode error: {m}"),
            HttpError::ResponseTooLarge { limit } => {
                write!(f, "response exceeds {limit} byte limit")
            }
            HttpError::Rejected(s) => write!(f, "certification rejected: {s:?}"),
            HttpError::Timeout => write!(f, "timed out waiting for inclusion proof"),
        }
    }
}

impl std::error::Error for HttpError {}

/// A blocking JSON-RPC aggregator client.
#[derive(Clone)]
pub struct HttpAggregatorClient {
    url: String,
    api_key: Option<SecretString>,
    agent: ureq::Agent,
    poll_interval: Duration,
    poll_attempts: u32,
    allow_insecure_http: bool,
}

#[derive(Clone)]
struct SecretString(String);

impl SecretString {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for HttpAggregatorClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpAggregatorClient")
            .field("url", &"<redacted>")
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("poll_interval", &self.poll_interval)
            .field("poll_attempts", &self.poll_attempts)
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish_non_exhaustive()
    }
}

impl HttpAggregatorClient {
    /// Create a client pointing at the aggregator's JSON-RPC `url`.
    pub fn new(url: impl Into<String>) -> Self {
        HttpAggregatorClient {
            url: url.into(),
            api_key: None,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .https_only(true)
                .redirects(0)
                .build(),
            poll_interval: Duration::from_secs(1),
            poll_attempts: 60,
            allow_insecure_http: false,
        }
    }

    /// Create and immediately validate a production HTTPS endpoint.
    pub fn try_new(url: impl Into<String>) -> Result<Self, HttpError> {
        let client = Self::new(url);
        client.validate_endpoint()?;
        Ok(client)
    }

    /// Create a redirect-free client that permits plaintext HTTP without an
    /// API key. Intended only for loopback development and tests.
    pub fn new_insecure_http(url: impl Into<String>) -> Self {
        HttpAggregatorClient {
            url: url.into(),
            api_key: None,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .redirects(0)
                .build(),
            poll_interval: Duration::from_secs(1),
            poll_attempts: 60,
            allow_insecure_http: true,
        }
    }

    /// Set the API key sent as `X-API-Key` on certification requests.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(SecretString(key.into()));
        self
    }

    /// Configure inclusion-proof polling: wait `interval` between up to
    /// `attempts` probes.
    pub fn with_polling(mut self, interval: Duration, attempts: u32) -> Self {
        self.poll_interval = interval;
        self.poll_attempts = attempts;
        self
    }

    fn validate_endpoint(&self) -> Result<url::Url, HttpError> {
        let parsed = url::Url::parse(&self.url)
            .map_err(|e| HttpError::Configuration(format!("invalid gateway URL: {e}")))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
            return Err(HttpError::Configuration(
                "gateway URL must be an absolute HTTP(S) URL".to_string(),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(HttpError::Configuration(
                "gateway URL must not contain credentials".to_string(),
            ));
        }
        if parsed.fragment().is_some() {
            return Err(HttpError::Configuration(
                "gateway URL must not contain a fragment".to_string(),
            ));
        }
        if parsed.scheme() != "https" && !self.allow_insecure_http {
            return Err(HttpError::Configuration(
                "gateway URL must use HTTPS".to_string(),
            ));
        }
        if parsed.scheme() != "https" && self.api_key.is_some() {
            return Err(HttpError::Configuration(
                "API keys must never be sent over plaintext HTTP".to_string(),
            ));
        }
        Ok(parsed)
    }

    /// Perform one JSON-RPC call, returning the `result` value.
    fn rpc(
        &self,
        method: &str,
        params: serde_json::Value,
        headers: &[(&str, &str)],
    ) -> Result<serde_json::Value, HttpError> {
        self.validate_endpoint()?;
        let id = request_id();
        let body = serde_json::json!({
            "id": id,
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        })
        .to_string();

        let mut request = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json");
        for (k, v) in headers {
            request = request.set(k, v);
        }

        let response = match request.send_string(&body) {
            Ok(r) => r,
            Err(ureq::Error::Status(status, r)) => {
                return Err(HttpError::Http {
                    status,
                    body: read_response(r, MAX_ERROR_BODY_BYTES)?,
                });
            }
            Err(e) => return Err(HttpError::Transport(e.to_string())),
        };
        if !(200..300).contains(&response.status()) {
            return Err(HttpError::Http {
                status: response.status(),
                body: read_response(response, MAX_ERROR_BODY_BYTES)?,
            });
        }

        let text = read_response(response, MAX_RESPONSE_BODY_BYTES)?;
        decode_rpc_response(&text, &id)
    }
}

fn read_response(response: ureq::Response, limit: usize) -> Result<String, HttpError> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| HttpError::Transport(e.to_string()))?;
    if bytes.len() > limit {
        return Err(HttpError::ResponseTooLarge { limit });
    }
    String::from_utf8(bytes).map_err(|e| HttpError::Decode(e.to_string()))
}

fn decode_rpc_response(text: &str, expected_id: &str) -> Result<serde_json::Value, HttpError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| HttpError::Decode(e.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| HttpError::Decode("JSON-RPC response must be an object".to_string()))?;
    if object.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Err(HttpError::Decode(
            "invalid or missing JSON-RPC version".to_string(),
        ));
    }
    let response_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HttpError::Decode("invalid or missing JSON-RPC id".to_string()))?;
    if response_id != expected_id {
        return Err(HttpError::Decode("JSON-RPC id mismatch".to_string()));
    }

    match (object.get("result"), object.get("error")) {
        (Some(_), Some(_)) => Err(HttpError::Decode(
            "JSON-RPC response contains both result and error".to_string(),
        )),
        (Some(result), None) => Ok(result.clone()),
        (None, Some(error)) => {
            let code = error
                .get("code")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| HttpError::Decode("invalid JSON-RPC error code".to_string()))?;
            let message = error
                .get("message")
                .and_then(|v| v.as_str())
                .ok_or_else(|| HttpError::Decode("invalid JSON-RPC error message".to_string()))?;
            Err(HttpError::Rpc {
                code,
                message: message.to_string(),
            })
        }
        (None, None) => Err(HttpError::Decode(
            "JSON-RPC response contains neither result nor error".to_string(),
        )),
    }
}

/// Decode the `[blockNumber, InclusionProof]` response payload.
fn decode_inclusion_proof_response(bytes: &[u8]) -> Result<InclusionProof, HttpError> {
    let d = Decoder::new(bytes);
    d.finish().map_err(|e| HttpError::Decode(e.to_string()))?;
    let items = d
        .array(Some(2))
        .map_err(|e| HttpError::Decode(e.to_string()))?;
    InclusionProof::from_cbor(items[1]).map_err(|e| HttpError::Decode(e.to_string()))
}

impl AggregatorClient for HttpAggregatorClient {
    type Error = HttpError;

    fn submit_certification_request(&self, data: &CertificationData) -> Result<(), HttpError> {
        let request = CertificationRequest::new(data);
        let state_id_hex = hex::encode(request.state_id().bytes());
        let params = serde_json::Value::String(hex::encode(request.to_cbor()));

        let mut headers: Vec<(&str, &str)> = alloc::vec![("X-State-ID", state_id_hex.as_str())];
        if let Some(key) = &self.api_key {
            headers.push(("X-API-Key", key.expose()));
        }

        let result = self.rpc("certification_request", params, &headers)?;
        let status = result
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        if status != "SUCCESS" {
            return Err(HttpError::Rejected(status.to_string()));
        }
        Ok(())
    }

    fn get_inclusion_proof(&self, state_id: &StateId) -> Result<InclusionProof, HttpError> {
        let params = serde_json::json!({ "stateId": hex::encode(state_id.bytes()) });

        for attempt in 0..self.poll_attempts {
            let result = self.rpc("get_inclusion_proof.v2", params.clone(), &[])?;
            let encoded = result
                .as_str()
                .ok_or_else(|| HttpError::Decode("expected hex string".to_string()))?;
            if encoded.len() > MAX_PROOF_HEX_CHARS {
                return Err(HttpError::ResponseTooLarge {
                    limit: MAX_PROOF_HEX_CHARS,
                });
            }
            let bytes = hex::decode(encoded).map_err(|e| HttpError::Decode(e.to_string()))?;
            let proof = decode_inclusion_proof_response(&bytes)?;

            // A non-inclusion proof (no certification data yet) means the state
            // has not been certified; keep polling.
            if proof.certification_data.is_some() && proof.inclusion_certificate.is_some() {
                return Ok(proof);
            }
            if attempt + 1 < self.poll_attempts {
                std::thread::sleep(self.poll_interval);
            }
        }
        Err(HttpError::Timeout)
    }
}

/// A random JSON-RPC request id.
fn request_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        return "0".to_string();
    }
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_endpoint_and_api_key() {
        let client =
            HttpAggregatorClient::new("https://user:password@example.invalid/rpc?secret=1")
                .with_api_key("AUDIT_SECRET");
        let debug = format!("{client:?}");
        assert!(!debug.contains("AUDIT_SECRET"));
        assert!(!debug.contains("password"));
        assert!(!debug.contains("secret=1"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn production_client_requires_safe_https_url() {
        assert!(HttpAggregatorClient::try_new("http://example.invalid").is_err());
        assert!(HttpAggregatorClient::try_new("not a URL").is_err());
        assert!(HttpAggregatorClient::try_new("https://user:pass@example.invalid").is_err());
        assert!(HttpAggregatorClient::try_new("https://example.invalid/rpc#fragment").is_err());
        assert!(HttpAggregatorClient::try_new("https://example.invalid/rpc").is_ok());
    }

    #[test]
    fn insecure_client_refuses_api_keys_before_network_io() {
        let client = HttpAggregatorClient::new_insecure_http("http://127.0.0.1:1")
            .with_api_key("must-not-leak");
        assert!(matches!(
            client.rpc("test", serde_json::json!({}), &[]),
            Err(HttpError::Configuration(_))
        ));
    }

    #[test]
    fn validates_json_rpc_envelope_and_correlation() {
        assert_eq!(
            decode_rpc_response(
                r#"{"jsonrpc":"2.0","id":"expected","result":7}"#,
                "expected",
            )
            .unwrap(),
            serde_json::json!(7)
        );
        for response in [
            r#"{"jsonrpc":"1.0","id":"expected","result":7}"#,
            r#"{"jsonrpc":"2.0","id":"wrong","result":7}"#,
            r#"{"jsonrpc":"2.0","id":"expected","result":7,"error":{"code":1,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":"expected"}"#,
        ] {
            assert!(matches!(
                decode_rpc_response(response, "expected"),
                Err(HttpError::Decode(_))
            ));
        }
    }

    #[test]
    fn insecure_http_endpoint_is_allowed_without_key() {
        let client = HttpAggregatorClient::new_insecure_http("http://127.0.0.1:8080/rpc");
        assert!(client.validate_endpoint().is_ok());
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(HttpAggregatorClient::new("ftp://example.invalid/rpc")
            .validate_endpoint()
            .is_err());
    }

    #[test]
    fn request_id_is_unique_hex() {
        let a = request_id();
        let b = request_id();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn decode_inclusion_proof_response_rejects_malformed() {
        use crate::cbor::{encode_array, encode_uint};

        // Empty input.
        assert!(decode_inclusion_proof_response(&[]).is_err());

        // Wrong array length (a single element).
        let one = encode_array(&[encode_uint(1).as_slice()]);
        assert!(decode_inclusion_proof_response(&one).is_err());

        // Well-formed 2-element array whose second element is not a proof.
        let two = encode_array(&[encode_uint(1).as_slice(), encode_uint(2).as_slice()]);
        assert!(decode_inclusion_proof_response(&two).is_err());

        // Trailing bytes after the payload are rejected.
        let mut trailing = two.clone();
        trailing.push(0xff);
        assert!(decode_inclusion_proof_response(&trailing).is_err());
    }
}
