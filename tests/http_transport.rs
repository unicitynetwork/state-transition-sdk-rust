//! Unit tests for the blocking HTTP JSON-RPC transport (`client::http`).
//!
//! These drive a real [`HttpAggregatorClient`] against a local loopback mock
//! server (via `new_insecure_http`), exercising the success path and every
//! error branch — request framing, headers, JSON-RPC error mapping, HTTP status
//! errors, certification rejection, inclusion-proof decoding, and the polling /
//! timeout loop — without touching live infrastructure.
#![cfg(feature = "http")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use unicity_token::api::{CertificationData, InclusionProof, StateId};
use unicity_token::cbor::{encode_array, encode_uint};
use unicity_token::client::{AggregatorClient, HttpAggregatorClient, HttpError};
use unicity_token::transaction::Token;

const FIXTURE: &str = include_str!("vectors/transition_flow.json");

// --- fixture helpers -------------------------------------------------------

fn field<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle).expect("key present") + needle.len();
    let rest = &json[start..];
    let q1 = rest.find('"').expect("open quote") + 1;
    let q2 = rest[q1..].find('"').expect("close quote") + q1;
    &rest[q1..q2]
}

/// A real `InclusionProof` and `CertificationData` taken from the cross-SDK
/// fixture (the first transfer of the Carol token).
fn fixture_proof_and_data() -> (InclusionProof, CertificationData) {
    let carol = hex::decode(field(FIXTURE, "carolToken")).unwrap();
    let token = Token::from_cbor(&carol).unwrap();
    let proof = token.transactions()[0].inclusion_proof().clone();
    let data = proof
        .certification_data
        .clone()
        .expect("fixture has cert data");
    (proof, data)
}

/// Wrap an inclusion proof as the `[blockNumber, InclusionProof]` response body
/// the aggregator returns, hex-encoded.
fn proof_response_hex(proof: &InclusionProof) -> String {
    let block = encode_uint(7);
    let body = encode_array(&[block.as_slice(), proof.to_cbor().as_slice()]);
    hex::encode(body)
}

// --- mock JSON-RPC server --------------------------------------------------

/// A loopback HTTP server that records requests and replies with canned
/// responses (response `i` for connection `i`, repeating the last one).
struct MockServer {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl MockServer {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();

        std::thread::spawn(move || {
            for (i, stream) in listener.incoming().enumerate() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let request = read_http_request(&mut stream);

                let response = responses
                    .get(i)
                    .or_else(|| responses.last())
                    .cloned()
                    .unwrap_or_default();
                let response = correlate_response_id(response, &request);
                captured.lock().unwrap().push(request);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });

        MockServer {
            url: format!("http://127.0.0.1:{port}/"),
            requests,
        }
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn last_request(&self) -> String {
        self.requests
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

fn correlate_response_id(response: Vec<u8>, request: &str) -> Vec<u8> {
    let Ok(response_text) = String::from_utf8(response.clone()) else {
        return response;
    };
    let Some((headers, body)) = response_text.split_once("\r\n\r\n") else {
        return response;
    };
    let Some(request_body) = request.split_once("\r\n\r\n").map(|(_, body)| body) else {
        return response;
    };
    let Ok(request_json) = serde_json::from_str::<serde_json::Value>(request_body) else {
        return response;
    };
    let Some(request_id) = request_json.get("id") else {
        return response;
    };
    let Ok(mut response_json) = serde_json::from_str::<serde_json::Value>(body) else {
        return response;
    };
    let Some(object) = response_json.as_object_mut() else {
        return response;
    };
    if !object.contains_key("id") {
        return response;
    }
    object.insert("id".to_string(), request_id.clone());
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .unwrap_or("200 OK");
    http_response(status, &response_json.to_string())
}

/// Read a full HTTP request (headers + Content-Length body) from the stream.
fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    let header_end = pos + 4;
                    let content_length = content_length(&buf[..header_end]);
                    if buf.len() >= header_end + content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    for line in text.lines() {
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            if let Ok(n) = value.trim().parse::<usize>() {
                return n;
            }
        }
    }
    0
}

fn http_response(status_line: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn redirect_response(status_line: &str, location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn ok_json(result: &str) -> Vec<u8> {
    http_response(
        "200 OK",
        &format!(r#"{{"jsonrpc":"2.0","id":"1","result":{result}}}"#),
    )
}

fn client(url: &str) -> HttpAggregatorClient {
    HttpAggregatorClient::new_insecure_http(url).with_polling(Duration::from_millis(5), 3)
}

// --- tests -----------------------------------------------------------------

#[test]
fn submit_success_sends_method_and_state_id_header() {
    let server = MockServer::start(vec![ok_json(r#"{"status":"SUCCESS"}"#)]);
    let (_, data) = fixture_proof_and_data();

    client(&server.url)
        .submit_certification_request(&data)
        .expect("submit should succeed");

    let request = server.last_request();
    assert!(request.starts_with("POST "), "expected POST: {request}");
    assert!(request.contains("certification_request"));
    assert!(request.to_ascii_lowercase().contains("x-state-id:"));
}

#[test]
fn submit_rejected_status_maps_to_rejected_error() {
    let server = MockServer::start(vec![ok_json(
        r#"{"status":"SIGNATURE_VERIFICATION_FAILED"}"#,
    )]);
    let (_, data) = fixture_proof_and_data();

    let err = client(&server.url)
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Rejected(ref s) if s == "SIGNATURE_VERIFICATION_FAILED"),
        "unexpected: {err}"
    );
}

#[test]
fn jsonrpc_error_object_maps_to_rpc_error() {
    let body = r#"{"jsonrpc":"2.0","id":"1","error":{"code":-32000,"message":"boom"}}"#;
    let server = MockServer::start(vec![http_response("200 OK", body)]);
    let (_, data) = fixture_proof_and_data();

    let err = client(&server.url)
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Rpc { code: -32000, ref message } if message == "boom"),
        "unexpected: {err}"
    );
}

#[test]
fn http_status_error_is_surfaced() {
    let server = MockServer::start(vec![http_response("500 Internal Server Error", "nope")]);
    let (_, data) = fixture_proof_and_data();

    let err = client(&server.url)
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Http { status: 500, .. }),
        "unexpected: {err}"
    );
}

#[test]
fn missing_result_maps_to_decode_error() {
    let server = MockServer::start(vec![http_response(
        "200 OK",
        r#"{"jsonrpc":"2.0","id":"1"}"#,
    )]);
    let (_, data) = fixture_proof_and_data();

    let err = client(&server.url)
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(matches!(err, HttpError::Decode(_)), "unexpected: {err}");
}

#[test]
fn get_inclusion_proof_returns_complete_proof() {
    let (proof, data) = fixture_proof_and_data();
    let server = MockServer::start(vec![ok_json(&format!(
        "\"{}\"",
        proof_response_hex(&proof)
    ))]);

    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());
    let got = client(&server.url)
        .get_inclusion_proof(&state_id)
        .expect("should return a complete proof");
    assert!(got.certification_data.is_some());
    assert!(got.inclusion_certificate.is_some());
    assert_eq!(server.request_count(), 1, "should not poll once complete");

    // The state-id header is not sent for proof lookups.
    assert!(!server
        .last_request()
        .to_ascii_lowercase()
        .contains("x-api-key:"));
}

#[test]
fn get_inclusion_proof_polls_then_times_out_on_non_inclusion() {
    let (proof, data) = fixture_proof_and_data();
    // A non-inclusion proof: valid unicity certificate but no certification/path.
    let non_inclusion = InclusionProof {
        certification_data: None,
        inclusion_certificate: None,
        unicity_certificate: proof.unicity_certificate.clone(),
    };
    let response = ok_json(&format!("\"{}\"", proof_response_hex(&non_inclusion)));
    let server = MockServer::start(vec![response]);

    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());
    let err = client(&server.url)
        .get_inclusion_proof(&state_id)
        .unwrap_err();
    assert!(matches!(err, HttpError::Timeout), "unexpected: {err}");
    assert_eq!(
        server.request_count(),
        3,
        "should poll exactly poll_attempts times"
    );
}

#[test]
fn get_inclusion_proof_rejects_non_string_result() {
    let server = MockServer::start(vec![ok_json("123")]);
    let (_, data) = fixture_proof_and_data();
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    let err = client(&server.url)
        .get_inclusion_proof(&state_id)
        .unwrap_err();
    assert!(matches!(err, HttpError::Decode(_)), "unexpected: {err}");
}

#[test]
fn get_inclusion_proof_rejects_bad_hex_and_bad_cbor() {
    let (_, data) = fixture_proof_and_data();
    let state_id = StateId::derive(data.lock_script(), data.source_state_hash());

    // Not hex.
    let server = MockServer::start(vec![ok_json("\"zzzz\"")]);
    assert!(matches!(
        client(&server.url).get_inclusion_proof(&state_id),
        Err(HttpError::Decode(_))
    ));

    // Valid hex, but not a valid `[blockNumber, InclusionProof]` payload.
    let server = MockServer::start(vec![ok_json("\"deadbeef\"")]);
    assert!(matches!(
        client(&server.url).get_inclusion_proof(&state_id),
        Err(HttpError::Decode(_))
    ));
}

#[test]
fn transport_error_when_server_unreachable() {
    // Nothing is listening on this port.
    let (_, data) = fixture_proof_and_data();
    let err = client("http://127.0.0.1:1/")
        .submit_certification_request(&data)
        .unwrap_err();
    assert!(
        matches!(err, HttpError::Transport(_) | HttpError::Http { .. }),
        "unexpected: {err}"
    );
}

#[test]
fn requests_do_not_follow_redirects() {
    for (status_line, status) in [
        ("301 Moved Permanently", 301),
        ("302 Found", 302),
        ("303 See Other", 303),
        ("307 Temporary Redirect", 307),
        ("308 Permanent Redirect", 308),
    ] {
        let server = MockServer::start(vec![redirect_response(
            status_line,
            "http://127.0.0.1:1/steal",
        )]);
        let (_, data) = fixture_proof_and_data();
        let err = client(&server.url)
            .submit_certification_request(&data)
            .unwrap_err();
        assert!(
            matches!(err, HttpError::Http { status: actual, .. } if actual == status),
            "redirect must be returned instead of followed: {err}"
        );
    }
}

#[test]
fn oversized_error_response_is_rejected() {
    let body = "x".repeat(64 * 1024 + 1);
    let server = MockServer::start(vec![http_response("500 Internal Server Error", &body)]);
    let (_, data) = fixture_proof_and_data();
    assert!(matches!(
        client(&server.url).submit_certification_request(&data),
        Err(HttpError::ResponseTooLarge { limit: 65_536 })
    ));
}
