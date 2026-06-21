//! Canonical CBOR encoders. Each function returns the encoded bytes for a
//! single CBOR data item.

use alloc::vec::Vec;

use super::{major, simple};

/// Emit the initial byte(s): major type combined with `value`, using the
/// minimal power-of-two argument width (matching the reference SDKs).
fn push_head(out: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        out.push(major | (value as u8));
    } else if value <= u8::MAX as u64 {
        out.push(major | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(major | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(major | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn head(major: u8, value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    push_head(&mut out, major, value);
    out
}

/// Encode an unsigned integer.
pub fn encode_uint(value: u64) -> Vec<u8> {
    head(major::UINT, value)
}

/// Encode a byte string.
pub fn encode_byte_string(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 9);
    push_head(&mut out, major::BYTES, data.len() as u64);
    out.extend_from_slice(data);
    out
}

/// Encode a UTF-8 text string.
pub fn encode_text_string(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() + 9);
    push_head(&mut out, major::TEXT, bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}

/// Frame already-encoded `items` as a definite-length CBOR array.
pub fn encode_array(items: &[&[u8]]) -> Vec<u8> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut out = Vec::with_capacity(total + 9);
    push_head(&mut out, major::ARRAY, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Wrap an already-encoded item in a CBOR tag.
pub fn encode_tag(tag: u64, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 9);
    push_head(&mut out, major::TAG, tag);
    out.extend_from_slice(content);
    out
}

/// Encode the CBOR `null` simple value (`0xf6`).
pub fn encode_null() -> Vec<u8> {
    alloc::vec![simple::NULL]
}

/// Encode a boolean (`0xf5` / `0xf4`).
pub fn encode_bool(value: bool) -> Vec<u8> {
    alloc::vec![if value { simple::TRUE } else { simple::FALSE }]
}

/// Encode `value` with `encoder`, or `null` when `value` is `None`.
pub fn encode_nullable<T: ?Sized, F>(value: Option<&T>, encoder: F) -> Vec<u8>
where
    F: FnOnce(&T) -> Vec<u8>,
{
    match value {
        Some(v) => encoder(v),
        None => encode_null(),
    }
}

/// Encode a canonical CBOR map from already-encoded `(key, value)` pairs.
///
/// Entries are sorted by encoded-key bytes (bytewise, shorter key first) to
/// match the reference SDKs. Duplicate input keys are canonicalized with
/// deterministic last-writer-wins semantics and are never emitted twice.
pub fn encode_map(entries: &mut [(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    entries.sort_by(|a, b| {
        let n = a.0.len().min(b.0.len());
        match a.0[..n].cmp(&b.0[..n]) {
            core::cmp::Ordering::Equal => a.0.len().cmp(&b.0.len()),
            other => other,
        }
    });

    // Canonical maps cannot contain duplicate keys. This infallible encoder
    // canonicalizes duplicate input with deterministic last-writer-wins
    // semantics, so it never emits an ambiguous map.
    let unique_count = entries
        .iter()
        .enumerate()
        .filter(|(i, (key, _))| {
            entries
                .get(i + 1)
                .map_or(true, |(next_key, _)| next_key != key)
        })
        .count();
    let total: usize = entries
        .iter()
        .enumerate()
        .filter(|(i, (key, _))| {
            entries
                .get(i + 1)
                .map_or(true, |(next_key, _)| next_key != key)
        })
        .map(|(_, (k, v))| k.len() + v.len())
        .sum();
    let mut out = Vec::with_capacity(total + 9);
    push_head(&mut out, major::MAP, unique_count as u64);
    for (i, (k, v)) in entries.iter().enumerate() {
        if entries
            .get(i + 1)
            .is_some_and(|(next_key, _)| next_key == k)
        {
            continue;
        }
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn uint_widths() {
        assert_eq!(encode_uint(0), hex!("00"));
        assert_eq!(encode_uint(23), hex!("17"));
        assert_eq!(encode_uint(24), hex!("1818"));
        assert_eq!(encode_uint(255), hex!("18ff"));
        assert_eq!(encode_uint(256), hex!("190100"));
        assert_eq!(encode_uint(65535), hex!("19ffff"));
        assert_eq!(encode_uint(65536), hex!("1a00010000"));
        assert_eq!(encode_uint(4294967295), hex!("1affffffff"));
        assert_eq!(encode_uint(4294967296), hex!("1b0000000100000000"));
    }

    #[test]
    fn byte_and_text_strings() {
        assert_eq!(encode_byte_string(&[]), hex!("40"));
        assert_eq!(encode_byte_string(&[1, 2, 3]), hex!("43010203"));
        assert_eq!(encode_text_string("a"), hex!("6161"));
    }

    #[test]
    fn array_and_tag() {
        // [1, 2] -> 0x82 0x01 0x02
        let one = encode_uint(1);
        let two = encode_uint(2);
        assert_eq!(encode_array(&[&one, &two]), hex!("820102"));
        // tag(39032, []) header is d9 9878
        assert_eq!(encode_tag(39032, &encode_array(&[])), hex!("d9987880"));
    }

    #[test]
    fn datahash_sha256_zero_vector() {
        // Reference DataHashTest.java: SHA-256 of 32 zero bytes serialises to
        // a byte string of the 34-byte imprint: 5822 0000 <32 zero bytes>.
        let imprint = [0u8; 34]; // alg id 0x0000 (SHA-256) + 32 zero bytes
        let mut expected = alloc::vec![0x58u8, 0x22]; // bstr, length 34
        expected.extend_from_slice(&[0u8; 34]);
        assert_eq!(encode_byte_string(&imprint), expected);
    }

    #[test]
    fn map_canonical_ordering() {
        // Keys 1 and 2 supplied out of order must come out sorted.
        let mut entries = alloc::vec![
            (encode_uint(2), encode_uint(20)),
            (encode_uint(1), encode_uint(10)),
        ];
        // sorted: {1:10, 2:20} = a2 01 0a 02 14
        assert_eq!(encode_map(&mut entries), hex!("a2010a0214"));
    }

    #[test]
    fn map_duplicate_keys_use_last_value() {
        let mut entries = alloc::vec![
            (encode_uint(1), encode_uint(10)),
            (encode_uint(1), encode_uint(20)),
        ];
        assert_eq!(encode_map(&mut entries), hex!("a10114"));
    }
}
