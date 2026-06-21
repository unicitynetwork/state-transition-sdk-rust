//! Canonical CBOR decoder.
//!
//! [`Decoder`] reads a single CBOR data item from the front of a byte slice and
//! exposes typed accessors. Compound accessors ([`Decoder::array`],
//! [`Decoder::tag`], [`Decoder::map`]) return borrowed sub-slices, each holding
//! exactly one encoded child item, which the caller decodes recursively.
//!
//! Indefinite lengths and the reserved additional-info values (28-30) are
//! rejected. The decoder is strict about major types so that a forged structure
//! cannot be silently coerced into a different shape.

use alloc::vec::Vec;

use super::{major, simple};
use crate::error::CborError;

type Result<T> = core::result::Result<T, CborError>;

/// Resource limits applied to untrusted CBOR decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum bytes in one public decoder input.
    pub max_input_bytes: usize,
    /// Maximum nested array/map/tag depth.
    pub max_nesting_depth: usize,
    /// Maximum entries in one array or map.
    pub max_collection_items: usize,
    /// Maximum total CBOR items reachable from one top-level item.
    pub max_total_items: usize,
}

impl DecodeLimits {
    /// Conservative defaults suitable for token verification on a host.
    pub const DEFAULT: Self = Self {
        max_input_bytes: 16 * 1024 * 1024,
        max_nesting_depth: 64,
        max_collection_items: 4096,
        max_total_items: 1_000_000,
    };
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A zero-copy reader over CBOR bytes.
#[derive(Debug, Clone, Copy)]
pub struct Decoder<'a> {
    bytes: &'a [u8],
    limits: DecodeLimits,
}

/// The decoded initial-byte "head": major type, raw argument, and the number of
/// bytes the head occupies.
#[derive(Debug, Clone, Copy)]
struct Head {
    major: u8,
    arg: u64,
    len: usize,
}

fn read_head(bytes: &[u8]) -> Result<Head> {
    let first = *bytes.first().ok_or(CborError::UnexpectedEof)?;
    let major = first & 0xe0;
    let info = first & 0x1f;
    let (arg, len) = match info {
        0..=23 => (info as u64, 1),
        24 => (*bytes.get(1).ok_or(CborError::UnexpectedEof)? as u64, 2),
        25 => {
            let b = bytes.get(1..3).ok_or(CborError::UnexpectedEof)?;
            (u16::from_be_bytes([b[0], b[1]]) as u64, 3)
        }
        26 => {
            let b = bytes.get(1..5).ok_or(CborError::UnexpectedEof)?;
            (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 5)
        }
        27 => {
            let b = bytes.get(1..9).ok_or(CborError::UnexpectedEof)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(b);
            (u64::from_be_bytes(a), 9)
        }
        other => return Err(CborError::UnsupportedAdditionalInfo(other)),
    };
    let minimum = match info {
        24 => Some(24),
        25 => Some(1 << 8),
        26 => Some(1 << 16),
        27 => Some(1 << 32),
        _ => None,
    };
    if minimum.is_some_and(|minimum| arg < minimum) {
        return Err(CborError::NonCanonicalEncoding);
    }
    Ok(Head { major, arg, len })
}

fn canonical_key_cmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let common = a.len().min(b.len());
    match a[..common].cmp(&b[..common]) {
        core::cmp::Ordering::Equal => a.len().cmp(&b.len()),
        other => other,
    }
}

fn checked_usize(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| CborError::IntegerOverflow)
}

fn collection_count(value: u64, limits: DecodeLimits) -> Result<usize> {
    let count = checked_usize(value)?;
    if count > limits.max_collection_items {
        return Err(CborError::LimitExceeded("CBOR collection items"));
    }
    Ok(count)
}

/// Total length in bytes of the first CBOR item in `bytes`.
fn item_len_with_budget(
    bytes: &[u8],
    limits: DecodeLimits,
    depth: usize,
    remaining_items: &mut usize,
) -> Result<usize> {
    *remaining_items = remaining_items
        .checked_sub(1)
        .ok_or(CborError::LimitExceeded("total CBOR items"))?;
    if bytes.len() > limits.max_input_bytes {
        return Err(CborError::LimitExceeded("CBOR input bytes"));
    }
    if depth > limits.max_nesting_depth {
        return Err(CborError::LimitExceeded("CBOR nesting depth"));
    }
    let head = read_head(bytes)?;
    match head.major {
        major::UINT | major::NEGINT | major::SIMPLE => Ok(head.len),
        major::BYTES | major::TEXT => {
            let value_len = checked_usize(head.arg)?;
            let total = head
                .len
                .checked_add(value_len)
                .ok_or(CborError::IntegerOverflow)?;
            if total > bytes.len() {
                return Err(CborError::UnexpectedEof);
            }
            Ok(total)
        }
        major::ARRAY => {
            let count = collection_count(head.arg, limits)?;
            if count > bytes.len().saturating_sub(head.len) {
                return Err(CborError::UnexpectedEof);
            }
            let mut pos = head.len;
            for _ in 0..count {
                let rest = bytes.get(pos..).ok_or(CborError::UnexpectedEof)?;
                pos = pos
                    .checked_add(item_len_with_budget(
                        rest,
                        limits,
                        depth + 1,
                        remaining_items,
                    )?)
                    .ok_or(CborError::IntegerOverflow)?;
            }
            Ok(pos)
        }
        major::MAP => {
            let count = collection_count(head.arg, limits)?;
            let item_count = count.checked_mul(2).ok_or(CborError::IntegerOverflow)?;
            if item_count > bytes.len().saturating_sub(head.len) {
                return Err(CborError::UnexpectedEof);
            }
            let mut pos = head.len;
            for _ in 0..item_count {
                let rest = bytes.get(pos..).ok_or(CborError::UnexpectedEof)?;
                pos = pos
                    .checked_add(item_len_with_budget(
                        rest,
                        limits,
                        depth + 1,
                        remaining_items,
                    )?)
                    .ok_or(CborError::IntegerOverflow)?;
            }
            Ok(pos)
        }
        major::TAG => {
            let rest = bytes.get(head.len..).ok_or(CborError::UnexpectedEof)?;
            head.len
                .checked_add(item_len_with_budget(
                    rest,
                    limits,
                    depth + 1,
                    remaining_items,
                )?)
                .ok_or(CborError::IntegerOverflow)
        }
        _ => Err(CborError::UnsupportedAdditionalInfo(0)),
    }
}

fn item_len(bytes: &[u8], limits: DecodeLimits, depth: usize) -> Result<usize> {
    let mut remaining_items = limits.max_total_items;
    item_len_with_budget(bytes, limits, depth, &mut remaining_items)
}

impl<'a> Decoder<'a> {
    /// Create a decoder over `bytes` with [`DecodeLimits::DEFAULT`].
    pub fn new(bytes: &'a [u8]) -> Self {
        Self::with_limits(bytes, DecodeLimits::DEFAULT)
    }

    /// Create a decoder with caller-selected resource limits.
    pub fn with_limits(bytes: &'a [u8], limits: DecodeLimits) -> Self {
        Decoder { bytes, limits }
    }

    /// The remaining bytes (the item this decoder points at, possibly followed
    /// by trailing data).
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Assert that the decoder's item consumes the entire input (no trailing
    /// bytes). Use at the top level to reject extra data appended by an attacker.
    pub fn finish(&self) -> Result<()> {
        if item_len(self.bytes, self.limits, 0)? != self.bytes.len() {
            return Err(CborError::TrailingBytes);
        }
        Ok(())
    }

    fn expect(&self, want: u8) -> Result<Head> {
        if self.bytes.len() > self.limits.max_input_bytes {
            return Err(CborError::LimitExceeded("CBOR input bytes"));
        }
        let head = read_head(self.bytes)?;
        if head.major != want {
            return Err(CborError::UnexpectedMajorType {
                expected: want >> 5,
                found: head.major >> 5,
            });
        }
        Ok(head)
    }

    /// Decode an unsigned integer.
    pub fn uint(&self) -> Result<u64> {
        let head = self.expect(major::UINT)?;
        if head.len != self.bytes.len() {
            return Err(CborError::TrailingBytes);
        }
        Ok(head.arg)
    }

    /// Decode a byte string, returning a borrowed slice.
    pub fn bytes_value(&self) -> Result<&'a [u8]> {
        let head = self.expect(major::BYTES)?;
        let value_len = checked_usize(head.arg)?;
        let end = head
            .len
            .checked_add(value_len)
            .ok_or(CborError::IntegerOverflow)?;
        let value = self
            .bytes
            .get(head.len..end)
            .ok_or(CborError::UnexpectedEof)?;
        if end != self.bytes.len() {
            return Err(CborError::TrailingBytes);
        }
        Ok(value)
    }

    /// Decode a UTF-8 text string.
    pub fn text(&self) -> Result<&'a str> {
        let head = self.expect(major::TEXT)?;
        let value_len = checked_usize(head.arg)?;
        let end = head
            .len
            .checked_add(value_len)
            .ok_or(CborError::IntegerOverflow)?;
        let raw = self
            .bytes
            .get(head.len..end)
            .ok_or(CborError::UnexpectedEof)?;
        if end != self.bytes.len() {
            return Err(CborError::TrailingBytes);
        }
        core::str::from_utf8(raw).map_err(|_| CborError::IntegerOverflow)
    }

    /// Decode a boolean.
    pub fn bool(&self) -> Result<bool> {
        if self.bytes.len() != 1 {
            return Err(CborError::TrailingBytes);
        }
        match self.bytes.first() {
            Some(&simple::TRUE) => Ok(true),
            Some(&simple::FALSE) => Ok(false),
            Some(_) => Err(CborError::UnexpectedMajorType {
                expected: 7,
                found: self.bytes[0] >> 5,
            }),
            None => Err(CborError::UnexpectedEof),
        }
    }

    /// Returns `true` if the current item is the CBOR `null` simple value.
    pub fn is_null(&self) -> bool {
        self.bytes.first() == Some(&simple::NULL)
    }

    /// Decode a nullable item: `None` for `null`, else `Some(decoder(child))`.
    pub fn nullable<T, F>(&self, f: F) -> core::result::Result<Option<T>, crate::Error>
    where
        F: FnOnce(Decoder<'a>) -> core::result::Result<T, crate::Error>,
    {
        if self.is_null() {
            self.finish()?;
            Ok(None)
        } else {
            f(*self).map(Some)
        }
    }

    /// Decode a definite-length array into per-element decoders.
    ///
    /// If `expected` is `Some(n)`, the array must hold exactly `n` elements.
    pub fn array(&self, expected: Option<usize>) -> Result<Vec<Decoder<'a>>> {
        self.finish()?;
        let head = self.expect(major::ARRAY)?;
        let count = collection_count(head.arg, self.limits)?;
        if let Some(n) = expected {
            if n != count {
                return Err(CborError::UnexpectedArrayLength {
                    expected: n,
                    found: count,
                });
            }
        }
        if count > self.bytes.len().saturating_sub(head.len) {
            return Err(CborError::UnexpectedEof);
        }
        let mut out = Vec::new();
        out.try_reserve(count)
            .map_err(|_| CborError::LimitExceeded("CBOR decoder allocation"))?;
        let mut pos = head.len;
        for _ in 0..count {
            let rest = self.bytes.get(pos..).ok_or(CborError::UnexpectedEof)?;
            let len = item_len(rest, self.limits, 1)?;
            let item = rest.get(..len).ok_or(CborError::UnexpectedEof)?;
            out.push(Decoder::with_limits(item, self.limits));
            pos = pos.checked_add(len).ok_or(CborError::IntegerOverflow)?;
        }
        if pos != self.bytes.len() {
            return Err(CborError::TrailingBytes);
        }
        Ok(out)
    }

    /// Decode a tag, returning `(tag_number, inner_decoder)`.
    pub fn tag(&self) -> Result<(u64, Decoder<'a>)> {
        self.finish()?;
        let head = self.expect(major::TAG)?;
        let rest = self.bytes.get(head.len..).ok_or(CborError::UnexpectedEof)?;
        let len = item_len(rest, self.limits, 1)?;
        let end = head
            .len
            .checked_add(len)
            .ok_or(CborError::IntegerOverflow)?;
        if end != self.bytes.len() {
            return Err(CborError::TrailingBytes);
        }
        Ok((head.arg, Decoder::with_limits(&rest[..len], self.limits)))
    }

    /// Decode a tag and assert it equals `expected`, returning the inner decoder.
    pub fn expect_tag(&self, expected: u64) -> Result<Decoder<'a>> {
        let (tag, inner) = self.tag()?;
        if tag != expected {
            return Err(CborError::UnexpectedTag {
                expected,
                found: tag,
            });
        }
        Ok(inner)
    }

    /// Decode a definite-length map into `(key, value)` decoder pairs, in the
    /// order they appear on the wire.
    pub fn map(&self) -> Result<Vec<(Decoder<'a>, Decoder<'a>)>> {
        self.finish()?;
        let head = self.expect(major::MAP)?;
        let count = collection_count(head.arg, self.limits)?;
        let item_count = count.checked_mul(2).ok_or(CborError::IntegerOverflow)?;
        if item_count > self.bytes.len().saturating_sub(head.len) {
            return Err(CborError::UnexpectedEof);
        }
        let mut out = Vec::new();
        out.try_reserve(count)
            .map_err(|_| CborError::LimitExceeded("CBOR decoder allocation"))?;
        let mut pos = head.len;
        let mut previous_key: Option<&[u8]> = None;
        for _ in 0..count {
            let krest = self.bytes.get(pos..).ok_or(CborError::UnexpectedEof)?;
            let klen = item_len(krest, self.limits, 1)?;
            let key = krest.get(..klen).ok_or(CborError::UnexpectedEof)?;
            if let Some(previous) = previous_key {
                match canonical_key_cmp(previous, key) {
                    core::cmp::Ordering::Less => {}
                    core::cmp::Ordering::Equal => return Err(CborError::DuplicateMapKey),
                    core::cmp::Ordering::Greater => return Err(CborError::NonCanonicalMapOrder),
                }
            }
            previous_key = Some(key);
            pos = pos.checked_add(klen).ok_or(CborError::IntegerOverflow)?;
            let vrest = self.bytes.get(pos..).ok_or(CborError::UnexpectedEof)?;
            let vlen = item_len(vrest, self.limits, 1)?;
            let value = vrest.get(..vlen).ok_or(CborError::UnexpectedEof)?;
            out.push((
                Decoder::with_limits(key, self.limits),
                Decoder::with_limits(value, self.limits),
            ));
            pos = pos.checked_add(vlen).ok_or(CborError::IntegerOverflow)?;
        }
        if pos != self.bytes.len() {
            return Err(CborError::TrailingBytes);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::encode;
    use hex_literal::hex;

    #[test]
    fn roundtrip_uint() {
        for v in [0u64, 23, 24, 255, 256, 65535, 65536, 1 << 40] {
            let enc = encode::encode_uint(v);
            assert_eq!(Decoder::new(&enc).uint().unwrap(), v);
        }
    }

    #[test]
    fn roundtrip_array_of_bytes() {
        let a = encode::encode_byte_string(&[0xaa, 0xbb]);
        let b = encode::encode_byte_string(&[0xcc]);
        let arr = encode::encode_array(&[&a, &b]);
        let d = Decoder::new(&arr);
        let items = d.array(Some(2)).unwrap();
        assert_eq!(items[0].bytes_value().unwrap(), &[0xaa, 0xbb]);
        assert_eq!(items[1].bytes_value().unwrap(), &[0xcc]);
        d.finish().unwrap();
    }

    #[test]
    fn tag_roundtrip() {
        let inner = encode::encode_uint(7);
        let tagged = encode::encode_tag(39032, &inner);
        let d = Decoder::new(&tagged);
        assert_eq!(d.expect_tag(39032).unwrap().uint().unwrap(), 7);
        assert!(d.expect_tag(39033).is_err());
    }

    #[test]
    fn rejects_wrong_major() {
        let enc = encode::encode_uint(1);
        assert!(matches!(
            Decoder::new(&enc).bytes_value(),
            Err(CborError::UnexpectedMajorType { .. })
        ));
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0x9f = array, additional info 31 (indefinite) -> rejected.
        assert!(Decoder::new(&hex!("9f")).array(None).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut enc = encode::encode_uint(1);
        enc.push(0xff);
        assert_eq!(Decoder::new(&enc).finish(), Err(CborError::TrailingBytes));
        assert_eq!(Decoder::new(&enc).uint(), Err(CborError::TrailingBytes));
    }

    #[test]
    fn rejects_non_minimal_heads() {
        for enc in [
            &hex!("1801")[..],
            &hex!("190018")[..],
            &hex!("1a00000100")[..],
            &hex!("1b0000000000010000")[..],
        ] {
            assert_eq!(
                Decoder::new(enc).uint(),
                Err(CborError::NonCanonicalEncoding)
            );
        }
    }

    #[test]
    fn rejects_non_canonical_maps() {
        assert!(matches!(
            Decoder::new(&hex!("a202000100")).map(),
            Err(CborError::NonCanonicalMapOrder)
        ));
        assert!(matches!(
            Decoder::new(&hex!("a201000101")).map(),
            Err(CborError::DuplicateMapKey)
        ));
    }

    #[test]
    fn rejects_huge_declared_collection_without_panicking() {
        let huge = hex!("9bffffffffffffffff");
        assert!(matches!(
            Decoder::new(&huge).array(None),
            Err(CborError::LimitExceeded(_)) | Err(CborError::IntegerOverflow)
        ));
    }

    #[test]
    fn rejects_excessive_nesting() {
        let mut nested = alloc::vec![0xc0; DecodeLimits::DEFAULT.max_nesting_depth + 1];
        nested.push(0x00);
        assert!(matches!(
            Decoder::new(&nested).finish(),
            Err(CborError::LimitExceeded("CBOR nesting depth"))
        ));
    }

    #[test]
    fn supports_tighter_caller_limits() {
        let encoded = encode::encode_byte_string(&[1, 2, 3]);
        let limits = DecodeLimits {
            max_input_bytes: 2,
            ..DecodeLimits::DEFAULT
        };
        assert!(matches!(
            Decoder::with_limits(&encoded, limits).bytes_value(),
            Err(CborError::LimitExceeded("CBOR input bytes"))
        ));
    }

    #[test]
    fn enforces_total_item_budget() {
        let item = encode::encode_uint(0);
        let encoded = encode::encode_array(&[&item, &item]);
        let limits = DecodeLimits {
            max_total_items: 2,
            ..DecodeLimits::DEFAULT
        };
        assert!(matches!(
            Decoder::with_limits(&encoded, limits).array(None),
            Err(CborError::LimitExceeded("total CBOR items"))
        ));
    }

    #[test]
    fn nullable_decodes_none_and_some() {
        let n = encode::encode_null();
        let some = encode::encode_byte_string(&[1, 2]);
        let dn = Decoder::new(&n)
            .nullable(|d| d.bytes_value().map(|b| b.to_vec()).map_err(Into::into))
            .unwrap();
        assert_eq!(dn, None);
        let ds = Decoder::new(&some)
            .nullable(|d| d.bytes_value().map(|b| b.to_vec()).map_err(Into::into))
            .unwrap();
        assert_eq!(ds, Some(alloc::vec![1, 2]));
    }
}
