//! Shard identifier: a variable-length bit string with an end-marker byte
//! encoding, ported exactly from the reference SDKs.

use alloc::vec::Vec;

use crate::error::Error;

/// A shard identifier (a bit string of `length` bits stored MSB-first).
#[derive(Clone, PartialEq, Eq)]
pub struct ShardId {
    bits: Vec<u8>,
    length: usize,
}

impl ShardId {
    /// Number of bits in the shard id.
    pub fn length(&self) -> usize {
        self.length
    }

    /// The bit at `index` (MSB-first within each byte).
    pub fn get_bit(&self, index: usize) -> Result<u8, Error> {
        if index >= self.length {
            return Err(Error::OutOfRange("ShardId bit index out of bounds"));
        }
        Ok((self.bits[index / 8] >> (7 - (index % 8))) & 1)
    }

    /// Whether this shard id is a bit-prefix of `data`.
    pub fn is_prefix_of(&self, data: &[u8]) -> bool {
        let full_bytes = self.length / 8;
        let remaining_bits = self.length % 8;
        if data.len() < full_bytes {
            return false;
        }
        if self.bits[..full_bytes] != data[..full_bytes] {
            return false;
        }
        if remaining_bits > 0 {
            let Some(&db) = data.get(full_bytes) else {
                return false;
            };
            let mask = 0xffu8.wrapping_shl(8 - remaining_bits as u32);
            if (self.bits[full_bytes] & mask) != (db & mask) {
                return false;
            }
        }
        true
    }

    /// Decode from the end-marker byte encoding.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut last_byte = *data.last().ok_or(Error::UnexpectedValue("empty ShardId"))?;
        for i in (1..=8usize).rev() {
            if last_byte & 1 == 1 {
                if i == 1 {
                    return Ok(ShardId {
                        bits: data[..data.len() - 1].to_vec(),
                        length: (data.len() - 1) * 8,
                    });
                }
                let mut bits = data[..data.len() - 1].to_vec();
                bits.push((last_byte >> 1) << (8 - i + 1));
                return Ok(ShardId {
                    bits,
                    length: (data.len() - 1) * 8 + i - 1,
                });
            }
            last_byte >>= 1;
        }
        Err(Error::UnexpectedValue("ShardId missing end marker"))
    }

    /// Encode to the end-marker byte form.
    pub fn encode(&self) -> Vec<u8> {
        let byte_count = self.length / 8;
        let bit_count = self.length % 8;
        let mut result = alloc::vec![0u8; byte_count + 1];
        result[..byte_count].copy_from_slice(&self.bits[..byte_count]);
        if bit_count == 0 {
            result[byte_count] = 0b1000_0000;
        } else {
            let v = self.bits[byte_count] & !(0xffu8 >> bit_count);
            result[byte_count] = v | (1 << (7 - bit_count));
        }
        result
    }
}

impl core::fmt::Debug for ShardId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ShardId(len={}, {})",
            self.length,
            hex::encode(&self.bits)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_shard_roundtrip() {
        let s = ShardId::decode(&[0x80]).unwrap();
        assert_eq!(s.length(), 0);
        assert_eq!(s.encode(), alloc::vec![0x80]);
    }
}
