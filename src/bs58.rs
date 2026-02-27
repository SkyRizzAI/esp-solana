//! Minimal base58 encoder/decoder (Bitcoin alphabet, used by Solana).

use alloc::string::String;
use alloc::vec::Vec;
use crate::types::{SdkError, Result};

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode table: maps ASCII byte -> base58 digit value (0xFF = invalid).
const DECODE: [u8; 128] = {
    let mut t = [0xFFu8; 128];
    let mut i = 0u8;
    while i < 58 {
        t[ALPHABET[i as usize] as usize] = i;
        i += 1;
    }
    t
};

/// Base58-encode arbitrary bytes.
pub fn encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    // Count leading zeros
    let mut zeros = 0;
    for &b in input {
        if b == 0 {
            zeros += 1;
        } else {
            break;
        }
    }

    // Allocate enough space (log(256)/log(58) ≈ 1.366)
    let size = input.len() * 138 / 100 + 1;
    let mut buf = alloc::vec![0u8; size];

    for &b in input {
        let mut carry = b as u32;
        let mut j = size;
        while j > 0 {
            j -= 1;
            carry += 256 * buf[j] as u32;
            buf[j] = (carry % 58) as u8;
            carry /= 58;
        }
    }

    // Skip leading zeros in buf
    let mut start = 0;
    while start < size && buf[start] == 0 {
        start += 1;
    }

    let mut out = String::with_capacity(zeros + size - start);
    for _ in 0..zeros {
        out.push('1');
    }
    for &digit in &buf[start..] {
        out.push(ALPHABET[digit as usize] as char);
    }
    out
}

/// Base58-decode a string into bytes.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let input = input.as_bytes();

    // Count leading '1's (represent leading zero bytes)
    let mut zeros = 0;
    for &b in input {
        if b == b'1' {
            zeros += 1;
        } else {
            break;
        }
    }

    let size = input.len() * 733 / 1000 + 1;
    let mut buf = alloc::vec![0u8; size];

    for &b in input {
        if b >= 128 {
            return Err(SdkError::Invalid);
        }
        let digit = DECODE[b as usize];
        if digit == 0xFF {
            return Err(SdkError::Invalid);
        }
        let mut carry = digit as u32;
        let mut j = size;
        while j > 0 {
            j -= 1;
            carry += 58 * buf[j] as u32;
            buf[j] = (carry % 256) as u8;
            carry /= 256;
        }
    }

    // Skip leading zeros in buf
    let mut start = 0;
    while start < size && buf[start] == 0 {
        start += 1;
    }

    let mut out = Vec::with_capacity(zeros + size - start);
    out.resize(zeros, 0u8);
    out.extend_from_slice(&buf[start..]);
    Ok(out)
}

/// Base58-decode exactly 32 bytes (for Pubkey / Hash).
pub fn decode_32(input: &str) -> Result<[u8; 32]> {
    let bytes = decode(input)?;
    if bytes.len() != 32 {
        return Err(SdkError::Invalid);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        assert_eq!(encode(b""), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn roundtrip_hello() {
        let encoded = encode(b"Hello World!");
        assert_eq!(encoded, "2NEpo7TZRRrLZSi2U");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, b"Hello World!");
    }

    #[test]
    fn leading_zeros() {
        let data = [0, 0, 0, 1, 2, 3];
        let encoded = encode(&data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn system_program_pubkey() {
        // System program is all zeros -> base58 "11111111111111111111111111111111"
        let zeros = [0u8; 32];
        let encoded = encode(&zeros);
        assert_eq!(encoded, "11111111111111111111111111111111");
        let decoded = decode_32(&encoded).unwrap();
        assert_eq!(decoded, zeros);
    }

    #[test]
    fn decode_invalid_char() {
        assert!(decode("0OIl").is_err()); // '0', 'O', 'I', 'l' are not in base58
    }

    #[test]
    fn decode_32_wrong_length() {
        assert!(decode_32("2NEpo7TZRRrLZSi2U").is_err()); // "Hello World!" is 12 bytes, not 32
    }
}
