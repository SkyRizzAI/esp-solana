//! Minimal base64 encoder (standard alphabet, no padding omission).

use alloc::string::String;
use crate::types::{SdkError, Result};
use alloc::vec::Vec;

const ENCODE_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode table: maps ASCII byte -> 6-bit value (0xFF = invalid, 0xFE = padding '=').
const DECODE_TABLE: [u8; 128] = {
    let mut t = [0xFFu8; 128];
    let mut i = 0u8;
    while i < 64 {
        t[ENCODE_TABLE[i as usize] as usize] = i;
        i += 1;
    }
    t[b'=' as usize] = 0xFE;
    t
};

/// Base64-encode bytes using standard alphabet with padding.
pub fn encode(input: &[u8]) -> String {
    let out_len = (input.len() + 2) / 3 * 4;
    let mut out = String::with_capacity(out_len);

    let chunks = input.chunks_exact(3);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let n = (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32;
        out.push(ENCODE_TABLE[(n >> 18 & 0x3F) as usize] as char);
        out.push(ENCODE_TABLE[(n >> 12 & 0x3F) as usize] as char);
        out.push(ENCODE_TABLE[(n >> 6 & 0x3F) as usize] as char);
        out.push(ENCODE_TABLE[(n & 0x3F) as usize] as char);
    }

    match remainder.len() {
        1 => {
            let n = (remainder[0] as u32) << 16;
            out.push(ENCODE_TABLE[(n >> 18 & 0x3F) as usize] as char);
            out.push(ENCODE_TABLE[(n >> 12 & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (remainder[0] as u32) << 16 | (remainder[1] as u32) << 8;
            out.push(ENCODE_TABLE[(n >> 18 & 0x3F) as usize] as char);
            out.push(ENCODE_TABLE[(n >> 12 & 0x3F) as usize] as char);
            out.push(ENCODE_TABLE[(n >> 6 & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }

    out
}

/// Base64-decode a string into bytes.
pub fn decode(input: &str) -> Result<Vec<u8>> {
    let input = input.as_bytes();
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() % 4 != 0 {
        return Err(SdkError::Invalid);
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3);

    for chunk in input.chunks_exact(4) {
        let mut vals = [0u8; 4];
        let mut pad_count = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            if b >= 128 {
                return Err(SdkError::Invalid);
            }
            let v = DECODE_TABLE[b as usize];
            if v == 0xFF {
                return Err(SdkError::Invalid);
            }
            if v == 0xFE {
                // Padding '=' only allowed in positions 2 and 3
                if i < 2 {
                    return Err(SdkError::Invalid);
                }
                pad_count += 1;
                vals[i] = 0;
            } else {
                if pad_count > 0 {
                    // Data after padding
                    return Err(SdkError::Invalid);
                }
                vals[i] = v;
            }
        }

        let n = (vals[0] as u32) << 18
            | (vals[1] as u32) << 12
            | (vals[2] as u32) << 6
            | vals[3] as u32;

        out.push((n >> 16) as u8);
        if pad_count < 2 {
            out.push((n >> 8) as u8);
        }
        if pad_count < 1 {
            out.push(n as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn encode_hello() {
        assert_eq!(encode(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn encode_hello_world() {
        assert_eq!(encode(b"Hello World!"), "SGVsbG8gV29ybGQh");
    }

    #[test]
    fn roundtrip() {
        let data = b"Solana transaction bytes here!";
        let encoded = encode(data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_one_byte() {
        assert_eq!(encode(&[0xFF]), "/w==");
    }

    #[test]
    fn encode_two_bytes() {
        assert_eq!(encode(&[0xFF, 0xFE]), "//4=");
    }

    #[test]
    fn decode_invalid() {
        assert!(decode("!!!").is_err());
    }
}
