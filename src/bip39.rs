//! BIP39 mnemonic generation, validation, and seed derivation.
//!
//! Supports 12-word and 24-word mnemonics (128-bit and 256-bit entropy).
//! Seed derivation uses PBKDF2-HMAC-SHA512 (2048 iterations) per the BIP39 spec.

use alloc::string::String;
use alloc::vec::Vec;
use crate::types::{SdkError, Result};
use crate::wordlist::WORDLIST;

/// A validated BIP39 mnemonic phrase.
#[derive(Clone)]
pub struct Mnemonic {
    /// Space-separated word string.
    phrase: String,
    /// Number of words (12 or 24).
    word_count: usize,
}

impl Mnemonic {
    /// Create a 12-word mnemonic from 16 bytes (128 bits) of entropy.
    ///
    /// The entropy should come from a cryptographically secure RNG
    /// (e.g., ESP32 hardware RNG via `esp_hal::rng::Rng`).
    pub fn from_entropy_128(entropy: &[u8; 16]) -> Result<Self> {
        Self::from_entropy(entropy)
    }

    /// Create a 24-word mnemonic from 32 bytes (256 bits) of entropy.
    pub fn from_entropy_256(entropy: &[u8; 32]) -> Result<Self> {
        Self::from_entropy(entropy)
    }

    /// Create a mnemonic from raw entropy (16 or 32 bytes).
    fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let ent_bits = entropy.len() * 8;
        if ent_bits != 128 && ent_bits != 256 {
            return Err(SdkError::Invalid);
        }

        // CS = ENT / 32 (checksum bits)
        let cs_bits = ent_bits / 32;
        let total_bits = ent_bits + cs_bits;
        let word_count = total_bits / 11;

        // SHA-256 hash for checksum
        let hash = hmac_sha256::Hash::hash(entropy);
        let checksum_byte = hash[0]; // first byte contains checksum bits

        // Build bit stream: entropy bytes + checksum bits
        // Extract 11-bit indices from the combined bit stream
        let mut words = Vec::with_capacity(word_count);

        for i in 0..word_count {
            let bit_offset = i * 11;
            let mut index: u16 = 0;

            for bit in 0..11 {
                let pos = bit_offset + bit;
                let byte_val = if pos < ent_bits {
                    // From entropy
                    entropy[pos / 8]
                } else {
                    // From checksum
                    checksum_byte
                };
                let bit_pos = 7 - (pos % 8);
                if pos >= ent_bits {
                    // Checksum bit position: offset within checksum byte
                    let cs_pos = pos - ent_bits;
                    let cs_bit_pos = 7 - cs_pos;
                    if (checksum_byte >> cs_bit_pos) & 1 == 1 {
                        index |= 1 << (10 - bit);
                    }
                } else if (byte_val >> bit_pos) & 1 == 1 {
                    index |= 1 << (10 - bit);
                }
            }

            if (index as usize) >= WORDLIST.len() {
                return Err(SdkError::Invalid);
            }
            words.push(WORDLIST[index as usize]);
        }

        let phrase = words.join(" ");
        Ok(Self { phrase, word_count })
    }

    /// Parse and validate a mnemonic phrase string.
    ///
    /// Verifies word count (12 or 24), all words are in the BIP39 wordlist,
    /// and the checksum is correct.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let word_count = words.len();

        if word_count != 12 && word_count != 24 {
            return Err(SdkError::Invalid);
        }

        // Look up each word's index
        let mut indices = Vec::with_capacity(word_count);
        for word in &words {
            let idx = WORDLIST.iter().position(|w| w == word)
                .ok_or(SdkError::Invalid)?;
            indices.push(idx as u16);
        }

        // Reconstruct entropy + checksum from 11-bit indices
        let total_bits = word_count * 11;
        let cs_bits = word_count / 3; // CS = ENT/32, and word_count = (ENT+CS)/11
        let ent_bits = total_bits - cs_bits;
        let ent_bytes = ent_bits / 8;

        let mut entropy = alloc::vec![0u8; ent_bytes];
        let mut checksum_bits: u8 = 0;

        for (i, &idx) in indices.iter().enumerate() {
            for bit in 0..11 {
                let pos = i * 11 + bit;
                let bit_val = (idx >> (10 - bit)) & 1;

                if pos < ent_bits {
                    if bit_val == 1 {
                        entropy[pos / 8] |= 1 << (7 - (pos % 8));
                    }
                } else {
                    let cs_pos = pos - ent_bits;
                    if bit_val == 1 {
                        checksum_bits |= 1 << (7 - cs_pos);
                    }
                }
            }
        }

        // Verify checksum
        let hash = hmac_sha256::Hash::hash(&entropy);
        let expected_mask = 0xFFu8 << (8 - cs_bits);
        if (hash[0] & expected_mask) != (checksum_bits & expected_mask) {
            return Err(SdkError::Invalid);
        }

        let phrase = words.join(" ");
        Ok(Self { phrase, word_count })
    }

    /// Get the mnemonic phrase as a string.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Get the word count (12 or 24).
    pub fn word_count(&self) -> usize {
        self.word_count
    }

    /// Derive a 64-byte seed using PBKDF2-HMAC-SHA512.
    ///
    /// `passphrase` is an optional BIP39 passphrase (empty string for no passphrase).
    /// This is the standard BIP39 seed derivation with 2048 iterations.
    pub fn derive_seed(&self, passphrase: &str) -> [u8; 64] {
        // Salt = "mnemonic" + passphrase
        let mut salt = Vec::with_capacity(8 + passphrase.len());
        salt.extend_from_slice(b"mnemonic");
        salt.extend_from_slice(passphrase.as_bytes());

        pbkdf2_hmac_sha512(self.phrase.as_bytes(), &salt, 2048)
    }
}

/// PBKDF2-HMAC-SHA512 implementation.
///
/// For BIP39: dkLen = 64, hLen = 64, so only one block (T1) is needed.
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    // U1 = HMAC-SHA512(password, salt || INT_32_BE(1))
    let mut salt_with_index = Vec::with_capacity(salt.len() + 4);
    salt_with_index.extend_from_slice(salt);
    salt_with_index.extend_from_slice(&1u32.to_be_bytes()); // block index = 1

    let mut u_prev = hmac_sha512::HMAC::mac(salt_with_index, password);
    let mut result = u_prev;

    // U2..Uc
    for _ in 1..iterations {
        let u_next = hmac_sha512::HMAC::mac(u_prev, password);
        for (r, u) in result.iter_mut().zip(u_next.iter()) {
            *r ^= u;
        }
        u_prev = u_next;
    }

    result
}

impl core::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't leak mnemonic in debug output
        write!(f, "Mnemonic({} words)", self.word_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_entropy_128_produces_12_words() {
        let entropy = [0u8; 16];
        let m = Mnemonic::from_entropy_128(&entropy).unwrap();
        assert_eq!(m.word_count(), 12);
        // All-zero entropy should give "abandon" repeated 11 times + "about"
        assert_eq!(m.phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }

    #[test]
    fn from_entropy_256_produces_24_words() {
        let entropy = [0u8; 32];
        let m = Mnemonic::from_entropy_256(&entropy).unwrap();
        assert_eq!(m.word_count(), 24);
        // All-zero 256-bit entropy
        assert_eq!(m.phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art");
    }

    #[test]
    fn from_phrase_valid_12_words() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = Mnemonic::from_phrase(phrase).unwrap();
        assert_eq!(m.word_count(), 12);
        assert_eq!(m.phrase(), phrase);
    }

    #[test]
    fn from_phrase_invalid_checksum() {
        // Change last word to break checksum
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(Mnemonic::from_phrase(phrase).is_err());
    }

    #[test]
    fn from_phrase_invalid_word() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz";
        assert!(Mnemonic::from_phrase(phrase).is_err());
    }

    #[test]
    fn from_phrase_wrong_count() {
        let phrase = "abandon abandon abandon";
        assert!(Mnemonic::from_phrase(phrase).is_err());
    }

    #[test]
    fn roundtrip_entropy_to_phrase() {
        let entropy: [u8; 16] = [0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
                                  0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f];
        let m = Mnemonic::from_entropy_128(&entropy).unwrap();
        // Verify the phrase can be parsed back
        let m2 = Mnemonic::from_phrase(m.phrase()).unwrap();
        assert_eq!(m.phrase(), m2.phrase());
    }

    #[test]
    fn derive_seed_known_vector() {
        // BIP39 test vector: all-zero entropy (128-bit) with no passphrase
        // Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed = m.derive_seed("");

        // Known BIP39 seed for this mnemonic (from reference implementations)
        // First 4 bytes should be: 5eb00bbd...
        assert_eq!(seed[0], 0x5e);
        assert_eq!(seed[1], 0xb0);
        assert_eq!(seed[2], 0x0b);
        assert_eq!(seed[3], 0xbd);
    }

    #[test]
    fn derive_seed_with_passphrase() {
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed_no_pass = m.derive_seed("");
        let seed_with_pass = m.derive_seed("mypassword");

        // Different passphrase should give different seed
        assert_ne!(seed_no_pass, seed_with_pass);
    }

    #[test]
    fn bip39_test_vector_128bit() {
        // Official BIP39 test vector:
        // Entropy: 00000000000000000000000000000000
        // Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        // Seed (no passphrase): 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let seed = m.derive_seed("");

        let expected: [u8; 64] = [
            0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
            0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
            0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
            0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
            0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
            0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
            0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
            0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
        ];
        assert_eq!(seed, expected);
    }
}
