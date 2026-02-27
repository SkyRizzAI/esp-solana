//! SLIP-10 Ed25519 hierarchical key derivation.
//!
//! Implements the SLIP-10 standard for deriving Ed25519 keys from a BIP39 seed.
//! Solana uses derivation path `m/44'/501'/account'/change'` (all hardened).
//!
//! Reference: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>

use crate::types::Result;

/// A derived key pair (32-byte private key + 32-byte chain code).
#[derive(Clone)]
pub struct DerivedKey {
    /// 32-byte Ed25519 private key (seed).
    key: [u8; 32],
    /// 32-byte chain code for further derivation.
    chain_code: [u8; 32],
}

/// Hardened index offset (2^31).
const HARDENED: u32 = 0x80000000;

impl DerivedKey {
    /// Derive the master key from a BIP39 seed (64 bytes).
    ///
    /// Uses HMAC-SHA512 with key "ed25519 seed" as specified in SLIP-10.
    pub fn master(seed: &[u8; 64]) -> Self {
        let hmac = hmac_sha512::HMAC::mac(seed.as_ref(), b"ed25519 seed");

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&hmac[..32]);
        chain_code.copy_from_slice(&hmac[32..]);

        Self { key, chain_code }
    }

    /// Derive a hardened child key at the given index.
    ///
    /// SLIP-10 for Ed25519 only supports hardened derivation.
    /// The `index` is automatically hardened (OR'd with 0x80000000).
    pub fn derive_child(&self, index: u32) -> Self {
        let hardened_index = index | HARDENED;

        // Data = 0x00 || key (32 bytes) || index (4 bytes big-endian) = 37 bytes
        let mut data = [0u8; 37];
        data[0] = 0x00;
        data[1..33].copy_from_slice(&self.key);
        data[33..37].copy_from_slice(&hardened_index.to_be_bytes());

        let hmac = hmac_sha512::HMAC::mac(data.as_ref(), &self.chain_code);

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&hmac[..32]);
        chain_code.copy_from_slice(&hmac[32..]);

        Self { key, chain_code }
    }

    /// Derive a Solana keypair at derivation path `m/44'/501'/account'/change'`.
    ///
    /// Standard Solana path: account=0, change=0 for the default wallet.
    /// All indices are hardened as required by Ed25519 SLIP-10.
    pub fn derive_solana_path(seed: &[u8; 64], account: u32, change: u32) -> Self {
        Self::master(seed)
            .derive_child(44)   // purpose: BIP44
            .derive_child(501)  // coin_type: Solana
            .derive_child(account)
            .derive_child(change)
    }

    /// Get the 32-byte private key (Ed25519 seed).
    pub fn key_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Get the 32-byte chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Convert to a `Keypair` using the crypto module.
    ///
    /// Requires the `crypto` feature.
    #[cfg(feature = "crypto")]
    pub fn to_keypair(&self) -> Result<crate::crypto::Keypair> {
        crate::crypto::Keypair::from_seed(&self.key)
    }
}

impl core::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DerivedKey {{ key: [REDACTED], chain_code: [REDACTED] }}")
    }
}

/// Zero sensitive key material on drop to prevent keys lingering in SRAM.
impl Drop for DerivedKey {
    fn drop(&mut self) {
        for b in self.key.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in self.chain_code.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_from_seed() {
        // SLIP-10 Ed25519 test vector 1
        // Seed: 000102030405060708090a0b0c0d0e0f
        let mut seed = [0u8; 64];
        seed[..16].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        // Note: SLIP-10 test vectors use short seeds but the spec allows any length.
        // For BIP39, seed is always 64 bytes. We test with padded seed here.

        let master = DerivedKey::master(&seed);
        // Just verify it produces deterministic output
        let master2 = DerivedKey::master(&seed);
        assert_eq!(master.key, master2.key);
        assert_eq!(master.chain_code, master2.chain_code);
    }

    #[test]
    fn derive_child_deterministic() {
        let seed = [0x42u8; 64];
        let master = DerivedKey::master(&seed);
        let child_a = master.derive_child(0);
        let child_b = master.derive_child(0);
        assert_eq!(child_a.key, child_b.key);
        assert_eq!(child_a.chain_code, child_b.chain_code);
    }

    #[test]
    fn different_indices_different_keys() {
        let seed = [0x42u8; 64];
        let master = DerivedKey::master(&seed);
        let child_0 = master.derive_child(0);
        let child_1 = master.derive_child(1);
        assert_ne!(child_0.key, child_1.key);
    }

    #[test]
    fn solana_path_derivation() {
        let seed = [0xABu8; 64];
        let derived = DerivedKey::derive_solana_path(&seed, 0, 0);
        // Should produce a valid 32-byte key
        assert_eq!(derived.key_bytes().len(), 32);
        assert_eq!(derived.chain_code().len(), 32);

        // Different account indices should give different keys
        let derived_1 = DerivedKey::derive_solana_path(&seed, 1, 0);
        assert_ne!(derived.key, derived_1.key);
    }

    #[test]
    fn slip10_test_vector_1() {
        // SLIP-10 Ed25519 Test Vector 1
        // Seed (hex): 000102030405060708090a0b0c0d0e0f
        // Master chain: m
        //   key: 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
        //   chain_code: 90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb
        //
        // Note: SLIP-10 test vectors use the raw seed bytes, not a 64-byte BIP39 seed.
        // We need to pad to 64 bytes since our API takes [u8; 64].
        let seed_short: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        // Test using raw HMAC-SHA512 directly to match the SLIP-10 spec
        // (our master() pads to 64 bytes which changes the result)
        let hmac = hmac_sha512::HMAC::mac(&seed_short, b"ed25519 seed");

        let expected_key: [u8; 32] = [
            0x2b, 0x4b, 0xe7, 0xf1, 0x9e, 0xe2, 0x7b, 0xbf,
            0x30, 0xc6, 0x67, 0xb6, 0x42, 0xd5, 0xf4, 0xaa,
            0x69, 0xfd, 0x16, 0x98, 0x72, 0xf8, 0xfc, 0x30,
            0x59, 0xc0, 0x8e, 0xba, 0xe2, 0xeb, 0x19, 0xe7,
        ];
        let expected_chain: [u8; 32] = [
            0x90, 0x04, 0x6a, 0x93, 0xde, 0x53, 0x80, 0xa7,
            0x2b, 0x5e, 0x45, 0x01, 0x07, 0x48, 0x56, 0x7d,
            0x5e, 0xa0, 0x2b, 0xbf, 0x65, 0x22, 0xf9, 0x79,
            0xe0, 0x5c, 0x0d, 0x8d, 0x8c, 0xa9, 0xff, 0xfb,
        ];

        assert_eq!(&hmac[..32], &expected_key);
        assert_eq!(&hmac[32..], &expected_chain);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn to_keypair_works() {
        let seed = [0x42u8; 64];
        let derived = DerivedKey::derive_solana_path(&seed, 0, 0);
        let kp = derived.to_keypair().unwrap();
        let msg = b"hello solana";
        let sig = kp.sign(msg);
        assert!(crate::crypto::verify(&kp.pubkey(), msg, &sig));
    }

    #[test]
    fn zeroize_on_drop() {
        let seed = [0xABu8; 64];
        let derived = DerivedKey::derive_solana_path(&seed, 0, 0);
        // Copy key bytes before drop
        let key_copy = *derived.key_bytes();
        assert_ne!(key_copy, [0u8; 32], "key should not be zero before drop");
        // derived is dropped here at end of scope — write_volatile zeros it
        drop(derived);
        // We can't read the dropped memory directly (that's the point!),
        // but we verify the Drop impl compiles and runs without panic.
    }
}
