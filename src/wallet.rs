//! High-level Solana wallet management.
//!
//! Provides a `Wallet` struct that wraps BIP39 mnemonic generation, seed derivation,
//! and SLIP-10 key derivation into a simple API for creating and managing Solana wallets.
//!
//! # Example
//! ```rust,ignore
//! use esp_solana::wallet::Wallet;
//!
//! // Create a new wallet from 16 bytes of random entropy
//! let entropy: [u8; 16] = get_random_bytes(); // from hardware RNG
//! let wallet = Wallet::generate_12(&entropy).unwrap();
//!
//! // Print mnemonic (store this safely!)
//! println!("Mnemonic: {}", wallet.mnemonic());
//!
//! // Get the default keypair (account 0)
//! let keypair = wallet.keypair(0).unwrap();
//! println!("Address: {}", keypair.pubkey());
//! ```

use crate::bip39::Mnemonic;
use crate::slip10::DerivedKey;
use crate::types::Result;

/// A Solana wallet backed by a BIP39 mnemonic and SLIP-10 key derivation.
///
/// The wallet stores the mnemonic phrase and the 64-byte BIP39 seed.
/// Individual keypairs are derived on-demand using the Solana derivation path
/// `m/44'/501'/account'/0'`.
#[derive(Clone)]
pub struct Wallet {
    mnemonic: Mnemonic,
    seed: [u8; 64],
}

impl Wallet {
    /// Create a new 12-word wallet from 16 bytes of random entropy.
    ///
    /// The entropy MUST come from a cryptographically secure source
    /// (e.g., ESP32 hardware RNG).
    pub fn generate_12(entropy: &[u8; 16]) -> Result<Self> {
        Self::generate_12_with_passphrase(entropy, "")
    }

    /// Create a new 12-word wallet with a BIP39 passphrase.
    pub fn generate_12_with_passphrase(entropy: &[u8; 16], passphrase: &str) -> Result<Self> {
        let mnemonic = Mnemonic::from_entropy_128(entropy)?;
        let seed = mnemonic.derive_seed(passphrase);
        Ok(Self { mnemonic, seed })
    }

    /// Create a new 24-word wallet from 32 bytes of random entropy.
    pub fn generate_24(entropy: &[u8; 32]) -> Result<Self> {
        Self::generate_24_with_passphrase(entropy, "")
    }

    /// Create a new 24-word wallet with a BIP39 passphrase.
    pub fn generate_24_with_passphrase(entropy: &[u8; 32], passphrase: &str) -> Result<Self> {
        let mnemonic = Mnemonic::from_entropy_256(entropy)?;
        let seed = mnemonic.derive_seed(passphrase);
        Ok(Self { mnemonic, seed })
    }

    /// Restore a wallet from an existing mnemonic phrase.
    ///
    /// Validates the mnemonic (word count, wordlist, checksum) and derives the seed.
    pub fn from_mnemonic(phrase: &str) -> Result<Self> {
        Self::from_mnemonic_with_passphrase(phrase, "")
    }

    /// Restore a wallet from a mnemonic phrase with a BIP39 passphrase.
    pub fn from_mnemonic_with_passphrase(phrase: &str, passphrase: &str) -> Result<Self> {
        let mnemonic = Mnemonic::from_phrase(phrase)?;
        let seed = mnemonic.derive_seed(passphrase);
        Ok(Self { mnemonic, seed })
    }

    /// Get the mnemonic phrase.
    ///
    /// **Security warning:** This is the master secret. Store it safely!
    pub fn mnemonic(&self) -> &str {
        self.mnemonic.phrase()
    }

    /// Get the word count of the mnemonic (12 or 24).
    pub fn word_count(&self) -> usize {
        self.mnemonic.word_count()
    }

    /// Get the raw 64-byte BIP39 seed.
    ///
    /// Can be used for persistent storage (encrypt before saving!).
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    /// Derive a SLIP-10 key at the Solana path `m/44'/501'/account'/0'`.
    ///
    /// Returns the raw `DerivedKey` for advanced use cases.
    pub fn derive_key(&self, account: u32) -> DerivedKey {
        DerivedKey::derive_solana_path(&self.seed, account, 0)
    }

    /// Derive a `Keypair` for the given account index.
    ///
    /// Account 0 is the default/primary wallet address.
    /// Account 1, 2, ... are additional addresses from the same mnemonic.
    ///
    /// Requires the `crypto` feature.
    #[cfg(feature = "crypto")]
    pub fn keypair(&self, account: u32) -> Result<crate::crypto::Keypair> {
        self.derive_key(account).to_keypair()
    }

    /// Get the public key (address) for the given account index.
    ///
    /// Convenience method that derives the keypair and returns just the pubkey.
    ///
    /// Requires the `crypto` feature.
    #[cfg(feature = "crypto")]
    pub fn pubkey(&self, account: u32) -> Result<crate::types::Pubkey> {
        Ok(self.keypair(account)?.pubkey())
    }

    /// Get the default public key (account 0).
    ///
    /// Requires the `crypto` feature.
    #[cfg(feature = "crypto")]
    pub fn default_pubkey(&self) -> Result<crate::types::Pubkey> {
        self.pubkey(0)
    }
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Wallet({} words)", self.word_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_12_word_wallet() {
        let entropy = [0x42u8; 16];
        let wallet = Wallet::generate_12(&entropy).unwrap();
        assert_eq!(wallet.word_count(), 12);
        assert!(!wallet.mnemonic().is_empty());
    }

    #[test]
    fn generate_24_word_wallet() {
        let entropy = [0x42u8; 32];
        let wallet = Wallet::generate_24(&entropy).unwrap();
        assert_eq!(wallet.word_count(), 24);
    }

    #[test]
    fn restore_from_mnemonic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(phrase).unwrap();
        assert_eq!(wallet.mnemonic(), phrase);
        assert_eq!(wallet.word_count(), 12);
    }

    #[test]
    fn restore_invalid_mnemonic() {
        assert!(Wallet::from_mnemonic("invalid words here").is_err());
    }

    #[test]
    fn roundtrip_generate_restore() {
        let entropy = [0xABu8; 16];
        let wallet1 = Wallet::generate_12(&entropy).unwrap();
        let wallet2 = Wallet::from_mnemonic(wallet1.mnemonic()).unwrap();
        assert_eq!(wallet1.seed(), wallet2.seed());
    }

    #[test]
    fn passphrase_changes_seed() {
        let entropy = [0x42u8; 16];
        let w1 = Wallet::generate_12(&entropy).unwrap();
        let w2 = Wallet::generate_12_with_passphrase(&entropy, "secret").unwrap();
        assert_eq!(w1.mnemonic(), w2.mnemonic()); // same mnemonic
        assert_ne!(w1.seed(), w2.seed()); // different seeds
    }

    #[test]
    fn different_accounts_different_keys() {
        let entropy = [0x42u8; 16];
        let wallet = Wallet::generate_12(&entropy).unwrap();
        let key0 = wallet.derive_key(0);
        let key1 = wallet.derive_key(1);
        assert_ne!(key0.key_bytes(), key1.key_bytes());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn keypair_can_sign() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(phrase).unwrap();
        let kp = wallet.keypair(0).unwrap();

        // Sign and verify
        let msg = b"hello solana from wallet";
        let sig = kp.sign(msg);
        assert!(crate::crypto::verify(&kp.pubkey(), msg, &sig));
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn multiple_accounts_all_valid() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(phrase).unwrap();

        for i in 0..5 {
            let kp = wallet.keypair(i).unwrap();
            let msg = b"test";
            let sig = kp.sign(msg);
            assert!(crate::crypto::verify(&kp.pubkey(), msg, &sig));
        }
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn known_solana_derivation() {
        // Known test: "abandon...about" mnemonic, no passphrase, account 0
        // This should produce a deterministic Solana address
        let wallet = Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let pubkey = wallet.default_pubkey().unwrap();

        // Verify it's deterministic
        let wallet2 = Wallet::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let pubkey2 = wallet2.default_pubkey().unwrap();
        assert_eq!(pubkey.as_bytes(), pubkey2.as_bytes());

        // The known Solana address for this mnemonic (m/44'/501'/0'/0')
        // is: 2gCEsed3wT7dc8MPS6Baqb7MDiEgLcGnuV3A3PFby9bY
        let expected_bs58 = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
        let actual_bs58 = pubkey.to_bs58();
        assert_eq!(actual_bs58, expected_bs58,
            "Expected Solana address {} but got {}", expected_bs58, actual_bs58);
    }
}
