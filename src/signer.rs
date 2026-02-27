//! Signer trait for Solana transaction signing.
//!
//! Abstracts over software keypairs ([`crypto::Keypair`](crate::crypto::Keypair))
//! and hardware-backed signers (e.g., [`se05x::Se05xSigner`](crate::se05x::Se05xSigner)).
//!
//! # Example
//!
//! ```rust,ignore
//! use esp_solana::signer::Signer;
//! use esp_solana::transaction::Transaction;
//!
//! fn send(signers: &[&dyn Signer], msg: Message) {
//!     let tx = Transaction::sign(msg, signers).unwrap();
//!     let b64 = tx.to_base64();
//! }
//! ```

use crate::types::{Pubkey, Signature, Result};

/// Trait for Solana transaction signing.
///
/// Implemented by software keypairs and hardware-backed signers.
pub trait Signer {
    /// Return the signer's Solana public key (Ed25519).
    fn pubkey(&self) -> Pubkey;

    /// Sign the given message bytes and return an Ed25519 signature.
    fn sign(&self, message: &[u8]) -> Result<Signature>;
}
