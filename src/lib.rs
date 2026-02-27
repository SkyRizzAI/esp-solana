//! `no_std` Solana SDK for ESP32 microcontrollers.
//!
//! Wallet creation (BIP39/SLIP-10), Ed25519 signing, transaction building,
//! and JSON-RPC — all in ~163KB of flash on ESP32-C3.
//!
//! # Quick start
//!
//! ```toml
//! [dependencies]
//! esp-solana = { version = "0.1", features = ["wallet"] }
//! ```
//!
//! ```rust,ignore
//! use esp_solana::prelude::*;
//! use esp_solana::wallet::Wallet;
//! use esp_solana::instruction::system_transfer;
//! use esp_solana::message::Message;
//! use esp_solana::transaction::Transaction;
//!
//! let wallet = Wallet::generate_12(&entropy).unwrap();
//! let keypair = wallet.keypair(0).unwrap();
//!
//! let ix = system_transfer(keypair.pubkey(), recipient, 1_000_000);
//! let msg = Message::compile(keypair.pubkey(), &[ix], blockhash).unwrap();
//! let tx = Transaction::new(msg, &[&keypair]).unwrap();
//! let b64 = tx.to_base64();
//! ```
//!
//! # Features
//!
//! - **`crypto`** (default) — Ed25519 signing via `ed25519-compact`
//! - **`wallet`** — BIP39 mnemonic + SLIP-10 key derivation (enables `crypto`)
//! - **`std`** — enables std for host-side testing

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

pub mod types;
pub mod bs58;
pub mod b64;
pub mod instruction;
pub mod message;
pub mod transaction;
pub mod rpc;

#[cfg(feature = "crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
pub mod crypto;

#[cfg(feature = "wallet")]
#[cfg_attr(docsrs, doc(cfg(feature = "wallet")))]
mod wordlist;

#[cfg(feature = "wallet")]
#[cfg_attr(docsrs, doc(cfg(feature = "wallet")))]
pub mod bip39;

#[cfg(feature = "wallet")]
#[cfg_attr(docsrs, doc(cfg(feature = "wallet")))]
pub mod slip10;

#[cfg(feature = "wallet")]
#[cfg_attr(docsrs, doc(cfg(feature = "wallet")))]
pub mod wallet;

/// Curated re-exports for common use.
/// `use esp_solana::prelude::*;`
pub mod prelude {
    pub use crate::types::*;
    pub use crate::bs58;
    pub use crate::b64;
    pub use crate::instruction::*;
    pub use crate::message::Message;
    pub use crate::transaction::Transaction;
    pub use crate::rpc::{RpcClient, SolanaRpc};

    #[cfg(feature = "crypto")]
    pub use crate::crypto::Keypair;

    #[cfg(feature = "wallet")]
    pub use crate::wallet::Wallet;

    #[cfg(feature = "wallet")]
    pub use crate::bip39::Mnemonic;
}
