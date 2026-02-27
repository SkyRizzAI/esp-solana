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
