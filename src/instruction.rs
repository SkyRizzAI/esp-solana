//! Solana instruction types and System Program builders.

use alloc::vec::Vec;
use crate::types::Pubkey;

/// Metadata for a single account in an instruction.
#[derive(Debug, Clone)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn new(pubkey: Pubkey, is_signer: bool, is_writable: bool) -> Self {
        Self { pubkey, is_signer, is_writable }
    }
}

/// A high-level instruction before message compilation.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

impl Instruction {
    pub fn new(program_id: Pubkey, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Self {
        Self { program_id, accounts, data }
    }
}

/// Build a System Program transfer instruction.
///
/// Layout: little-endian u32 instruction index (2 = Transfer), then u64 lamports.
pub fn system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    // System instruction index 2 = Transfer (as LE u32)
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());

    let accounts = alloc::vec![
        AccountMeta::new(from, true, true),
        AccountMeta::new(to, false, true),
    ];

    Instruction::new(Pubkey::system_program(), accounts, data)
}
