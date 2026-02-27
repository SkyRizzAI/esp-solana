//! Solana message compilation and wire-format serialization.

use alloc::vec::Vec;
use crate::types::{Pubkey, Hash, SdkError, Result, write_compact_u16, MAX_ACCOUNTS};
use crate::instruction::Instruction;

/// Compiled instruction with indices into the message's account_keys array.
#[derive(Debug, Clone)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// Message header describing signer/readonly counts.
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

/// A compiled Solana message ready for signing.
#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: Hash,
    pub instructions: Vec<CompiledInstruction>,
}

impl Message {
    /// Compile a message from high-level instructions.
    ///
    /// - `payer` is always `account_keys\[0\]` and a signer.
    /// - De-duplicates pubkeys across all instructions.
    /// - Orders: writable signers, readonly signers, writable non-signers, readonly non-signers.
    pub fn compile(
        payer: Pubkey,
        ixs: &[Instruction],
        recent_blockhash: Hash,
    ) -> Result<Self> {
        if ixs.is_empty() {
            return Err(SdkError::Invalid);
        }

        // Collect all unique keys with their signer/writable status
        // Use a simple vec-based dedup (account lists are tiny on embedded)
        let mut keys: Vec<(Pubkey, bool, bool)> = Vec::new(); // (pubkey, is_signer, is_writable)

        // Payer is always signer + writable
        keys.push((payer, true, true));

        for ix in ixs {
            for meta in &ix.accounts {
                if let Some(entry) = keys.iter_mut().find(|(pk, _, _)| *pk == meta.pubkey) {
                    // Merge flags: promote to signer/writable if any instruction requires it
                    entry.1 |= meta.is_signer;
                    entry.2 |= meta.is_writable;
                } else {
                    keys.push((meta.pubkey, meta.is_signer, meta.is_writable));
                }
            }
            // Program ID is an account too (readonly, non-signer)
            if !keys.iter().any(|(pk, _, _)| *pk == ix.program_id) {
                keys.push((ix.program_id, false, false));
            }
        }

        // Sort into Solana canonical order:
        // 1. Writable signers (payer first, already at index 0)
        // 2. Readonly signers
        // 3. Writable non-signers
        // 4. Readonly non-signers
        //
        // We use a stable partition approach to keep payer at index 0.
        let payer_entry = keys[0];
        let mut writable_signers: Vec<(Pubkey, bool, bool)> = Vec::new();
        let mut readonly_signers: Vec<(Pubkey, bool, bool)> = Vec::new();
        let mut writable_nonsigners: Vec<(Pubkey, bool, bool)> = Vec::new();
        let mut readonly_nonsigners: Vec<(Pubkey, bool, bool)> = Vec::new();

        for (i, entry) in keys.iter().enumerate() {
            if i == 0 {
                continue; // payer handled separately
            }
            match (entry.1, entry.2) {
                (true, true) => writable_signers.push(*entry),
                (true, false) => readonly_signers.push(*entry),
                (false, true) => writable_nonsigners.push(*entry),
                (false, false) => readonly_nonsigners.push(*entry),
            }
        }

        let num_signers = 1 + writable_signers.len() + readonly_signers.len();
        let num_readonly_signed = readonly_signers.len();
        let num_readonly_unsigned = readonly_nonsigners.len();
        let total_accounts = num_signers + writable_nonsigners.len() + readonly_nonsigners.len();

        if total_accounts > MAX_ACCOUNTS {
            return Err(SdkError::Invalid);
        }

        let mut account_keys = Vec::with_capacity(keys.len());
        account_keys.push(payer_entry.0);
        for e in &writable_signers {
            account_keys.push(e.0);
        }
        for e in &readonly_signers {
            account_keys.push(e.0);
        }
        for e in &writable_nonsigners {
            account_keys.push(e.0);
        }
        for e in &readonly_nonsigners {
            account_keys.push(e.0);
        }

        // Compile instructions: map pubkeys to indices
        let mut compiled_ixs = Vec::with_capacity(ixs.len());
        for ix in ixs {
            let program_id_index = account_keys
                .iter()
                .position(|pk| *pk == ix.program_id)
                .ok_or(SdkError::Serialize)? as u8;

            let accounts: Vec<u8> = ix
                .accounts
                .iter()
                .map(|meta| {
                    account_keys
                        .iter()
                        .position(|pk| *pk == meta.pubkey)
                        .map(|i| i as u8)
                        .ok_or(SdkError::Serialize)
                })
                .collect::<Result<Vec<u8>>>()?;

            compiled_ixs.push(CompiledInstruction {
                program_id_index,
                accounts,
                data: ix.data.clone(),
            });
        }

        let header = MessageHeader {
            num_required_signatures: num_signers as u8,
            num_readonly_signed_accounts: num_readonly_signed as u8,
            num_readonly_unsigned_accounts: num_readonly_unsigned as u8,
        };

        Ok(Self {
            header,
            account_keys,
            recent_blockhash,
            instructions: compiled_ixs,
        })
    }

    /// Serialize this message to exact Solana wire format bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);

        // Header: 3 bytes
        out.push(self.header.num_required_signatures);
        out.push(self.header.num_readonly_signed_accounts);
        out.push(self.header.num_readonly_unsigned_accounts);

        // Account keys: compact-u16 length, then 32 bytes each
        write_compact_u16(&mut out, self.account_keys.len() as u16);
        for key in &self.account_keys {
            out.extend_from_slice(&key.0);
        }

        // Recent blockhash: 32 bytes
        out.extend_from_slice(&self.recent_blockhash.0);

        // Instructions: compact-u16 count
        write_compact_u16(&mut out, self.instructions.len() as u16);
        for ix in &self.instructions {
            out.push(ix.program_id_index);
            write_compact_u16(&mut out, ix.accounts.len() as u16);
            out.extend_from_slice(&ix.accounts);
            write_compact_u16(&mut out, ix.data.len() as u16);
            out.extend_from_slice(&ix.data);
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::system_transfer;
    use crate::types::write_compact_u16;

    #[test]
    fn compact_u16_encoding() {
        let mut buf = Vec::new();
        write_compact_u16(&mut buf, 0);
        assert_eq!(buf, [0x00]);

        buf.clear();
        write_compact_u16(&mut buf, 1);
        assert_eq!(buf, [0x01]);

        buf.clear();
        write_compact_u16(&mut buf, 127);
        assert_eq!(buf, [0x7F]);

        buf.clear();
        write_compact_u16(&mut buf, 128);
        assert_eq!(buf, [0x80, 0x01]);

        buf.clear();
        write_compact_u16(&mut buf, 16383);
        assert_eq!(buf, [0xFF, 0x7F]);
    }

    #[test]
    fn compile_simple_transfer() {
        let payer = Pubkey::new([1u8; 32]);
        let to = Pubkey::new([2u8; 32]);
        let blockhash = Hash::new([0xAA; 32]);

        let ix = system_transfer(payer, to, 1_000_000);
        let msg = Message::compile(payer, &[ix], blockhash).unwrap();

        // Header: 1 signer (payer), 0 readonly signed, 1 readonly unsigned (system program)
        assert_eq!(msg.header.num_required_signatures, 1);
        assert_eq!(msg.header.num_readonly_signed_accounts, 0);
        assert_eq!(msg.header.num_readonly_unsigned_accounts, 1);

        // 3 accounts: payer, to, system_program
        assert_eq!(msg.account_keys.len(), 3);
        assert_eq!(msg.account_keys[0], payer);
        assert_eq!(msg.account_keys[1], to);
        assert_eq!(msg.account_keys[2], Pubkey::system_program());

        // 1 instruction
        assert_eq!(msg.instructions.len(), 1);
        assert_eq!(msg.instructions[0].program_id_index, 2);
        assert_eq!(msg.instructions[0].accounts, &[0, 1]);
    }

    #[test]
    fn serialize_has_correct_structure() {
        let payer = Pubkey::new([1u8; 32]);
        let to = Pubkey::new([2u8; 32]);
        let blockhash = Hash::new([0xBB; 32]);

        let ix = system_transfer(payer, to, 500);
        let msg = Message::compile(payer, &[ix], blockhash).unwrap();
        let bytes = msg.serialize();

        // Verify structure: header(3) + compact_len(1) + 3*32(96) + hash(32) + instructions
        assert_eq!(bytes[0], 1); // num_required_signatures
        assert_eq!(bytes[1], 0); // num_readonly_signed
        assert_eq!(bytes[2], 1); // num_readonly_unsigned
        assert_eq!(bytes[3], 3); // compact-u16: 3 account keys
        // account_keys start at byte 4
        assert_eq!(&bytes[4..36], &[1u8; 32]); // payer
        assert_eq!(&bytes[36..68], &[2u8; 32]); // to
        assert_eq!(&bytes[68..100], &[0u8; 32]); // system program
        // blockhash at byte 100
        assert_eq!(&bytes[100..132], &[0xBB; 32]);
    }
}
