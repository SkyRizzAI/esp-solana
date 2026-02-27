//! Solana transaction signing and serialization.

use alloc::vec::Vec;
use alloc::string::String;
use crate::types::{Signature, SdkError, Result, write_compact_u16};
use crate::message::Message;

/// A signed Solana transaction ready for submission.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub signatures: Vec<Signature>,
    pub message: Message,
}

impl Transaction {
    /// Create and sign a transaction.
    ///
    /// `signers` must be ordered to match the message's required signers:
    /// signers[0] = payer, then any additional signers in account_keys order.
    #[cfg(feature = "crypto")]
    pub fn new(message: Message, signers: &[&crate::crypto::Keypair]) -> Result<Self> {
        let expected = message.header.num_required_signatures as usize;
        if signers.len() != expected {
            return Err(SdkError::Invalid);
        }

        // Validate that each signer's pubkey matches the corresponding account_key
        for (i, kp) in signers.iter().enumerate() {
            if kp.pubkey() != message.account_keys[i] {
                return Err(SdkError::Crypto);
            }
        }

        let msg_bytes = message.serialize();
        let mut signatures = Vec::with_capacity(expected);
        for kp in signers {
            signatures.push(kp.sign(&msg_bytes));
        }

        Ok(Self { signatures, message })
    }

    /// Create a transaction with pre-computed signatures (for when crypto feature is off
    /// or signatures are computed externally).
    pub fn new_with_signatures(message: Message, signatures: Vec<Signature>) -> Result<Self> {
        let expected = message.header.num_required_signatures as usize;
        if signatures.len() != expected {
            return Err(SdkError::Invalid);
        }
        Ok(Self { signatures, message })
    }

    /// Serialize the full transaction to Solana wire format.
    pub fn serialize(&self) -> Vec<u8> {
        let msg_bytes = self.message.serialize();
        let mut out = Vec::with_capacity(1 + self.signatures.len() * 64 + msg_bytes.len());

        // Signature count (compact-u16)
        write_compact_u16(&mut out, self.signatures.len() as u16);

        // Signatures (64 bytes each)
        for sig in &self.signatures {
            out.extend_from_slice(&sig.0);
        }

        // Serialized message
        out.extend_from_slice(&msg_bytes);
        out
    }

    /// Serialize and base64-encode for RPC `sendTransaction`.
    pub fn to_base64(&self) -> String {
        crate::b64::encode(&self.serialize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Pubkey, Hash};
    use crate::instruction::system_transfer;
    use crate::message::Message;

    #[cfg(feature = "crypto")]
    #[test]
    fn sign_and_serialize_transfer() {
        let kp = crate::crypto::Keypair::from_seed(&[42u8; 32]).unwrap();
        let payer = kp.pubkey();
        let to = Pubkey::new([2u8; 32]);
        let blockhash = Hash::new([0xCC; 32]);

        let ix = system_transfer(payer, to, 1_000_000);
        let msg = Message::compile(payer, &[ix], blockhash).unwrap();
        let tx = Transaction::new(msg, &[&kp]).unwrap();

        let bytes = tx.serialize();
        // First byte is compact-u16 for signature count = 1
        assert_eq!(bytes[0], 1);
        // Next 64 bytes are the signature
        assert_eq!(bytes.len(), 1 + 64 + tx.message.serialize().len());

        // Verify the signature is valid
        let msg_bytes = tx.message.serialize();
        assert!(crate::crypto::verify(&payer, &msg_bytes, &tx.signatures[0]));
    }

    #[test]
    fn to_base64_produces_valid_output() {
        let payer = Pubkey::new([1u8; 32]);
        let to = Pubkey::new([2u8; 32]);
        let blockhash = Hash::new([0xDD; 32]);

        let ix = system_transfer(payer, to, 100);
        let msg = Message::compile(payer, &[ix], blockhash).unwrap();

        // Use a dummy signature
        let sig = Signature::default();
        let tx = Transaction::new_with_signatures(msg, alloc::vec![sig]).unwrap();

        let b64 = tx.to_base64();
        // Should be valid base64 that decodes back to the wire bytes
        let decoded = crate::b64::decode(&b64).unwrap();
        assert_eq!(decoded, tx.serialize());
    }

    #[test]
    fn wrong_signer_count() {
        let payer = Pubkey::new([1u8; 32]);
        let to = Pubkey::new([2u8; 32]);
        let blockhash = Hash::new([0xEE; 32]);

        let ix = system_transfer(payer, to, 100);
        let msg = Message::compile(payer, &[ix], blockhash).unwrap();

        // 0 signatures when 1 is required
        let result = Transaction::new_with_signatures(msg, alloc::vec![]);
        assert!(result.is_err());
    }
}
