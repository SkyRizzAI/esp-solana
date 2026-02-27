//! Ed25519 keypair, signing, and verification via `ed25519-compact`.

use crate::types::{Pubkey, Signature, SdkError, Result};

/// Ed25519 keypair for Solana transaction signing.
pub struct Keypair {
    secret: ed25519_compact::SecretKey,
    public: ed25519_compact::PublicKey,
}

impl Keypair {
    /// Create a keypair from a 32-byte seed (deterministic).
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let kp = ed25519_compact::KeyPair::from_seed(
            ed25519_compact::Seed::new(*seed),
        );
        Ok(Self {
            secret: kp.sk,
            public: kp.pk,
        })
    }

    /// Create a keypair from 64 raw bytes (first 32 = secret seed, last 32 = public key).
    /// This matches Solana CLI keypair file format.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        let kp = ed25519_compact::KeyPair::from_seed(
            ed25519_compact::Seed::new(seed),
        );
        // Verify the public key matches
        let expected_pk: &[u8] = &bytes[32..64];
        if kp.pk.as_ref() != expected_pk {
            return Err(SdkError::Crypto);
        }
        Ok(Self {
            secret: kp.sk,
            public: kp.pk,
        })
    }

    /// Return the Solana public key for this keypair.
    pub fn pubkey(&self) -> Pubkey {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.public.as_ref());
        Pubkey(bytes)
    }

    /// Ed25519-sign a message (Solana signs the serialized message bytes).
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.secret.sign(message, None);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        Signature(out)
    }
}

impl crate::signer::Signer for Keypair {
    fn pubkey(&self) -> Pubkey {
        self.pubkey()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature> {
        Ok(self.sign(message))
    }
}

/// Verify an Ed25519 signature against a message and public key.
pub fn verify(pubkey: &Pubkey, message: &[u8], signature: &Signature) -> bool {
    let pk = match ed25519_compact::PublicKey::from_slice(&pubkey.0) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match ed25519_compact::Signature::from_slice(&signature.0) {
        Ok(s) => s,
        Err(_) => return false,
    };
    pk.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_from_seed_deterministic() {
        let seed = [42u8; 32];
        let kp1 = Keypair::from_seed(&seed).unwrap();
        let kp2 = Keypair::from_seed(&seed).unwrap();
        assert_eq!(kp1.pubkey(), kp2.pubkey());
    }

    #[test]
    fn sign_and_verify() {
        let seed = [7u8; 32];
        let kp = Keypair::from_seed(&seed).unwrap();
        let msg = b"hello solana";
        let sig = kp.sign(msg);
        assert!(verify(&kp.pubkey(), msg, &sig));
    }

    #[test]
    fn verify_wrong_message() {
        let seed = [7u8; 32];
        let kp = Keypair::from_seed(&seed).unwrap();
        let sig = kp.sign(b"hello");
        assert!(!verify(&kp.pubkey(), b"world", &sig));
    }

    #[test]
    fn from_bytes_roundtrip() {
        let seed = [99u8; 32];
        let kp = Keypair::from_seed(&seed).unwrap();
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&seed);
        bytes[32..].copy_from_slice(kp.pubkey().as_bytes());
        let kp2 = Keypair::from_bytes(&bytes).unwrap();
        assert_eq!(kp.pubkey(), kp2.pubkey());
    }

    #[test]
    fn from_bytes_mismatch() {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&[1u8; 32]);
        bytes[32..].copy_from_slice(&[2u8; 32]); // wrong pubkey
        assert!(Keypair::from_bytes(&bytes).is_err());
    }
}
