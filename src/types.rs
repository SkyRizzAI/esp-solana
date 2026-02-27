use alloc::vec::Vec;
use core::fmt;

/// 32-byte Solana public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub const LEN: usize = 32;

    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// System program: 11111111111111111111111111111111
    pub const fn system_program() -> Self {
        Self([0u8; 32])
    }

    /// Create from a base58 string.
    pub fn from_bs58(s: &str) -> Result<Self> {
        let bytes = crate::bs58::decode_32(s)?;
        Ok(Self(bytes))
    }

    /// Encode as base58 string.
    pub fn to_bs58(&self) -> alloc::string::String {
        crate::bs58::encode(&self.0)
    }
}

impl AsRef<[u8]> for Pubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey({})", crate::bs58::encode(&self.0))
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", crate::bs58::encode(&self.0))
    }
}

/// 32-byte blockhash.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", crate::bs58::encode(&self.0))
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", crate::bs58::encode(&self.0))
    }
}

/// 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    pub const LEN: usize = 64;

    pub const fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({})", crate::bs58::encode(&self.0))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", crate::bs58::encode(&self.0))
    }
}

/// SDK-wide error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkError {
    /// Ed25519 signing or verification failure.
    Crypto,
    /// RPC request failed or returned an error.
    Rpc,
    /// Network / transport error.
    Network,
    /// Serialization error.
    Serialize,
    /// Deserialization / parse error.
    Deserialize,
    /// Invalid input (bad length, malformed data).
    Invalid,
    /// Operation timed out.
    Timeout,
    /// Feature or operation not supported.
    Unsupported,
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto => write!(f, "crypto error"),
            Self::Rpc => write!(f, "rpc error"),
            Self::Network => write!(f, "network error"),
            Self::Serialize => write!(f, "serialize error"),
            Self::Deserialize => write!(f, "deserialize error"),
            Self::Invalid => write!(f, "invalid input"),
            Self::Timeout => write!(f, "timeout"),
            Self::Unsupported => write!(f, "unsupported"),
        }
    }
}

pub type Result<T> = core::result::Result<T, SdkError>;

/// Write a Solana compact-u16 (1–3 byte variable-length encoding) into `buf`.
pub fn write_compact_u16(buf: &mut Vec<u8>, mut val: u16) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val > 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
}

/// Maximum number of accounts in a single Solana transaction.
pub const MAX_ACCOUNTS: usize = 255;
