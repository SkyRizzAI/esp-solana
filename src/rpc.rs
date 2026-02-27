//! Transport-agnostic Solana JSON-RPC client.
//!
//! The SDK provides JSON request builders and response parsers.
//! Users implement the `RpcClient` trait with their own HTTP transport
//! (e.g., reqwless, smoltcp, esp-tls, or std ureq).

use alloc::string::String;
use alloc::format;
use crate::types::{Pubkey, Hash, SdkError, Result};

/// Transport trait. Implement this for your HTTP client.
///
/// # Example (pseudo-code for ESP32 with reqwless)
/// ```ignore
/// impl RpcClient for MyEspClient {
///     fn post_json(&self, url: &str, body: &str) -> Result<String> {
///         // HTTP POST with Content-Type: application/json
///         // Return the response body as a UTF-8 string
///     }
/// }
/// ```
pub trait RpcClient {
    fn post_json(&self, url: &str, body: &str) -> Result<String>;
}

/// High-level Solana RPC wrapper.
pub struct SolanaRpc<'a, C: RpcClient> {
    pub url: &'a str,
    pub client: C,
}

impl<'a, C: RpcClient> SolanaRpc<'a, C> {
    pub fn new(url: &'a str, client: C) -> Self {
        Self { url, client }
    }

    /// Fetch the latest blockhash for transaction building.
    pub fn get_latest_blockhash(&self) -> Result<Hash> {
        let body = json_get_latest_blockhash();
        let resp = self.client.post_json(self.url, &body)?;
        parse_blockhash(&resp)
    }

    /// Submit a signed transaction (base64-encoded) and return the signature.
    pub fn send_transaction(&self, b64_tx: &str) -> Result<String> {
        let body = json_send_transaction(b64_tx);
        let resp = self.client.post_json(self.url, &body)?;
        parse_string_result(&resp)
    }

    /// Get the SOL balance (in lamports) for a public key.
    pub fn get_balance(&self, pubkey: &Pubkey) -> Result<u64> {
        let pk_b58 = crate::bs58::encode(&pubkey.0);
        let body = json_get_balance(&pk_b58);
        let resp = self.client.post_json(self.url, &body)?;
        parse_balance(&resp)
    }

    /// Get raw account info JSON (owner, lamports, data, etc.).
    pub fn get_account_info(&self, pubkey: &Pubkey) -> Result<String> {
        let pk_b58 = crate::bs58::encode(&pubkey.0);
        let body = json_get_account_info(&pk_b58);
        self.client.post_json(self.url, &body)
    }
}

// ─── JSON-RPC Request Builders ───────────────────────────────

/// Build JSON-RPC request for `getLatestBlockhash`.
pub fn json_get_latest_blockhash() -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{{"commitment":"finalized"}}]}}"#
    )
}

/// Build JSON-RPC request for `sendTransaction`.
pub fn json_send_transaction(b64_tx: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":["{}",{{"encoding":"base64"}}]}}"#,
        b64_tx
    )
}

/// Build JSON-RPC request for `getBalance`.
pub fn json_get_balance(pubkey_b58: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["{}"]}}"#,
        pubkey_b58
    )
}

/// Build JSON-RPC request for `getAccountInfo`.
pub fn json_get_account_info(pubkey_b58: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["{}",{{"encoding":"base64"}}]}}"#,
        pubkey_b58
    )
}

// ─── Response Parsers ────────────────────────────────────────
// Minimal JSON parsing without serde — searches for known keys.

/// Parse `getLatestBlockhash` response to extract the 32-byte hash.
///
/// Expected shape: `{"result":{"context":...,"value":{"blockhash":"<base58>", ...}}}`
pub fn parse_blockhash(json: &str) -> Result<Hash> {
    // Check for RPC error
    if json.contains("\"error\"") {
        return Err(SdkError::Rpc);
    }

    let key = "\"blockhash\":\"";
    let start = json.find(key).ok_or(SdkError::Deserialize)? + key.len();
    let end = json[start..].find('"').ok_or(SdkError::Deserialize)? + start;
    let b58_str = &json[start..end];

    let bytes = crate::bs58::decode_32(b58_str)?;
    Ok(Hash::new(bytes))
}

/// Parse `getBalance` response to extract lamports.
///
/// Expected shape: `{"result":{"context":...,"value":12345}}`
pub fn parse_balance(json: &str) -> Result<u64> {
    if json.contains("\"error\"") {
        return Err(SdkError::Rpc);
    }

    let key = "\"value\":";
    let start = json.find(key).ok_or(SdkError::Deserialize)? + key.len();

    // Find the number (skip whitespace, read digits)
    let remaining = &json[start..];
    let num_start = remaining.find(|c: char| c.is_ascii_digit()).ok_or(SdkError::Deserialize)?;
    let num_end = remaining[num_start..]
        .find(|c: char| !c.is_ascii_digit())
        .map(|i| num_start + i)
        .unwrap_or(remaining.len());

    let num_str = &remaining[num_start..num_end];
    parse_u64(num_str)
}

/// Parse a JSON-RPC response where the result is a string (e.g., sendTransaction signature).
///
/// Expected shape: `{"result":"<signature_string>"}`
pub fn parse_string_result(json: &str) -> Result<String> {
    if json.contains("\"error\"") {
        return Err(SdkError::Rpc);
    }

    let key = "\"result\":\"";
    let start = json.find(key).ok_or(SdkError::Deserialize)? + key.len();
    let end = json[start..].find('"').ok_or(SdkError::Deserialize)? + start;
    Ok(String::from(&json[start..end]))
}

/// Parse a decimal string to u64 without pulling in std.
fn parse_u64(s: &str) -> Result<u64> {
    let mut result: u64 = 0;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return Err(SdkError::Deserialize);
        }
        result = result
            .checked_mul(10)
            .ok_or(SdkError::Deserialize)?
            .checked_add((b - b'0') as u64)
            .ok_or(SdkError::Deserialize)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_builders_are_valid() {
        let s = json_get_latest_blockhash();
        assert!(s.contains("getLatestBlockhash"));
        assert!(s.contains("jsonrpc"));

        let s = json_send_transaction("AQID");
        assert!(s.contains("sendTransaction"));
        assert!(s.contains("AQID"));

        let s = json_get_balance("11111111111111111111111111111111");
        assert!(s.contains("getBalance"));

        let s = json_get_account_info("11111111111111111111111111111111");
        assert!(s.contains("getAccountInfo"));
    }

    #[test]
    fn parse_blockhash_success() {
        let json = r#"{"jsonrpc":"2.0","result":{"context":{"slot":123},"value":{"blockhash":"11111111111111111111111111111111","lastValidBlockHeight":456}},"id":1}"#;
        let hash = parse_blockhash(json).unwrap();
        assert_eq!(hash, Hash::new([0u8; 32]));
    }

    #[test]
    fn parse_blockhash_error() {
        let json = r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"bad"},"id":1}"#;
        assert!(parse_blockhash(json).is_err());
    }

    #[test]
    fn parse_balance_success() {
        let json = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":1000000000},"id":1}"#;
        let balance = parse_balance(json).unwrap();
        assert_eq!(balance, 1_000_000_000);
    }

    #[test]
    fn parse_balance_zero() {
        let json = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":0},"id":1}"#;
        let balance = parse_balance(json).unwrap();
        assert_eq!(balance, 0);
    }

    #[test]
    fn parse_string_result_success() {
        let json = r#"{"jsonrpc":"2.0","result":"5VERv8NMhbf3stL4VKdZXzK12xJGQRP2WQGLNfgfB2aD","id":1}"#;
        let sig = parse_string_result(json).unwrap();
        assert_eq!(sig, "5VERv8NMhbf3stL4VKdZXzK12xJGQRP2WQGLNfgfB2aD");
    }

    #[test]
    fn parse_string_result_error() {
        let json = r#"{"jsonrpc":"2.0","error":{"code":-32002,"message":"tx sim fail"},"id":1}"#;
        assert!(parse_string_result(json).is_err());
    }

    // Mock RPC client for testing
    struct MockClient {
        response: String,
    }
    impl RpcClient for MockClient {
        fn post_json(&self, _url: &str, _body: &str) -> Result<String> {
            Ok(self.response.clone())
        }
    }

    #[test]
    fn solana_rpc_get_balance() {
        let client = MockClient {
            response: r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":5000000000},"id":1}"#.into(),
        };
        let rpc = SolanaRpc::new("http://localhost:8899", client);
        let balance = rpc.get_balance(&Pubkey::new([1u8; 32])).unwrap();
        assert_eq!(balance, 5_000_000_000);
    }
}
