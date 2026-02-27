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

    /// Request an airdrop of `lamports` to a public key (devnet/testnet only).
    ///
    /// Returns the transaction signature string.
    pub fn request_airdrop(&self, pubkey: &Pubkey, lamports: u64) -> Result<String> {
        let pk_b58 = crate::bs58::encode(&pubkey.0);
        let body = json_request_airdrop(&pk_b58, lamports);
        let resp = self.client.post_json(self.url, &body)?;
        parse_string_result(&resp)
    }

    /// Get the confirmation status of a transaction signature.
    ///
    /// Returns one of: `"processed"`, `"confirmed"`, `"finalized"`,
    /// or `Err` if not found or RPC error.
    pub fn get_signature_status(&self, signature: &str) -> Result<String> {
        let body = json_get_signature_statuses(signature);
        let resp = self.client.post_json(self.url, &body)?;
        parse_confirmation_status(&resp)
    }

    /// Get detailed transaction info as raw JSON.
    ///
    /// Returns the full JSON response for the given transaction signature.
    /// Use this to inspect transaction details (accounts, instructions, logs, etc.).
    pub fn get_transaction(&self, signature: &str) -> Result<String> {
        let body = json_get_transaction(signature);
        self.client.post_json(self.url, &body)
    }

    /// Poll until a transaction is confirmed (or timeout).
    ///
    /// `max_retries`: how many times to poll (each with ~2s delay via caller).
    /// Returns `true` if confirmed/finalized, `false` if still pending after retries.
    ///
    /// **Note:** This method does NOT sleep. The caller should sleep between calls.
    /// Use `confirm_transaction_with_sleep` (std only) for automatic polling.
    pub fn check_confirmation(&self, signature: &str) -> Result<bool> {
        match self.get_signature_status(signature) {
            Ok(status) => {
                Ok(status == "confirmed" || status == "finalized")
            }
            Err(SdkError::Deserialize) => Ok(false), // not found yet
            Err(e) => Err(e),
        }
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

/// Build JSON-RPC request for `requestAirdrop`.
pub fn json_request_airdrop(pubkey_b58: &str, lamports: u64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"requestAirdrop","params":["{}",{}]}}"#,
        pubkey_b58, lamports
    )
}

/// Build JSON-RPC request for `getSignatureStatuses`.
pub fn json_get_signature_statuses(signature: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[["{}"],{{"searchTransactionHistory":true}}]}}"#,
        signature
    )
}

/// Build JSON-RPC request for `getTransaction`.
pub fn json_get_transaction(signature: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["{}",{{"encoding":"json","maxSupportedTransactionVersion":0}}]}}"#,
        signature
    )
}

// ─── Response Parsers ────────────────────────────────────────
// Minimal JSON parsing without serde — searches for known keys.
// Handles optional whitespace around `:` and values.

/// Parse `getLatestBlockhash` response to extract the 32-byte hash.
///
/// Expected shape: `{"result":{"context":...,"value":{"blockhash":"<base58>", ...}}}`
pub fn parse_blockhash(json: &str) -> Result<Hash> {
    if let Some(err) = extract_rpc_error(json) {
        return Err(err);
    }

    let b58_str = extract_string_value(json, "blockhash")?;
    let bytes = crate::bs58::decode_32(b58_str)?;
    Ok(Hash::new(bytes))
}

/// Parse `getBalance` response to extract lamports.
///
/// Expected shape: `{"result":{"context":...,"value":12345}}`
pub fn parse_balance(json: &str) -> Result<u64> {
    if let Some(err) = extract_rpc_error(json) {
        return Err(err);
    }

    // Find "value" key — for getBalance it's a number, could also be null
    let key = "\"value\"";
    let key_pos = json.find(key).ok_or(SdkError::Deserialize)?;
    let after_key = &json[key_pos + key.len()..];

    // Skip whitespace and colon
    let after_colon = skip_ws_colon(after_key)?;

    // Check for null
    if after_colon.starts_with("null") {
        return Ok(0);
    }

    // Read digits
    let num_start = after_colon
        .find(|c: char| c.is_ascii_digit())
        .ok_or(SdkError::Deserialize)?;
    let num_end = after_colon[num_start..]
        .find(|c: char| !c.is_ascii_digit())
        .map(|i| num_start + i)
        .unwrap_or(after_colon.len());

    parse_u64(&after_colon[num_start..num_end])
}

/// Parse a JSON-RPC response where the result is a string (e.g., sendTransaction signature).
///
/// Expected shape: `{"result":"<signature_string>"}`
pub fn parse_string_result(json: &str) -> Result<String> {
    if let Some(err) = extract_rpc_error(json) {
        return Err(err);
    }

    let val = extract_string_value(json, "result")?;
    Ok(String::from(val))
}

/// Extract a JSON string value for a given key, handling optional whitespace.
/// Finds `"key" : "value"` and returns the inner value (without quotes).
fn extract_string_value<'a>(json: &'a str, key: &str) -> Result<&'a str> {
    // Build pattern: "key"
    let mut search = String::with_capacity(key.len() + 2);
    search.push('"');
    search.push_str(key);
    search.push('"');

    let key_pos = json.find(search.as_str()).ok_or(SdkError::Deserialize)?;
    let after_key = &json[key_pos + search.len()..];

    // Skip whitespace and colon
    let after_colon = skip_ws_colon(after_key)?;

    // Skip whitespace before opening quote
    let trimmed = after_colon.trim_start();
    if !trimmed.starts_with('"') {
        return Err(SdkError::Deserialize);
    }

    let value_start = 1; // skip opening quote
    let value_end = trimmed[value_start..]
        .find('"')
        .ok_or(SdkError::Deserialize)?;

    Ok(&trimmed[value_start..value_start + value_end])
}

/// Skip optional whitespace then a colon then optional whitespace.
fn skip_ws_colon(s: &str) -> Result<&str> {
    let s = s.trim_start();
    if !s.starts_with(':') {
        return Err(SdkError::Deserialize);
    }
    Ok(s[1..].trim_start())
}

/// Check for a JSON-RPC error and return the appropriate SdkError.
fn extract_rpc_error(json: &str) -> Option<SdkError> {
    // Look for "error" as a top-level key (not inside a string value)
    let key = "\"error\"";
    if let Some(pos) = json.find(key) {
        // Make sure it's preceded by `{` or `,` (possibly with whitespace), not inside a string
        let before = json[..pos].trim_end();
        if before.ends_with('{') || before.ends_with(',') {
            return Some(SdkError::Rpc);
        }
    }
    None
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

/// Parse `getSignatureStatuses` response to extract confirmation status.
///
/// Returns "processed", "confirmed", or "finalized".
/// Returns `Err(Deserialize)` if the status is null (not found).
pub fn parse_confirmation_status(json: &str) -> Result<String> {
    if let Some(err) = extract_rpc_error(json) {
        return Err(err);
    }

    // The response has "value":[{...,"confirmationStatus":"finalized"}] or "value":[null]
    let val_key = "\"value\"";
    let val_pos = json.find(val_key).ok_or(SdkError::Deserialize)?;
    let after_val = &json[val_pos..];

    // Check for null inside the array
    if let Some(bracket_pos) = after_val.find('[') {
        let inside = &after_val[bracket_pos + 1..];
        let trimmed = inside.trim_start();
        if trimmed.starts_with("null") {
            return Err(SdkError::Deserialize); // tx not found
        }
    }

    // Extract confirmationStatus
    let status = extract_string_value(json, "confirmationStatus")?;
    Ok(String::from(status))
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
    fn parse_blockhash_with_whitespace() {
        // Some RPC servers send pretty-printed JSON
        let json = r#"{"jsonrpc": "2.0", "result": {"context": {"slot": 123}, "value": {"blockhash" : "11111111111111111111111111111111", "lastValidBlockHeight": 456}}, "id": 1}"#;
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
    fn parse_balance_null() {
        // Account doesn't exist — value is null
        let json = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":null},"id":1}"#;
        let balance = parse_balance(json).unwrap();
        assert_eq!(balance, 0);
    }

    #[test]
    fn parse_balance_with_whitespace() {
        let json = r#"{"jsonrpc" : "2.0", "result" : {"context" : {"slot" : 1}, "value" : 999}, "id" : 1}"#;
        let balance = parse_balance(json).unwrap();
        assert_eq!(balance, 999);
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

    #[test]
    fn json_request_airdrop_valid() {
        let s = json_request_airdrop("11111111111111111111111111111111", 1_000_000_000);
        assert!(s.contains("requestAirdrop"));
        assert!(s.contains("1000000000"));
    }

    #[test]
    fn json_get_signature_statuses_valid() {
        let s = json_get_signature_statuses("5VERv8NMhbf3stL");
        assert!(s.contains("getSignatureStatuses"));
        assert!(s.contains("5VERv8NMhbf3stL"));
        assert!(s.contains("searchTransactionHistory"));
    }

    #[test]
    fn json_get_transaction_valid() {
        let s = json_get_transaction("5VERv8NMhbf3stL");
        assert!(s.contains("getTransaction"));
        assert!(s.contains("maxSupportedTransactionVersion"));
    }

    #[test]
    fn parse_confirmation_finalized() {
        let json = r#"{"jsonrpc":"2.0","result":{"context":{"slot":123},"value":[{"slot":456,"confirmations":null,"err":null,"confirmationStatus":"finalized"}]},"id":1}"#;
        let status = parse_confirmation_status(json).unwrap();
        assert_eq!(status, "finalized");
    }

    #[test]
    fn parse_confirmation_confirmed() {
        let json = r#"{"jsonrpc":"2.0","result":{"context":{"slot":123},"value":[{"slot":456,"confirmations":10,"err":null,"confirmationStatus":"confirmed"}]},"id":1}"#;
        let status = parse_confirmation_status(json).unwrap();
        assert_eq!(status, "confirmed");
    }

    #[test]
    fn parse_confirmation_null_not_found() {
        let json = r#"{"jsonrpc":"2.0","result":{"context":{"slot":123},"value":[null]},"id":1}"#;
        assert!(parse_confirmation_status(json).is_err());
    }

    #[test]
    fn parse_confirmation_with_whitespace() {
        let json = r#"{"jsonrpc" : "2.0", "result" : {"context" : {"slot" : 123}, "value" : [{"confirmationStatus" : "processed"}]}, "id" : 1}"#;
        let status = parse_confirmation_status(json).unwrap();
        assert_eq!(status, "processed");
    }

    #[test]
    fn rpc_request_airdrop_mock() {
        let client = MockClient {
            response: r#"{"jsonrpc":"2.0","result":"5VERv8NMhbf3stL4VKdZXzK12xJGQRP2WQGLNfgfB2aD","id":1}"#.into(),
        };
        let rpc = SolanaRpc::new("http://localhost:8899", client);
        let sig = rpc.request_airdrop(&Pubkey::new([1u8; 32]), 1_000_000_000).unwrap();
        assert_eq!(sig, "5VERv8NMhbf3stL4VKdZXzK12xJGQRP2WQGLNfgfB2aD");
    }

    #[test]
    fn rpc_check_confirmation_mock() {
        let client = MockClient {
            response: r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":[{"confirmationStatus":"finalized"}]},"id":1}"#.into(),
        };
        let rpc = SolanaRpc::new("http://localhost:8899", client);
        assert!(rpc.check_confirmation("somesig").unwrap());
    }

    #[test]
    fn rpc_check_confirmation_pending() {
        let client = MockClient {
            response: r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":[null]},"id":1}"#.into(),
        };
        let rpc = SolanaRpc::new("http://localhost:8899", client);
        assert!(!rpc.check_confirmation("somesig").unwrap());
    }
}
