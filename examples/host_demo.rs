//! Host-side demo: build and sign a SOL transfer transaction.
//!
//! Run: `cargo test --example host_demo --features crypto`
//! (This is a runnable test, not an actual RPC call.)

extern crate alloc;

use esp_solana::prelude::*;
use esp_solana::crypto::Keypair;
use esp_solana::instruction::system_transfer;
use esp_solana::message::Message;
use esp_solana::transaction::Transaction;
use esp_solana::rpc::{RpcClient, SolanaRpc};

// ─── Mock HTTP client for demo ───────────────────────────────

struct MockHttpClient;

impl RpcClient for MockHttpClient {
    fn post_json(&self, _url: &str, body: &str) -> esp_solana::types::Result<String> {
        // Simulate RPC responses based on the method called
        if body.contains("getLatestBlockhash") {
            Ok(r#"{"jsonrpc":"2.0","result":{"context":{"slot":123},"value":{"blockhash":"GWWjbfFnZkEqjVh8sMz5HFkpJLaRqfNG3P3fX7aEbCE9","lastValidBlockHeight":456}},"id":1}"#.into())
        } else if body.contains("sendTransaction") {
            Ok(r#"{"jsonrpc":"2.0","result":"5VERv8NMhbf3stL4VKdZXzK12xJGQRP2WQGLNfgfB2aD","id":1}"#.into())
        } else if body.contains("getBalance") {
            Ok(r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":5000000000},"id":1}"#.into())
        } else {
            Err(esp_solana::types::SdkError::Unsupported)
        }
    }
}

fn main() {
    println!("=== esp-solana Host Demo ===\n");

    // 1. Create a keypair from a seed (deterministic for demo)
    let seed = [42u8; 32];
    let payer = Keypair::from_seed(&seed).unwrap();
    println!("Payer pubkey: {}", payer.pubkey());

    // 2. Define the recipient
    let recipient = Pubkey::from_bs58("11111111111111111111111111111112").unwrap_or_else(|_| {
        Pubkey::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    });
    println!("Recipient:    {}", recipient);

    // 3. Set up RPC client (using mock for demo)
    let rpc = SolanaRpc::new("https://api.devnet.solana.com", MockHttpClient);

    // 4. Check balance
    let balance = rpc.get_balance(&payer.pubkey()).unwrap();
    println!("\nPayer balance: {} lamports ({} SOL)", balance, balance as f64 / 1e9);

    // 5. Get recent blockhash
    let blockhash = rpc.get_latest_blockhash().unwrap();
    println!("Blockhash:    {}", blockhash);

    // 6. Build a transfer instruction (0.001 SOL = 1_000_000 lamports)
    let lamports = 1_000_000u64;
    let ix = system_transfer(payer.pubkey(), recipient, lamports);
    println!("\nTransfer:     {} lamports → {}", lamports, recipient);

    // 7. Compile the message
    let msg = Message::compile(payer.pubkey(), &[ix], blockhash).unwrap();
    println!("Message:      {} accounts, {} instructions",
        msg.account_keys.len(), msg.instructions.len());
    println!("  accounts[0] (payer):   {}", msg.account_keys[0]);
    println!("  accounts[1] (to):      {}", msg.account_keys[1]);
    println!("  accounts[2] (system):  {}", msg.account_keys[2]);

    // 8. Sign and build the transaction
    let tx = Transaction::new(msg, &[&payer]).unwrap();
    println!("\nSignature:    {}", tx.signatures[0]);

    // 9. Serialize to base64 for RPC submission
    let b64 = tx.to_base64();
    println!("Base64 tx:    {}...({} chars)", &b64[..40], b64.len());

    // 10. Verify the signature locally
    let msg_bytes = tx.message.serialize();
    let valid = esp_solana::crypto::verify(&payer.pubkey(), &msg_bytes, &tx.signatures[0]);
    println!("Sig valid:    {}", valid);

    // 11. Send the transaction (mock)
    let sig = rpc.send_transaction(&b64).unwrap();
    println!("\nTx sent!      {}", sig);

    // 12. Show wire format size
    let wire_bytes = tx.serialize();
    println!("Wire size:    {} bytes", wire_bytes.len());

    println!("\n=== Demo complete ===");
}
