//! Host-side demo: build and sign a SOL transfer transaction.
//!
//! Run: `cargo run --example host_demo --features crypto`
//! With wallet: `cargo run --example host_demo --features wallet`

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

    #[cfg(feature = "wallet")]
    wallet_demo();
}

/// Wallet demo (requires `wallet` feature).
/// Run: `cargo run --example host_demo --features wallet`
#[cfg(feature = "wallet")]
fn wallet_demo() {
    use esp_solana::wallet::Wallet;

    println!("\n=== Wallet Demo ===\n");

    // 1. Generate a new wallet from entropy
    let entropy = [0x42u8; 16]; // In real code, use hardware RNG!
    let wallet = Wallet::generate_12(&entropy).unwrap();
    println!("New wallet created!");
    println!("Mnemonic:     {}", wallet.mnemonic());
    println!("Word count:   {}", wallet.word_count());

    // 2. Derive multiple accounts
    for i in 0..3 {
        let pubkey = wallet.pubkey(i).unwrap();
        println!("Account #{}: {}", i, pubkey);
    }

    // 3. Restore from mnemonic
    let restored = Wallet::from_mnemonic(wallet.mnemonic()).unwrap();
    let pk_original = wallet.pubkey(0).unwrap();
    let pk_restored = restored.pubkey(0).unwrap();
    assert_eq!(pk_original.as_bytes(), pk_restored.as_bytes());
    println!("\nRestore verified: same address after recovery");

    // 4. Use wallet keypair to sign a transaction
    let kp = wallet.keypair(0).unwrap();
    let msg = b"hello from wallet";
    let sig = kp.sign(msg);
    let valid = esp_solana::crypto::verify(&kp.pubkey(), msg, &sig);
    println!("Sign & verify: {}", valid);

    // 5. Validate a known mnemonic
    let known = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let w = Wallet::from_mnemonic(known).unwrap();
    println!("\nKnown mnemonic test:");
    println!("Address:      {}", w.default_pubkey().unwrap());

    println!("\n=== Wallet Demo complete ===");
}
