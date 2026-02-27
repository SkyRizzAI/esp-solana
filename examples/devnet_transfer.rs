//! End-to-end devnet demo: create wallets, airdrop, transfer SOL, verify.
//!
//! Run: `cargo run --example devnet_transfer --features wallet`
//!
//! This example uses real Solana devnet RPC. It:
//! 1. Creates two wallets from entropy
//! 2. Airdrops 1 SOL to wallet A
//! 3. Builds & signs a 0.1 SOL transfer from A → B
//! 4. Sends the transaction and waits for confirmation
//! 5. Checks final balances
//! 6. Fetches detailed transaction info

extern crate alloc;

use std::thread;
use std::time::Duration;

use esp_solana::instruction::system_transfer;
use esp_solana::message::Message;
use esp_solana::rpc::{RpcClient, SolanaRpc};
use esp_solana::transaction::Transaction;
use esp_solana::wallet::Wallet;

const DEVNET_URL: &str = "https://api.devnet.solana.com";

// ─── Real HTTP transport using ureq ──────────────────────────

struct UreqClient;

impl RpcClient for UreqClient {
    fn post_json(&self, url: &str, body: &str) -> esp_solana::types::Result<String> {
        match ureq::post(url)
            .set("Content-Type", "application/json")
            .send_string(body)
        {
            Ok(resp) => {
                resp.into_string()
                    .map_err(|_| esp_solana::types::SdkError::Deserialize)
            }
            Err(ureq::Error::Status(_code, resp)) => {
                // Some RPC errors come as HTTP 4xx with valid JSON body
                resp.into_string()
                    .map_err(|_| esp_solana::types::SdkError::Deserialize)
            }
            Err(_) => Err(esp_solana::types::SdkError::Network),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────

fn wait_for_confirmation(rpc: &SolanaRpc<UreqClient>, sig: &str, label: &str) {
    print!("  Waiting for {} confirmation", label);
    for _ in 0..30 {
        print!(".");
        thread::sleep(Duration::from_secs(2));
        match rpc.check_confirmation(sig) {
            Ok(true) => {
                println!(" ✓");
                return;
            }
            Ok(false) => continue,
            Err(_) => continue,
        }
    }
    println!(" ✗ TIMEOUT (tx may still land)");
}

fn print_separator() {
    println!("{}", "─".repeat(60));
}

// ─── Main ────────────────────────────────────────────────────

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          esp-solana Devnet Transfer Demo                ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let rpc = SolanaRpc::new(DEVNET_URL, UreqClient);

    // ── Step 1: Create two wallets ───────────────────────────
    print_separator();
    println!("Step 1: Create two wallets\n");

    // Use different entropy for each wallet (in real code, use hardware RNG!)
    let entropy_a = [0x11u8; 16];
    let entropy_b = [0x22u8; 16];

    let wallet_a = Wallet::generate_12(&entropy_a).unwrap();
    let wallet_b = Wallet::generate_12(&entropy_b).unwrap();

    let pubkey_a = wallet_a.default_pubkey().unwrap();
    let pubkey_b = wallet_b.default_pubkey().unwrap();

    println!("  Wallet A mnemonic: {}", wallet_a.mnemonic());
    println!("  Wallet A address:  {}", pubkey_a);
    println!();
    println!("  Wallet B mnemonic: {}", wallet_b.mnemonic());
    println!("  Wallet B address:  {}", pubkey_b);

    // ── Step 2: Check initial balances ───────────────────────
    print_separator();
    println!("Step 2: Check initial balances\n");

    let balance_a = rpc.get_balance(&pubkey_a).unwrap_or(0);
    let balance_b = rpc.get_balance(&pubkey_b).unwrap_or(0);
    println!("  Wallet A: {} lamports ({:.4} SOL)", balance_a, balance_a as f64 / 1e9);
    println!("  Wallet B: {} lamports ({:.4} SOL)", balance_b, balance_b as f64 / 1e9);

    // ── Step 3: Airdrop 1 SOL to Wallet A (if needed) ──────────
    print_separator();
    println!("Step 3: Airdrop 1 SOL to Wallet A\n");

    if balance_a >= 200_000_000 {
        // Already have enough SOL from a previous run
        println!("  Wallet A already has {:.4} SOL — skipping airdrop.", balance_a as f64 / 1e9);
    } else {
        let airdrop_lamports = 1_000_000_000u64; // 1 SOL
        println!("  Requesting {} lamports ({} SOL)...", airdrop_lamports, airdrop_lamports / 1_000_000_000);

        let airdrop_sig = match rpc.request_airdrop(&pubkey_a, airdrop_lamports) {
            Ok(sig) => {
                println!("  Airdrop tx: {}", sig);
                sig
            }
            Err(e) => {
                eprintln!("  ✗ Airdrop failed: {:?}", e);
                eprintln!("  The public devnet airdrop is rate-limited.");
                eprintln!("  Manual airdrop: visit https://faucet.solana.com");
                eprintln!("  Paste this address: {}", pubkey_a);
                eprintln!();
                eprintln!("  After airdropping manually, re-run this example.");
                std::process::exit(1);
            }
        };

        wait_for_confirmation(&rpc, &airdrop_sig, "airdrop");

        // Verify balance increased
        let balance_a = rpc.get_balance(&pubkey_a).unwrap_or(0);
        println!("  Wallet A balance: {} lamports ({:.4} SOL)", balance_a, balance_a as f64 / 1e9);

        if balance_a == 0 {
            eprintln!("  ✗ Airdrop didn't land. Devnet may be congested.");
            std::process::exit(1);
        }
    }

    // ── Step 4: Build & sign transfer A → B ──────────────────
    print_separator();
    println!("Step 4: Build & sign transfer (0.1 SOL: A → B)\n");

    // Refresh balance before transfer
    let balance_a_before = rpc.get_balance(&pubkey_a).unwrap_or(0);

    let transfer_lamports = 100_000_000u64; // 0.1 SOL

    // Get fresh blockhash
    let blockhash = rpc.get_latest_blockhash().unwrap();
    println!("  Blockhash: {}", blockhash);

    // Build transfer instruction
    let ix = system_transfer(pubkey_a, pubkey_b, transfer_lamports);
    println!("  Instruction: transfer {} lamports", transfer_lamports);
    println!("    from: {}", pubkey_a);
    println!("    to:   {}", pubkey_b);

    // Compile message
    let msg = Message::compile(pubkey_a, &[ix], blockhash).unwrap();
    println!("  Message: {} accounts, {} instructions", msg.account_keys.len(), msg.instructions.len());

    // Sign with Wallet A's keypair
    let keypair_a = wallet_a.keypair(0).unwrap();
    let tx = Transaction::new(msg, &[&keypair_a]).unwrap();
    println!("  Signature: {}", tx.signatures[0]);

    // Verify signature locally before sending
    let msg_bytes = tx.message.serialize();
    let valid = esp_solana::crypto::verify(&pubkey_a, &msg_bytes, &tx.signatures[0]);
    println!("  Local sig verify: {}", if valid { "✓ valid" } else { "✗ INVALID" });

    let wire = tx.serialize();
    let b64 = tx.to_base64();
    println!("  Wire size: {} bytes", wire.len());
    println!("  Base64 length: {} chars", b64.len());

    // ── Step 5: Send transaction ─────────────────────────────
    print_separator();
    println!("Step 5: Send transaction to devnet\n");

    let tx_sig = match rpc.send_transaction(&b64) {
        Ok(sig) => {
            println!("  ✓ Transaction sent!");
            println!("  Tx signature: {}", sig);
            sig
        }
        Err(e) => {
            eprintln!("  ✗ Send failed: {:?}", e);
            std::process::exit(1);
        }
    };

    wait_for_confirmation(&rpc, &tx_sig, "transfer");

    // ── Step 6: Get detailed transaction info ────────────────
    print_separator();
    println!("Step 6: Transaction details\n");

    // Wait for the transaction to be fully indexed
    print!("  Waiting for indexing");
    let mut tx_json = String::new();
    for _ in 0..10 {
        thread::sleep(Duration::from_secs(3));
        print!(".");
        match rpc.get_transaction(&tx_sig) {
            Ok(json) if !json.contains("\"result\":null") => {
                tx_json = json;
                println!(" ✓");
                break;
            }
            _ => continue,
        }
    }
    if tx_json.is_empty() {
        println!(" (not indexed yet — try explorer link below)");
    }

    if !tx_json.is_empty() {
        println!("  Raw JSON length: {} bytes", tx_json.len());

        // Extract key fields
        if tx_json.contains("\"err\":null") {
            println!("  Status: ✓ Success (no error)");
        } else if tx_json.contains("\"err\"") {
            println!("  Status: ✗ Error in transaction");
        }

        if let Some(slot_pos) = tx_json.find("\"slot\":") {
            let after = &tx_json[slot_pos + 7..];
            let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
            println!("  Slot: {}", &after[..end]);
        }

        if let Some(fee_pos) = tx_json.find("\"fee\":") {
            let after = &tx_json[fee_pos + 6..];
            let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
            println!("  Fee:  {} lamports", &after[..end]);
        }

        // Print first 500 chars of the JSON for inspection
        println!();
        println!("  Transaction JSON (first 500 chars):");
        let preview: String = tx_json.chars().take(500).collect();
        println!("  {}", preview);
        if tx_json.len() > 500 {
            println!("  ... ({} more chars)", tx_json.len() - 500);
        }
    }

    // ── Step 7: Check final balances ─────────────────────────
    print_separator();
    println!("Step 7: Final balances\n");

    let final_a = rpc.get_balance(&pubkey_a).unwrap_or(0);
    let final_b = rpc.get_balance(&pubkey_b).unwrap_or(0);
    println!("  Wallet A: {} lamports ({:.4} SOL)", final_a, final_a as f64 / 1e9);
    println!("  Wallet B: {} lamports ({:.4} SOL)", final_b, final_b as f64 / 1e9);

    let fee = balance_a_before.saturating_sub(final_a).saturating_sub(transfer_lamports);
    println!();
    println!("  Transferred: {} lamports ({:.4} SOL)", transfer_lamports, transfer_lamports as f64 / 1e9);
    println!("  Fee:          {} lamports", fee);

    // ── Step 8: Verify signature status ──────────────────────
    print_separator();
    println!("Step 8: Confirm transaction status\n");

    match rpc.get_signature_status(&tx_sig) {
        Ok(status) => println!("  Confirmation status: {}", status),
        Err(e) => println!("  Could not get status: {:?}", e),
    }

    // ── Done ─────────────────────────────────────────────────
    print_separator();
    println!();
    println!("  ✓ Demo complete! View on Solana Explorer:");
    println!("  https://explorer.solana.com/tx/{}?cluster=devnet", tx_sig);
    println!();
}
