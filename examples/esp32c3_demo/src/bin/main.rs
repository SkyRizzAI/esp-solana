//! ESP32-C3 Solana Demo — Wallet, Transaction Building & RPC
//!
//! Demonstrates the full esp-solana SDK on real ESP32-C3 hardware:
//! - BIP39 wallet creation from entropy
//! - SLIP-10 Ed25519 key derivation
//! - Solana transaction building and signing
//! - RPC JSON request construction
//!
//! ## Build & Flash
//! ```bash
//! cd examples/esp32c3_demo
//! cargo +stable build --release
//! espflash flash target/riscv32imc-unknown-none-elf/release/esp32c3-solana-demo --monitor
//! ```

#![no_std]
#![no_main]
#![deny(clippy::mem_forget)]

extern crate alloc;

use esp_hal::clock::CpuClock;
use esp_hal::main;
use esp_println::println;

use esp_solana::types::{Hash, SdkError};
use esp_solana::bs58;
use esp_solana::crypto;
use esp_solana::instruction::system_transfer;
use esp_solana::message::Message;
use esp_solana::transaction::Transaction;
use esp_solana::wallet::Wallet;
use esp_solana::rpc::{self, RpcClient, SolanaRpc};

const RPC_URL: &str = "https://api.devnet.solana.com";

/// Placeholder HTTP client — replace with esp-wifi networking
struct StubHttpClient;

impl RpcClient for StubHttpClient {
    fn post_json(&self, _url: &str, _body: &str) -> core::result::Result<alloc::string::String, SdkError> {
        Err(SdkError::Network)
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("PANIC: {}", info);
    loop {}
}

esp_bootloader_esp_idf::esp_app_desc!();

#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let _peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 65536);

    println!("========================================");
    println!("  esp-solana ESP32-C3 Demo");
    println!("========================================");
    println!();

    // ── Step 1: Create wallets from entropy ──
    println!("-- Step 1: Create wallets --");

    let entropy_a: [u8; 16] = [
        0xba, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    ];
    let wallet_a = Wallet::generate_12(&entropy_a).unwrap();
    let kp_a = wallet_a.keypair(0).unwrap();
    let addr_a = bs58::encode(&kp_a.pubkey().0);
    println!("  Wallet A mnemonic: {}", wallet_a.mnemonic());
    println!("  Wallet A address:  {}", addr_a);

    let entropy_b: [u8; 16] = [
        0xca, 0xfe, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    ];
    let wallet_b = Wallet::generate_12(&entropy_b).unwrap();
    let kp_b = wallet_b.keypair(0).unwrap();
    let addr_b = bs58::encode(&kp_b.pubkey().0);
    println!("  Wallet B address:  {}", addr_b);
    println!();

    // ── Step 2: Build a SOL transfer transaction ──
    println!("-- Step 2: Build transfer transaction --");

    // Use a dummy blockhash (fetch real one via RPC when connected)
    let blockhash = Hash::new([0xAA; 32]);
    let lamports = 100_000_000u64; // 0.1 SOL

    let ix = system_transfer(kp_a.pubkey(), kp_b.pubkey(), lamports);
    println!("  Transfer: {} lamports (0.1 SOL)", lamports);

    let msg = Message::compile(kp_a.pubkey(), &[ix], blockhash).unwrap();
    println!("  Message: {} accounts, {} instructions", msg.account_keys.len(), msg.instructions.len());

    let tx = Transaction::new(msg, &[&kp_a]).unwrap();
    let wire = tx.serialize();
    let b64 = tx.to_base64();
    let sig = &tx.signatures[0];
    println!("  Signature: {}", sig);
    println!("  Wire size: {} bytes", wire.len());
    println!("  Base64:    {} chars", b64.len());

    // Verify signature locally
    let sig_valid = crypto::verify(&kp_a.pubkey(), &wire[65..], sig);
    println!("  Sig verify: {}", if sig_valid { "VALID" } else { "INVALID" });
    println!();

    // ── Step 3: Build RPC request bodies ──
    println!("-- Step 3: RPC request JSON bodies --");

    let balance_req = rpc::json_get_balance(&addr_a);
    println!("  getBalance:         {} bytes", balance_req.len());

    let blockhash_req = rpc::json_get_latest_blockhash();
    println!("  getLatestBlockhash: {} bytes", blockhash_req.len());

    let send_req = rpc::json_send_transaction(&b64);
    println!("  sendTransaction:    {} bytes", send_req.len());

    let airdrop_req = rpc::json_request_airdrop(&addr_a, 1_000_000_000);
    println!("  requestAirdrop:     {} bytes", airdrop_req.len());
    println!();

    // ── Step 4: RPC client demo (network stub) ──
    println!("-- Step 4: RPC client (stub, no WiFi) --");

    let rpc_client = SolanaRpc::new(RPC_URL, StubHttpClient);
    match rpc_client.get_balance(&kp_a.pubkey()) {
        Ok(bal) => println!("  Balance: {} lamports", bal),
        Err(_) => println!("  Balance: [no network - implement StubHttpClient]"),
    }
    println!();

    // ── Step 5: Security — zeroize on drop ──
    println!("-- Step 5: Zeroize-on-drop security --");
    {
        let temp_wallet = Wallet::generate_12(&[0xFF; 16]).unwrap();
        let _temp_key = temp_wallet.keypair(0).unwrap();
        // wallet and derived key are zeroized here
    }
    println!("  Temporary wallet + keys zeroized on drop");
    println!();

    println!("========================================");
    println!("  Demo complete!");
    println!("  Flash: ~165KB (4%% of 4MB)");
    println!("  To send real transactions, implement");
    println!("  RpcClient with esp-wifi + TCP/HTTP.");
    println!("========================================");

    loop {
        let delay_start = esp_hal::time::Instant::now();
        while delay_start.elapsed() < esp_hal::time::Duration::from_millis(5000) {}
    }
}
