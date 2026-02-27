//! ESP32-C3 Demo: Solana SOL transfer from an embedded device.
//!
//! This example demonstrates the esp-solana SDK on real hardware.
//! It connects to WiFi, fetches a blockhash, builds and signs a
//! SOL transfer transaction, and submits it via JSON-RPC.
//!
//! ## Hardware
//! - ESP32-C3 dev board (e.g., ESP32-C3-DevKitM-1)
//!
//! ## Build & Flash
//! ```bash
//! # Install ESP toolchain (one time)
//! cargo install espup espflash
//! espup install
//! . ~/export-esp.sh
//!
//! # Build and flash
//! cargo +esp build --release -p esp32c3-demo
//! espflash flash target/riscv32imc-unknown-none-elf/release/esp32c3-demo --monitor
//! ```
//!
//! ## Configuration
//! Set your WiFi credentials and keypair seed below.

#![no_std]
#![no_main]

extern crate alloc;

use esp_println::println;

use esp_solana::prelude::*;
use esp_solana::crypto::Keypair;
use esp_solana::instruction::system_transfer;
use esp_solana::message::Message;
use esp_solana::transaction::Transaction;
use esp_solana::rpc::{RpcClient, SolanaRpc};

// ─── Configuration ───────────────────────────────────────────

const WIFI_SSID: &str = "YOUR_WIFI_SSID";
const WIFI_PASS: &str = "YOUR_WIFI_PASSWORD";
const RPC_URL: &str = "https://api.devnet.solana.com";

// WARNING: In production, use secure key storage (e.g., eFuse, secure element).
// This is a devnet-only demo seed.
const KEYPAIR_SEED: [u8; 32] = [42u8; 32];

// Recipient address (devnet faucet or your own wallet)
const RECIPIENT: &str = "11111111111111111111111111111112";

// ─── HTTP Client (stub — implement with your networking stack) ─

/// Placeholder HTTP client. Replace with your actual networking implementation.
///
/// Popular options for ESP32-C3:
/// - `reqwless` (async HTTP client for embedded)
/// - Manual TCP + HTTP/1.1 via `smoltcp` or `esp-wifi` sockets
/// - `esp-tls` for HTTPS
///
/// Example implementation with raw sockets:
/// ```ignore
/// impl RpcClient for EspHttpClient {
///     fn post_json(&self, url: &str, body: &str) -> esp_solana::types::Result<String> {
///         // 1. Parse URL into host:port and path
///         // 2. Open TCP socket via esp-wifi
///         // 3. Send HTTP POST request with Content-Type: application/json
///         // 4. Read response body
///         // 5. Return as String
///     }
/// }
/// ```
struct EspHttpClient;

impl RpcClient for EspHttpClient {
    fn post_json(&self, _url: &str, _body: &str) -> esp_solana::types::Result<alloc::string::String> {
        // TODO: Implement with your WiFi/HTTP stack
        // See examples in the esp-wifi crate for TCP socket usage
        Err(esp_solana::types::SdkError::Network)
    }
}

// ─── Entry Point ─────────────────────────────────────────────

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("PANIC: {}", info);
    loop {}
}

fn main() {
    // Initialize heap allocator (64KB for Solana operations)
    const HEAP_SIZE: usize = 65536;
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    unsafe {
        #[allow(static_mut_refs)]
        esp_alloc::HEAP.add_region(esp_alloc::HeapRegion::new(
            HEAP.as_mut_ptr(),
            HEAP_SIZE,
            esp_alloc::MemoryCapability::Internal,
        ));
    }

    println!("=== esp-solana ESP32-C3 Demo ===");

    // ── 1. Create keypair ──
    let keypair = Keypair::from_seed(&KEYPAIR_SEED).unwrap();
    println!("Payer: {}", keypair.pubkey());

    // ── 2. Parse recipient ──
    let recipient = Pubkey::from_bs58(RECIPIENT).expect("invalid recipient");
    println!("Recipient: {}", recipient);

    // ── 3. Initialize WiFi ──
    // TODO: Set up esp-wifi with your hardware peripherals
    // See: https://github.com/esp-rs/esp-wifi
    //
    // let peripherals = esp_hal::init(esp_hal::Config::default());
    // let timg0 = TimerGroup::new(peripherals.TIMG0);
    // let esp_wifi_ctrl = esp_wifi::init(timg0.timer0, rng, peripherals.RADIO_CLK).unwrap();
    // let (wifi_interface, controller) = esp_wifi::wifi::new_with_mode(
    //     &esp_wifi_ctrl, peripherals.WIFI, WifiStaDevice
    // ).unwrap();
    // ... connect to AP with SSID/password ...

    println!("WiFi: connect to '{}' (implement in EspHttpClient)", WIFI_SSID);

    // ── 4. Set up RPC client ──
    let rpc = SolanaRpc::new(RPC_URL, EspHttpClient);

    // ── 5. Get balance ──
    match rpc.get_balance(&keypair.pubkey()) {
        Ok(balance) => println!("Balance: {} lamports", balance),
        Err(e) => println!("Balance check failed: {:?} (WiFi not connected)", e),
    }

    // ── 6. Build transaction (offline — works without network) ──
    // Use a dummy blockhash for demo; in production, fetch via rpc.get_latest_blockhash()
    let blockhash = match rpc.get_latest_blockhash() {
        Ok(bh) => {
            println!("Blockhash: {}", bh);
            bh
        }
        Err(_) => {
            println!("Using dummy blockhash (no network)");
            Hash::new([0xAA; 32])
        }
    };

    let lamports = 1_000u64; // 0.000001 SOL
    let ix = system_transfer(keypair.pubkey(), recipient, lamports);
    let msg = Message::compile(keypair.pubkey(), &[ix], blockhash).unwrap();
    let tx = Transaction::new(msg, &[&keypair]).unwrap();

    println!("Transaction built:");
    println!("  Signature: {}", tx.signatures[0]);
    println!("  Wire size: {} bytes", tx.serialize().len());

    let b64 = tx.to_base64();
    println!("  Base64 length: {} chars", b64.len());

    // ── 7. Send transaction ──
    match rpc.send_transaction(&b64) {
        Ok(sig) => println!("Transaction sent! Sig: {}", sig),
        Err(e) => println!("Send failed: {:?} (expected without WiFi)", e),
    }

    println!("=== Demo complete ===");

    loop {}
}
