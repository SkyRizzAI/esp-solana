# esp-solana

A compact, `no_std` Solana SDK for ESP32 microcontrollers. Sign transactions, build messages, read on-chain state, manage wallets, and submit RPC requests — all from bare-metal Rust.

**~298 KB** release rlib (with wallet). **Only 2** external dependencies. **Zero** hardware dependencies — bring your own networking.

## Features

| Feature | What it does |
|---------|-------------|
| **Ed25519 signing** | Keypair generation, transaction signing, signature verification |
| **Transaction building** | Compile instructions → Solana wire format, exact byte-level compatibility |
| **Wallet management** | BIP39 mnemonic generation/validation, SLIP-10 HD key derivation, multi-account, zeroize-on-drop |
| **RPC client** | Transport-agnostic JSON-RPC for `getLatestBlockhash`, `sendTransaction`, `getBalance`, `getAccountInfo` |
| **Base58 / Base64** | Built-in codecs, no external dependencies |
| **System program** | SOL transfer instruction builder |

## Quick Start

### Add to your project

```toml
# Cargo.toml
[dependencies]
# Full SDK with wallet support
esp-solana = { git = "https://github.com/SkyRizzAI/esp-solana", features = ["wallet"] }

# Or just crypto (no wallet/mnemonic)
# esp-solana = { git = "https://github.com/SkyRizzAI/esp-solana", features = ["crypto"] }
```

### Create and manage a wallet

```rust
use esp_solana::wallet::Wallet;

// Generate a new wallet from hardware RNG entropy (16 bytes = 12-word mnemonic)
let entropy: [u8; 16] = get_entropy_from_hw_rng(); // ESP32 hardware RNG
let wallet = Wallet::generate_12(&entropy).unwrap();

// Save the mnemonic phrase (back it up securely!)
let mnemonic = wallet.mnemonic(); // "word1 word2 ... word12"

// Restore a wallet from mnemonic
let restored = Wallet::from_mnemonic(mnemonic).unwrap();

// Derive keypairs for multiple accounts
let keypair_0 = wallet.keypair(0).unwrap(); // Default account
let keypair_1 = wallet.keypair(1).unwrap(); // Second account

// Get addresses
let address = wallet.default_pubkey().unwrap();
println!("Address: {}", address);
```

### Build and sign a SOL transfer

```rust
use esp_solana::prelude::*;
use esp_solana::crypto::Keypair;
use esp_solana::instruction::system_transfer;
use esp_solana::message::Message;
use esp_solana::transaction::Transaction;

// Create keypair from a 32-byte seed
let keypair = Keypair::from_seed(&[42u8; 32]).unwrap();

// Build a transfer instruction (0.001 SOL)
let recipient = Pubkey::from_bs58("RecipientBase58Address...").unwrap();
let ix = system_transfer(keypair.pubkey(), recipient, 1_000_000);

// Compile message with a recent blockhash
let blockhash = Hash::new([/* 32 bytes from RPC */]);
let msg = Message::compile(keypair.pubkey(), &[ix], blockhash).unwrap();

// Sign and serialize
let tx = Transaction::new(msg, &[&keypair]).unwrap();
let b64 = tx.to_base64();  // Ready for sendTransaction RPC
```

### Use the RPC client

```rust
use esp_solana::rpc::{RpcClient, SolanaRpc};

// Implement the transport trait with your HTTP client
struct MyHttpClient;
impl RpcClient for MyHttpClient {
    fn post_json(&self, url: &str, body: &str) -> esp_solana::types::Result<String> {
        // HTTP POST with Content-Type: application/json
        // Return response body as String
        todo!()
    }
}

let rpc = SolanaRpc::new("https://api.devnet.solana.com", MyHttpClient);

// Fetch blockhash
let blockhash = rpc.get_latest_blockhash()?;

// Check balance
let balance = rpc.get_balance(&keypair.pubkey())?;

// Send transaction
let sig = rpc.send_transaction(&tx.to_base64())?;

// Read account info (raw JSON)
let info = rpc.get_account_info(&some_pubkey)?;
```

## Architecture

```
esp-solana (pure library, no hardware deps)
├── types      Pubkey, Hash, Signature, SdkError
├── bs58       Base58 encode/decode (built-in)
├── b64        Base64 encode/decode (built-in)
├── crypto     Ed25519 via ed25519-compact [feature: "crypto"]
├── wallet     Wallet struct, generate/restore/derive [feature: "wallet"]
├── bip39      BIP39 mnemonic + PBKDF2 seed derivation [feature: "wallet"]
├── slip10     SLIP-10 Ed25519 HD key derivation [feature: "wallet"]
├── instruction  System program builders
├── message    Compile & serialize to Solana wire format
├── transaction  Sign + serialize full transactions
└── rpc        Transport-agnostic JSON-RPC client
```

### Design Decisions

- **No `solana_program` dependency** — self-contained types (`Pubkey` = `[u8; 32]` wrapper). This avoids pulling in heavy std-dependent crates.
- **No serde** — manual JSON building and parsing keeps the binary tiny. The parsers handle whitespace variations and null values.
- **No `esp-hal` in the library** — `esp-solana` is a pure SDK. Your project brings the networking stack (reqwless, smoltcp, esp-wifi sockets, etc.).
- **Feature-gated crypto** — the `crypto` feature adds Ed25519 via `ed25519-compact` (~15 KB). Disable it if you sign externally.
- **Compact wordlist** — BIP39 English words stored as a single `include_str!` text file (~13 KB) instead of 2048 `&str` pointers, saving ~16 KB of metadata on 32-bit targets.
- **Zeroize-on-drop** — `DerivedKey` and `Wallet` use `write_volatile` to zero private keys and seeds from SRAM when dropped, preventing key material from lingering in memory.
- **`alloc` required** — uses `Vec` and `String` from the alloc crate. ESP32-C3 has 400 KB SRAM, so this is fine. Initialize a heap allocator in your project (e.g., `esp-alloc`).

## ESP32-C3 Setup

### Prerequisites

```bash
# Install Rust ESP toolchain
cargo install espup espflash
espup install
. ~/export-esp.sh    # Run each terminal session, or add to shell profile
```

### Project structure

```
my-esp32c3-project/
├── Cargo.toml
├── src/
│   └── main.rs
└── .cargo/
    └── config.toml
```

**.cargo/config.toml:**
```toml
[build]
target = "riscv32imc-unknown-none-elf"

[target.riscv32imc-unknown-none-elf]
runner = "espflash flash --monitor"
```

**Cargo.toml:**
```toml
[dependencies]
esp-solana = { path = "../esp-solana", features = ["wallet"] }
esp-hal = { version = "0.23", features = ["esp32c3"] }
esp-wifi = { version = "0.13", features = ["esp32c3", "wifi"] }
esp-alloc = "0.7"
esp-println = { version = "0.13", features = ["esp32c3", "log"] }
```

### Heap allocator

ESP32-C3 needs a heap allocator for `alloc`. Add this to your `main()`:

```rust
const HEAP_SIZE: usize = 131072; // 128KB for wallet + transactions
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
unsafe {
    esp_alloc::HEAP.add_region(esp_alloc::HeapRegion::new(
        HEAP.as_mut_ptr(), HEAP_SIZE,
        esp_alloc::MemoryCapability::Internal,
    ));
}
```

### Implementing the HTTP transport

The SDK is transport-agnostic. You implement `RpcClient` with your networking stack:

```rust
use esp_solana::rpc::RpcClient;

struct EspHttpClient { /* your wifi/socket state */ }

impl RpcClient for EspHttpClient {
    fn post_json(&self, url: &str, body: &str)
        -> esp_solana::types::Result<alloc::string::String>
    {
        // 1. Open TCP socket (via esp-wifi)
        // 2. Optional: TLS handshake (via esp-tls) for HTTPS
        // 3. Send: POST /path HTTP/1.1\r\nHost: ...\r\nContent-Type: application/json\r\n...
        // 4. Read response body
        // 5. Return as String
        todo!()
    }
}
```

## Examples

### Host demo (runs on your computer)

```bash
# Transaction demo
cargo run --example host_demo --features crypto

# Full demo with wallet
cargo run --example host_demo --features wallet
```

Output:
```
=== esp-solana Host Demo ===

Payer pubkey: 2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ
Recipient:    11111111111111111111111111111112

Payer balance: 5000000000 lamports (5 SOL)
Blockhash:    GWWjbfFnZkEqjVh8sMz5HFkpJLaRqfNG3P3fX7aEbCE9

Transfer:     1000000 lamports → 11111111111111111111111111111112
Signature:    2suTHPgyh5vxu87gymj5thW182eoZYt4qgyKz84VCEGBg8bR1uCRy9B4MuRLn39ZhJz1AePgy9jnTrzAdeb4gMBs
Wire size:    215 bytes

Tx sent!      5VERv8NMhbf3stL4VKdZXzK12xJGQRP2WQGLNfgfB2aD

=== Demo complete ===
```

### ESP32-C3 demo (embedded)

See [`examples/esp32c3_demo/`](examples/esp32c3_demo/) for a complete project scaffold with WiFi setup, keypair loading, and RPC integration.

```bash
cd examples/esp32c3_demo
cargo +esp build --release
espflash flash target/riscv32imc-unknown-none-elf/release/esp32c3-demo --monitor
```

## Cargo Features

| Feature | Default | Description |
|---------|---------|-------------|
| `crypto` | ✅ | Ed25519 signing via `ed25519-compact` |
| `wallet` | ❌ | BIP39 mnemonic + SLIP-10 key derivation (enables `crypto`) |
| `std` | ❌ | Enable std (for host-side testing) |

### Minimal build (no crypto)

If you sign transactions externally (e.g., via a secure element or host computer):

```toml
esp-solana = { path = "..", default-features = false }
```

Use `Transaction::new_with_signatures()` to attach pre-computed signatures.

## Module Reference

### `types`
- `Pubkey` — 32-byte public key with base58 Display
- `Hash` — 32-byte blockhash with base58 Display
- `Signature` — 64-byte Ed25519 signature with base58 Display
- `SdkError` — unified error enum: `Crypto`, `Rpc`, `Network`, `Serialize`, `Deserialize`, `Invalid`, `Timeout`, `Unsupported`

### `crypto` (feature: `crypto`)
- `Keypair::from_seed(&[u8; 32])` — deterministic keypair from seed
- `Keypair::from_bytes(&[u8; 64])` — from Solana CLI format (secret + public)
- `Keypair::pubkey()` → `Pubkey`
- `Keypair::sign(&[u8])` → `Signature`
- `verify(&Pubkey, &[u8], &Signature)` → `bool`

### `wallet` (feature: `wallet`)
- `Wallet::generate_12(&[u8; 16])` — new 12-word wallet from entropy
- `Wallet::generate_24(&[u8; 32])` — new 24-word wallet from entropy
- `Wallet::from_mnemonic(phrase)` — restore from mnemonic string
- `Wallet::from_mnemonic_with_passphrase(phrase, pass)` — restore with BIP39 passphrase
- `Wallet::mnemonic()` → `&str` — the mnemonic phrase
- `Wallet::keypair(account)` → `Result<Keypair>` — derive keypair at `m/44'/501'/account'/0'`
- `Wallet::pubkey(account)` → `Result<Pubkey>` — derive address
- `Wallet::default_pubkey()` → `Result<Pubkey>` — account 0 address
- `Wallet::seed()` → `&[u8; 64]` — raw BIP39 seed bytes

### `bip39` (feature: `wallet`)
- `Mnemonic::from_entropy_128(&[u8; 16])` — 12-word mnemonic from entropy
- `Mnemonic::from_entropy_256(&[u8; 32])` — 24-word mnemonic from entropy
- `Mnemonic::from_phrase(phrase)` — parse and validate mnemonic
- `Mnemonic::derive_seed(passphrase)` → `[u8; 64]` — PBKDF2-HMAC-SHA512

### `slip10` (feature: `wallet`)
- `DerivedKey::master(&[u8; 64])` — master key from BIP39 seed
- `DerivedKey::derive_child(index)` — hardened child derivation
- `DerivedKey::derive_solana_path(seed, account, change)` — full `m/44'/501'/account'/change'`
- `DerivedKey::to_keypair()` → `Result<Keypair>` — convert to signing keypair

### `instruction`
- `system_transfer(from, to, lamports)` → `Instruction`
- `Instruction::new(program_id, accounts, data)` — custom instruction builder
- `AccountMeta::new(pubkey, is_signer, is_writable)`

### `message`
- `Message::compile(payer, &[Instruction], blockhash)` — dedup accounts, sort signers, build wire format
- `Message::serialize()` → `Vec<u8>` — exact Solana wire format

### `transaction`
- `Transaction::new(message, &[&Keypair])` — sign and assemble
- `Transaction::new_with_signatures(message, signatures)` — pre-signed
- `Transaction::serialize()` → `Vec<u8>` — full wire format
- `Transaction::to_base64()` → `String` — ready for `sendTransaction`

### `rpc`
- `trait RpcClient` — implement `post_json(url, body) -> Result<String>`
- `SolanaRpc::new(url, client)` — high-level wrapper
- `SolanaRpc::get_latest_blockhash()` → `Result<Hash>`
- `SolanaRpc::send_transaction(b64)` → `Result<String>`
- `SolanaRpc::get_balance(pubkey)` → `Result<u64>`
- `SolanaRpc::get_account_info(pubkey)` → `Result<String>`

### `bs58` / `b64`
- `bs58::encode(&[u8])` → `String`
- `bs58::decode(&str)` → `Result<Vec<u8>>`
- `bs58::decode_32(&str)` → `Result<[u8; 32]>`
- `b64::encode(&[u8])` → `String`
- `b64::decode(&str)` → `Result<Vec<u8>>`

## Binary Size (RISC-V 32-bit release rlib)

| Config | Size | Dependencies |
|--------|------|-------------|
| `wallet` | ~298 KB | 2 (ed25519-compact, hmac-sha256/512) |
| `crypto` only | ~163 KB | 1 (ed25519-compact) |
| no features | ~145 KB | 0 |

## Security

- **Zeroize-on-drop** — `DerivedKey` and `Wallet` automatically zero private keys and seeds from memory when dropped via `core::ptr::write_volatile`. This prevents key material from lingering in ESP32 SRAM where it could be extracted via JTAG, memory dumps, or fault injection.
- **Never hardcode mainnet private keys** in firmware. Use secure key storage (eFuse, secure element, or encrypted flash).
- **Protect mnemonic phrases** — store encrypted in NVS (Non-Volatile Storage) or secure element. Never log or transmit mnemonics.
- **Use HTTPS** (TLS) for RPC connections to prevent MITM attacks on transaction submission.
- **Use hardware RNG** for wallet entropy — ESP32's `esp_random()` via `esp-hal` provides true random numbers.
- **Devnet only** for development. Test thoroughly before mainnet deployment.
- **PBKDF2 is slow on ESP32** (~1-3 seconds for 2048 iterations) — this is expected and provides brute-force resistance.

## License

MIT
