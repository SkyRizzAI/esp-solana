# esp-solana

A compact, `no_std` Solana SDK for ESP32 microcontrollers. Sign transactions, build messages, read on-chain state, and submit RPC requests — all from bare-metal Rust.

**146 KB** release binary. **One** optional dependency (`ed25519-compact`). **Zero** hardware dependencies — bring your own networking.

## Features

| Feature | What it does |
|---------|-------------|
| **Ed25519 signing** | Keypair generation, transaction signing, signature verification |
| **Transaction building** | Compile instructions → Solana wire format, exact byte-level compatibility |
| **RPC client** | Transport-agnostic JSON-RPC for `getLatestBlockhash`, `sendTransaction`, `getBalance`, `getAccountInfo` |
| **Base58 / Base64** | Built-in codecs, no external dependencies |
| **System program** | SOL transfer instruction builder |

## Quick Start

### Add to your project

```toml
# Cargo.toml
[dependencies]
esp-solana = { git = "https://github.com/youruser/esp-solana", features = ["crypto"] }
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
esp-solana = { path = "../esp-solana", features = ["crypto"] }
esp-hal = { version = "0.23", features = ["esp32c3"] }
esp-wifi = { version = "0.13", features = ["esp32c3", "wifi"] }
esp-alloc = "0.7"
esp-println = { version = "0.13", features = ["esp32c3", "log"] }
```

### Heap allocator

ESP32-C3 needs a heap allocator for `alloc`. Add this to your `main()`:

```rust
const HEAP_SIZE: usize = 65536; // 64KB is plenty for Solana
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
cargo run --example host_demo --features crypto
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

## Binary Size

| Config | Size |
|--------|------|
| Release rlib (`crypto` on) | ~146 KB |
| Release rlib (no crypto) | ~30 KB |

## Security Notes

- **Never hardcode mainnet private keys** in firmware. Use secure key storage (eFuse, secure element, or encrypted flash).
- **Use HTTPS** (TLS) for RPC connections to prevent MITM attacks on transaction submission.
- **Devnet only** for development. Test thoroughly before mainnet deployment.

## License

MIT OR Apache-2.0
