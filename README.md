# esp-solana

`no_std` Solana SDK for ESP32. Wallets, signing, transactions, and RPC — in ~163KB of flash.

<p align="left">
    <a href="https://crates.io/crates/esp-solana">
        <img src="https://img.shields.io/crates/v/esp-solana.svg" alt="Crates.io">
    </a>
    <a href="https://docs.rs/esp-solana">
        <img src="https://docs.rs/esp-solana/badge.svg" alt="Documentation">
    </a>
</p>

<img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
    <img src="https://img.shields.io/badge/Solana-9945FF?style=for-the-badge&logo=solana&logoColor=white" alt="Solana">

## Usage

```toml
[dependencies]
esp-solana = { git = "https://github.com/SkyRizzAI/esp-solana", features = ["wallet"] }
```

Requires `alloc`. On ESP32, set up a heap with `esp-alloc`:

```rust
esp_alloc::heap_allocator!(size: 65536);
```

## Wallet

```rust
use esp_solana::wallet::Wallet;

let entropy: [u8; 16] = get_from_hw_rng();
let wallet = Wallet::generate_12(&entropy).unwrap();

let mnemonic = wallet.mnemonic();
let keypair = wallet.keypair(0).unwrap();
let address = wallet.default_pubkey().unwrap();

// restore later
let restored = Wallet::from_mnemonic(mnemonic).unwrap();
```

Keys and seeds are zeroized from memory on drop.

## Transactions

```rust
use esp_solana::prelude::*;
use esp_solana::instruction::system_transfer;
use esp_solana::message::Message;
use esp_solana::transaction::Transaction;

let ix = system_transfer(keypair.pubkey(), recipient, 1_000_000);
let msg = Message::compile(keypair.pubkey(), &[ix], blockhash).unwrap();
let tx = Transaction::new(msg, &[&keypair]).unwrap();
let b64 = tx.to_base64(); // ready for sendTransaction
```

## RPC

The SDK doesn't include an HTTP client — you bring your own by implementing `RpcClient`:

```rust
use esp_solana::rpc::{RpcClient, SolanaRpc};

struct MyHttp;
impl RpcClient for MyHttp {
    fn post_json(&self, url: &str, body: &str) -> esp_solana::types::Result<String> {
        todo!("use reqwless, esp-wifi sockets, etc.")
    }
}

let rpc = SolanaRpc::new("https://api.devnet.solana.com", MyHttp);
let blockhash = rpc.get_latest_blockhash()?;
let balance = rpc.get_balance(&keypair.pubkey())?;
let sig = rpc.send_transaction(&b64)?;
```

Also supports `request_airdrop`, `get_signature_status`, `get_transaction`, `get_account_info`.

## Examples

```bash
# host-side transaction demo
cargo run --example host_demo --features wallet

# real devnet transfer (creates wallets, sends SOL, verifies)
cargo run --example devnet_transfer --features wallet
```

For ESP32-C3 hardware, see [`examples/esp32c3_demo/`](examples/esp32c3_demo/).

```bash
cd examples/esp32c3_demo
cargo build --release
espflash flash target/riscv32imc-unknown-none-elf/release/esp32c3-solana-demo --monitor
```

## ESP32-C3 flash usage

| Config | Flash |
|--------|-------|
| crypto only (signing + tx + rpc) | 148 KB |
| full SDK with wallet | 163 KB |

Out of 4MB. Use `lto = 'fat'` and `opt-level = 's'` in your release profile.

## NXP SE05x Secure Element

Hardware-backed key storage and signing via the NXP SE05x over I²C.
Private keys never leave the secure element.

```toml
[dependencies]
esp-solana = { git = "https://github.com/SkyRizzAI/esp-solana", features = ["se05x"] }
```

```rust
use esp_solana::se05x::Se05xSigner;
use esp_solana::signer::Signer;
use esp_solana::transaction::Transaction;

// `i2c` implements `embedded_hal::i2c::I2c`
let mut se = Se05xSigner::new(i2c, 0x0001_0001);
se.generate_ed25519().unwrap(); // one-time key generation

let pubkey = se.pubkey();
let ix = system_transfer(pubkey, recipient, 1_000_000);
let msg = Message::compile(pubkey, &[ix], blockhash).unwrap();
let tx = Transaction::sign(msg, &[&se]).unwrap();
let b64 = tx.to_base64();
```

The `Signer` trait lets you mix software and hardware signers in the same transaction:

```rust
let tx = Transaction::sign(msg, &[&se05x_signer as &dyn Signer]).unwrap();
```

## License

MIT
