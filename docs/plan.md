# esp-solana SDK — Implementation Plan

## Problem
Build a compact, `no_std` Solana SDK for ESP32 (targeting ESP32-C3 / `riscv32imc-unknown-none-elf`) that can:
1. **Sign** transactions (Ed25519)
2. **Build** transactions (Solana wire format)
3. **Read** on-chain state (getBalance, getAccountInfo)
4. **Submit** RPC requests (sendTransaction, getLatestBlockhash)

## Approach
A **pure library** with zero hardware dependencies — no `esp-hal` in the SDK itself.
Users bring their own networking (esp-wifi, reqwless, smoltcp).
This keeps the SDK usable in any ESP32 project.

**Key design decisions:**
- **No `solana_program` dependency** — too heavy for embedded. We define our own minimal types (Pubkey, Hash, Signature as `[u8; 32/64]` wrappers).
- **`ed25519-compact`** for Ed25519 signing (~15 KB flash, no_std).
- **Built-in base58** encoder/decoder — essential for Solana, implemented in ~100 lines.
- **Built-in base64** encoder — needed for `sendTransaction`.
- **Manual JSON** building & parsing — no serde (too heavy). Simple string-search parser for RPC responses.
- **`alloc` required** — uses `Vec`/`String` from `alloc` crate (ESP32-C3 has enough RAM, and esp-hal provides a global allocator).
- **Feature-gated** modules to keep binary size minimal.

## Module Layout
```
src/
├── lib.rs          — crate root, no_std, feature gates
├── types.rs        — Pubkey, Hash, Signature, SdkError, Result
├── bs58.rs         — minimal base58 encode/decode
├── b64.rs          — minimal base64 encode
├── crypto.rs       — Keypair, sign, verify (ed25519-compact)
├── instruction.rs  — Instruction, AccountMeta, system_transfer
├── message.rs      — Message compilation + wire serialization
├── transaction.rs  — Transaction signing + full serialization
└── rpc.rs          — RpcClient trait, JSON-RPC builders, response parsers
```

## Modules Detail

### 1. types
- `Pubkey([u8; 32])` — Solana public key
- `Hash([u8; 32])` — Blockhash / program hash
- `Signature([u8; 64])` — Ed25519 signature
- `SdkError` — unified error enum
- System program ID constant (`11111111111111111111111111111111`)

### 2. bs58
- `encode(bytes) -> String` — base58 encode arbitrary bytes
- `decode(s) -> Vec<u8>` — base58 decode to bytes
- `decode_32(s) -> [u8; 32]` — decode exactly 32 bytes (pubkey/hash)

### 3. b64
- `encode(bytes) -> String` — standard base64 encode

### 4. crypto
- `Keypair` wrapping `ed25519_compact::KeyPair`
- `Keypair::from_seed([u8; 32])` — deterministic keypair
- `Keypair::from_bytes([u8; 64])` — from raw secret+public
- `Keypair::pubkey() -> Pubkey`
- `Keypair::sign(msg) -> Signature`
- `verify(pubkey, msg, sig) -> bool`

### 5. instruction
- `AccountMeta { pubkey, is_signer, is_writable }`
- `Instruction { program_id, accounts, data }`
- `system_transfer(from, to, lamports) -> Instruction`

### 6. message
- `CompiledInstruction { program_id_index, accounts, data }`
- `MessageHeader { num_required_signatures, num_readonly_signed, num_readonly_unsigned }`
- `Message { header, account_keys, recent_blockhash, instructions }`
- `Message::compile(payer, ixs, blockhash) -> Message` — dedup keys, sort signers first
- `Message::serialize() -> Vec<u8>` — exact Solana wire format

### 7. transaction
- `Transaction { signatures, message }`
- `Transaction::new(message, signers) -> Transaction` — sign + assemble
- `Transaction::serialize() -> Vec<u8>` — full wire format
- `Transaction::to_base64() -> String`

### 8. rpc
- `trait RpcClient { fn post_json(url, body) -> Result<String> }`
- `SolanaRpc<C: RpcClient>` — typed wrapper
- JSON builders: `get_latest_blockhash()`, `send_transaction(b64)`, `get_balance(pubkey)`, `get_account_info(pubkey)`
- Response parsers: extract blockhash, signature, balance, account data from JSON

## Dependencies (Cargo.toml)
```toml
[dependencies]
ed25519-compact = { version = "2.1", default-features = false, optional = true }

[features]
default = ["crypto"]
crypto = ["dep:ed25519-compact"]
std = []  # for host-side testing
```

## Target
- Primary: `riscv32imc-unknown-none-elf` (ESP32-C3 bare metal)
- Test: `x86_64` with `--features std`
