# esp-solana SDK — Implementation Plan

## Status: Phase 2 Complete ✓

## Problem
Build a compact, `no_std` Solana SDK for ESP32 (targeting ESP32-C3 / `riscv32imc-unknown-none-elf`) that can:
1. **Sign** transactions (Ed25519) ✓
2. **Build** transactions (Solana wire format) ✓
3. **Read** on-chain state (getBalance, getAccountInfo) ✓
4. **Submit** RPC requests (sendTransaction, getLatestBlockhash) ✓

## Completed

### Phase 1: Core SDK
- All 8 modules implemented and tested (35 tests)
- Cross-compiles for `riscv32imc-unknown-none-elf`
- 146 KB release rlib with crypto, ~30 KB without

### Phase 2: Hardening & Docs
- Hardened RPC JSON parsers (whitespace handling, null values, robust error detection)
- Deduplicated `write_compact_u16` into shared `types` module
- Added Display impls for Pubkey/Hash/Signature (base58 output for serial debugging)
- Added validation guards (account count limit, signer order verification)
- Created host demo (`examples/host_demo.rs`)
- Created ESP32-C3 project scaffold (`examples/esp32c3_demo/`)
- Comprehensive README.md with getting started, API reference, examples

## Module Layout
```
src/
├── lib.rs          — crate root, no_std, feature gates
├── types.rs        — Pubkey, Hash, Signature, SdkError, write_compact_u16
├── bs58.rs         — minimal base58 encode/decode
├── b64.rs          — minimal base64 encode/decode
├── crypto.rs       — Keypair, sign, verify (ed25519-compact)
├── instruction.rs  — Instruction, AccountMeta, system_transfer
├── message.rs      — Message compilation + wire serialization
├── transaction.rs  — Transaction signing + full serialization
└── rpc.rs          — RpcClient trait, JSON-RPC builders, response parsers

examples/
├── host_demo.rs           — Run on host with mock RPC
└── esp32c3_demo/          — Full ESP32-C3 project scaffold
    ├── Cargo.toml
    └── src/main.rs
```

## Future Work
- SPL Token transfer instruction builder
- Memo program instruction
- `reqwless`-based `RpcClient` implementation for ESP32
- Websocket subscription support for account change notifications
- Hardware RNG integration for keypair generation on ESP32
