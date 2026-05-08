# Solana NoStd Secp256k1 Recover

[![CI](https://github.com/blueshift-gg/solana-nostd-secp256k1-recover/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-nostd-secp256k1-recover/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/solana-nostd-secp256k1-recover.svg)](https://crates.io/crates/solana-nostd-secp256k1-recover)
[![docs.rs](https://docs.rs/solana-nostd-secp256k1-recover/badge.svg)](https://docs.rs/solana-nostd-secp256k1-recover)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/blueshift-gg/solana-nostd-secp256k1-recover/blob/master/LICENSE)

A more efficient, `no_std` secp256k1 public-key recovery for the Solana SVM. Routes through the `sol_secp256k1_recover` syscall on-chain (~25006 CUs vs ~25193 CUs for `solana_program::secp256k1_recover::secp256k1_recover`) and falls through to the `k256` crate off-chain so the same APIs work in host code.

## Quick start

```toml
[dependencies]
solana-nostd-secp256k1-recover = "0.3.0"
```

```rust
use solana_nostd_secp256k1_recover::secp256k1_recover;

let pubkey = secp256k1_recover(&hash, is_odd, &signature)?;
```

The library is `#![no_std]`-clean for SBPF; no allocator setup required.

## Features

- No `Secp256k1Pubkey` struct — returns `[u8; 64]` directly (uncompressed point, no 0x04 prefix)
- Returns `solana_program_error::ProgramError` so the result is `?`-propagatable from any program entrypoint
- Uses `MaybeUninit` to skip zero-initializing the output buffer
- `secp256k1_recover_unchecked` skips the syscall return-code branch when callers have already validated the input

## Static syscalls

If your target supports the Upstream BPF / sBPFv3 static-syscall ABI, enable the `static-syscalls` feature:

```toml
[dependencies]
solana-nostd-secp256k1-recover = { version = "0.3.0", features = ["static-syscalls"] }
```

The syscall name is murmur3-hashed at compile time and transmuted to a fn pointer, so the SBPF program calls the syscall directly instead of going through an `extern "C"` PLT relocation. No measurable CU difference in our benchmarks — the win is a smaller `.so` and one less relocation for the loader to resolve.

## Benchmarks

On-chain compute unit cost per operation:

| function                      | CU cost |
|-------------------------------|--------:|
| `secp256k1_recover`           |   25006 |
| `secp256k1_recover_unchecked` |   25006 |

To reproduce, install `cargo build-sbf` (Solana CLI) and run:

```sh
cargo test --test sbpf --jobs 1
```

The benchmarks compile each function into its own SBPF program and run it through [Mollusk](https://github.com/anza-xyz/mollusk) via [`svm-unit-test`](https://crates.io/crates/svm-unit-test).

## License

Licensed under the [MIT License](https://github.com/blueshift-gg/solana-nostd-secp256k1-recover/blob/master/LICENSE). The license includes the standard "as-is" warranty disclaimer — use at your own risk.
