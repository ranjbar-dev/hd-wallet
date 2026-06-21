# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`github.com/ranjbar-dev/hd-wallet` is a published, security-focused, **Trust Wallet–compatible** HD wallet library (single Go package `hdwallet`, plus a demo CLI in `cmd/hdwallet`). It derives addresses and signs digests/messages for 33 networks across 3 elliptic curves. **Correctness is fund-critical**: a wrong address or signature means permanently lost funds, so nothing in the derivation/encoder/signing paths ships without passing an authoritative test vector.

## Commands

```bash
go build ./...
go test -race -cover ./...                 # full suite (target ≥80% on the library package)
go test -race -run TestSignSecp256k1 .     # single test
go test -run 'Example' -count=1 .          # run runnable examples (verifies // Output: blocks)
go test -run '^$' -fuzz '^FuzzParsePath$' -fuzztime 10s .   # fuzz parsePath
go test -run '^$' -bench '^Benchmark' .    # benchmarks

gofmt -l .                                 # must be empty
go vet ./...
golangci-lint run ./...                    # v2 config in .golangci.yml; CI pins v2.12
gosec -quiet ./...                         # security scan
govulncheck ./...                          # use Go ≥1.24.4 locally to avoid a stdlib-only false positive

go run ./cmd/hdwallet -mnemonic "abandon abandon ... about"   # derive every chain's address
```

There is no Makefile; run the Go toolchain directly. Tests live in the same package (`package hdwallet`) so they can exercise unexported helpers; examples/benchmarks are `package hdwallet_test`.

## Architecture

The whole library is one flat package built around three concerns. Reading these in order explains the system:

1. **Secret isolation (`secret.go`, `hdwallet.go`).** The mnemonic and derived seed live only in **memguard enclaves** (encrypted at rest in RAM, page-locked against swap, auto-wiped) — never as a Go `string` or long-lived `[]byte`, and never in an exported field. `secret.withSeed(fn)` opens the seed enclave exactly once per operation and destroys the decrypted buffer on return. `HDWallet` guards everything with a `sync.RWMutex` and a `w.secret == nil → ErrDestroyed` check; `Destroy()` wipes secrets. **Invariant: private keys are derived, used, and wiped inside the package — they are NEVER returned to callers.** There is deliberately no `PrivateKey()` getter; adding one would defeat the entire design.

2. **Curve-agnostic registry (`registry.go`).** `Symbol` is a typed string enum with an exported constant per network (`BTC`, `ETH`, `SOL`, …). `Coin{Name, Symbol, Curve, Path, Encode}` is the registry row; `coins` is a `map[Symbol]Coin`. `Curve` is one of `Secp256k1`, `Ed25519`, `Nist256p1`. **Adding a network is a single registry row** plus an encoder — the public API (`Address`, `Sign`, `PublicKey`, `AllAddresses`, `SupportedCoins`) is data-driven off this map.

3. **Derivation + signing layers** — designed so future per-chain transaction builders ("Option B") reuse the bottom layers without changes:
   - **Layer 1 — `derive.go`:** `withPrivateKey(seed, coin, fn)` is the *single* place a private key is materialized; it derives the leaf key per curve, hands the raw 32-byte key to `fn`, and **wipes it on return**. `derivePublicKey` is implemented on top of it. secp256k1 uses BIP-32 via `btcd/hdkeychain`; ed25519 and nist256p1 use **SLIP-0010** (`slip10.go`, `deriveEd25519`/`deriveNist256p1`). `parsePath` parses `m/44'/.../0/0`; `withIndex` rewrites the final path element for multi-address support (`AddressIndex`/`SignIndex`).
   - **Layer 2 — `sign.go`:** per-curve signers (`signDigest`) and the `Signature` type. secp256k1 = RFC 6979 deterministic, canonical low-S, recoverable; ed25519 signs the message directly; nist256p1 = ECDSA P-256. `Signature` exposes `Bytes()` (64-byte R‖S / ed25519), `Recoverable()` (65-byte R‖S‖V, secp256k1 only), and `DER()`.
   - **Layer 3 — `hdwallet.go`:** the public `Sign`/`SignIndex`/`PublicKey`/`Address` methods, all routed through `withCoin` (resolve symbol+index → open seed once → run callback).
   - **Encoders** are split by curve: `encoders_secp256k1.go` (BTC/EVM/Cosmos/XRP/Tron/…), `encoders_ed25519.go` (SOL/XLM/SS58/…), `encoders_nist256p1.go` (NEO). `crypto.go` and `codec.go` hold shared hash/base58/bech32/base32 primitives.

### The hashing asymmetry (don't break this)
ECDSA chains (secp256k1, nist256p1) sign a **32-byte digest** — the *caller* pre-hashes with the chain's hash function. ed25519 signs the **raw message**. `Sign` validates 32-byte input for ECDSA (`ErrInvalidDigest`) and passes ed25519 messages through unchanged. This is inherent to the cryptography, not a style choice.

## How correctness is proven (extend this when adding chains)

Three independent sources of truth — a change to derivation/encoding/signing must keep all green:
- **Encoders** (`encoders_test.go`): every address encoder checked against Trust Wallet Core's `CoinAddressDerivationTests` exact outputs for a fixed key.
- **Derivation** (`slip10_test.go`): ed25519/nist256p1 against official **SLIP-0010** spec vectors; secp256k1/end-to-end against BIP-84 (BTC) and the canonical ETH vector (`hdwallet_test.go`, `address_index_test.go`).
- **Signing** (`sign_test.go`): sign/verify per curve, RFC 6979 determinism, and the strong anchor — sign an ETH digest, `ecrecover`, and assert the address equals the known value for the canonical mnemonic.

The canonical test mnemonic everywhere is the all-`abandon … about` BIP-39 vector (holds no funds). When adding a network, add its Trust Wallet test vector before considering it done.

## CI / release

`.github/workflows/ci.yml` runs Build & Test, Security (govulncheck + gosec), and Lint (golangci-lint v2.12) on push/PR. **Releases are automated**: every push to `main` that passes the gates auto-tags the next semver and publishes to the Go proxy + a GitHub Release. The bump is controlled by the **commit message**: `[major]`, `[minor]`, default = patch, `[skip release]` = none. Pushing to `main` therefore publishes an immutable version — use `[skip release]` if a push should not release. The module path in `go.mod` must always match the repository (`github.com/ranjbar-dev/hd-wallet`), or published versions become uninstallable.

## Conventions

- RIPEMD-160 (`crypto.go`) is intentionally imported despite deprecation (consensus-mandated for Bitcoin/Cosmos `hash160`); it is `//nosec`/`//nolint`-annotated and excluded for SA1019 in `.golangci.yml` for that file only — keep that exclusion narrow.
- Breaking API changes are acceptable pre-1.0 but the security invariants (no exported secrets, keys wiped after use, RFC 6979 + low-S for ECDSA) are not negotiable.
- Commit messages: conventional (`feat:`, `fix:`, …), attribution disabled.
