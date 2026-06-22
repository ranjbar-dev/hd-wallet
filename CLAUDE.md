# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`github.com/ranjbar-dev/hd-wallet` is a published, security-focused, **Trust Wallet–compatible** HD wallet library (single Go package `hdwallet`, plus a demo CLI in `cmd/hdwallet`). It derives addresses and signs digests/messages for **129 networks**; the registered coins span 5 elliptic curves (secp256k1, ed25519, nist256p1, ed25519-blake2b, curve25519) and the package implements 8 curve schemes total (also ed25519-extended/Cardano, starkex, sr25519 — present but not yet wired to a registered chain). On top of raw signing it provides **EVM tooling** (RLP, ABI, EIP-191, EIP-712), **protobuf transaction signing** for core families (`SignTransaction`; EVM/Tron/XRP/Cosmos/Solana — no broadcast), **secure private-key import/export**, and **address validation/parsing** (`AnyAddress`-style). **Correctness is fund-critical**: a wrong address or signature means permanently lost funds, so nothing in the derivation/encoder/signing paths ships without passing an authoritative test vector.

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

### Feature layers built on top (Trust Wallet Core parity)
These reuse the derive/sign/encoder layers without touching the secret-isolation core:
- **Curves (`cardano.go`, `curve25519.go`, `ed25519_blake2b.go`, `starkex.go`, `sr25519.go`, `curve_helpers.go`):** the 5 curves beyond the original 3. Dispatched from `derive.go`/`sign.go`. Cardano needs BIP-39 *entropy* (not the seed) so its seed-path returns `errCardanoNeedsEntropy`; starkex seed→key and sr25519 are provisional/unverified — none is wired to a registered chain yet.
- **Passphrase + custom derivation (`secret.go`, `hdwallet.go`, `path.go`):** `FromMnemonicWithPassphrase`/`FromMnemonicBufferWithPassphrase` thread a BIP-39 passphrase through `deriveSeedEnclave` (passphrase wiped after seed derivation). `AddressPath`/`SignPath`/`PublicKeyPath`/`WithPrivateKeyPath`/`PrivateKeyPath` take an absolute path; `AddressAt`/`SignAt`/`PublicKeyAt` take account/change/index. All route through `withLeafPrivateKeyPath`→`deriveLeafSeedMode` (seed-only; key wiped on return).
- **Mnemonic length + bulk index (`hdwallet.go`):** `NewHDWalletWithWordCount`/`NewHDWalletWithEntropy`/`GenerateMnemonicWithWordCount` generate 12/15/18/21/24-word mnemonics (128–256-bit; `NewHDWallet`/`GenerateMnemonic` stay 12-word wrappers, `ErrInvalidWordCount` on a bad count). `AllAddressesAt(index)` derives every coin at an arbitrary index in one seed-open window (via `withIndex`); `AllAddresses` == `AllAddressesAt(0)`.
- **Private-key mode (`privatekey.go`, key-only branch in `secret.go`/`hdwallet.go`):** `FromPrivateKeyBytes`/`FromPrivateKeyBuffer` build a key-only wallet; `WithPrivateKey(fn)` (wiped on return) and `PrivateKey()` (memguard buffer) export — mirroring `WithMnemonic`/`Mnemonic`. **The "keys never leave the package as a raw `[]byte`" invariant still holds**; there is no raw getter. `withCoin` was unified into `withLeafPrivateKey` (handles both seed and key-only modes). `validatePrivateKey` accepts every 32-byte-scalar curve (Cardano excluded — 96-byte/entropy).
- **WIF + extended keys (`wif.go`, `extkey.go`):** `FromWIF`/`WithWIF`/`WIF` (secp256k1 Bitcoin WIF); `AccountXPub`/`WithAccountXPrv` export BIP-32 extended keys, and `WatchOnlyFromXPub` → `WatchWallet` derives addresses from an xpub with no seed. Extended keys / watch-only are **secp256k1-only** (`ErrExtKeyUnsupportedCurve`); xprv/WIF export follow the wiped-callback / memguard discipline (no raw-string secret getter).
- **EVM tooling (`eth_rlp.go`, `eth_abi.go`, `eth_eip191.go`, `eth_eip712.go`, `eth_message.go`):** pure-Go RLP, contract ABI, EIP-191 `personal_sign`, EIP-712 typed data, and an `EthereumMessageSigner`-style API. No new deps; reuses `keccak256` + the secp256k1 signer.
- **Non-EVM message signing (`message_bitcoin.go`, `message_solana.go`):** `SignBitcoinMessage`/`VerifyBitcoinMessage` (Bitcoin `signmessage` standard — magic-prefixed `sha256d`, secp256k1 recoverable, base64) and `SignSolanaMessage`/`VerifySolanaMessage` (raw-ed25519 off-chain message, base58). Each pinned byte-for-byte to its Trust Wallet Core `MessageSigner` vector. Cosmos ADR-36 is a documented roadmap stub + skipped test (`message_cosmos_test.go`) — TWC ships no ADR-36 vector.
- **Transaction signing (`tx.go` dispatcher + `tx_ethereum.go`/`tx_tron.go`/`tx_ripple.go`/`tx_cosmos.go`/`tx_solana.go`, protos in `txproto/`):** `(*HDWallet).SignTransaction(symbol, index, proto.Message)` returns a signed, serialized raw tx (**no broadcast**). Family routing is data-driven from `tx_families.go` (`evmTxChains`/`cosmosTxChains`) so all EVM and standard Cosmos chains sign — ethermint-keyed Cosmos chains (INJ/EVMOS/…) are deliberately excluded (wrong pubkey type). Shapes: EVM legacy/1559/2930 + ERC-20 + `ContractGeneric` (arbitrary call) + deploy (empty `to`) + **EIP-2930/1559 access lists** (`tx_mode` 1/2, `SigningInput.access_list`, vectors pinned to the go-ethereum reference signer); Cosmos `MsgSend`/`MsgDelegate`/`MsgUndelegate`/`MsgWithdrawReward` + multi-message; Solana system + SPL `TransferChecked`; Tron `TransferContract` + TRC-20 `TriggerSmartContract`. **Bitcoin** tx and ethermint Cosmos tx remain deferred (no authoritative TWC AnySigner vector — `tx_roadmap.go`). Non-EVM wire formats are hand-built with `protowire` for byte-exactness.
- **Address validation (`address_validate.go`):** `IsValidAddress`/`ValidateAddress`/`ParseAddress`/`AddressFromPublicKey` via a separate validator registry (reverse of the encoders) — keyed by `Symbol`, **not** stored on the `Coin` struct.
- `crypto.go` is excluded from gosec via `-exclude-generated` only for the generated `txproto/*.pb.go`; three hand-written safe int→byte conversions carry narrow `#nosec G115` notes.

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
