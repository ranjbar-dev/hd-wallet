# hd-wallet

[![Go Reference](https://pkg.go.dev/badge/github.com/ranjbar-dev/hd-wallet.svg)](https://pkg.go.dev/github.com/ranjbar-dev/hd-wallet)
[![Go Report Card](https://goreportcard.com/badge/github.com/ranjbar-dev/hd-wallet)](https://goreportcard.com/report/github.com/ranjbar-dev/hd-wallet)
[![CI](https://github.com/ranjbar-dev/hd-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/ranjbar-dev/hd-wallet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **Trust Wallet–compatible**, security-focused **hierarchical-deterministic (HD) wallet** library for Go.

Generate a BIP-39 mnemonic (or import one) and derive receive addresses for **33 networks across 3 elliptic-curve families** using the same derivation paths and address formats Trust Wallet uses by default — so seeds are interchangeable between the two.

Sensitive material (the mnemonic and derived seed) is **never** held as a plain Go string or a long-lived byte slice. It lives in encrypted, page-locked [memguard](https://github.com/awnumar/memguard) enclaves and is decrypted only for the microseconds of a single derivation.

---

## Why this library

- 🔐 **Secrets isolated in RAM.** Encrypted enclaves, memory locked against swap (`mlock`/`VirtualLock`), guard pages, and automatic wiping. No mnemonic-as-`string`, no exported secret fields.
- ✅ **Provably Trust Wallet–compatible.** Every address encoder is tested against Trust Wallet Core's own vectors; key derivation is tested against the SLIP-0010 specification. See [Verification](#verification).
- 🌐 **33 networks, 3 curves.** secp256k1 (Bitcoin-style, EVM, Cosmos, XRP, Tron), ed25519 (Solana, Stellar, Polkadot, …), and NIST P-256 (NEO).
- ✍️ **Raw signing** for every network (ECDSA + EdDSA). Derived keys are wiped after each signature and are never exported.
- 🧩 **Extensible.** Add a network with a single registry row.
- 📦 **Small dependency surface.** btcd (secp256k1/bech32/base58), go-bip39, x/crypto, and memguard.

---

## Install

```bash
go get github.com/ranjbar-dev/hd-wallet
```

```go
import hdwallet "github.com/ranjbar-dev/hd-wallet"
```

Requires Go 1.23+.

---

## Quick start

```go
package main

import (
	"fmt"
	"log"

	"github.com/awnumar/memguard"
	hdwallet "github.com/ranjbar-dev/hd-wallet"
)

func main() {
	defer memguard.Purge() // wipe all protected memory on exit

	// Create a wallet with a fresh 12-word mnemonic...
	w, err := hdwallet.NewHDWallet()
	if err != nil {
		log.Fatal(err)
	}
	defer w.Destroy() // wipe this wallet's secrets when done

	// ...or import one:
	// w, _ := hdwallet.FromMnemonic("abandon abandon ... about")

	// Symbols are a typed enum (hdwallet.Symbol) — use the exported constants
	// for compile-time checking and autocomplete.
	btc, _ := w.Address(hdwallet.BTC)
	eth, _ := w.Address(hdwallet.ETH)
	sol, _ := w.Address(hdwallet.SOL)
	fmt.Println(btc, eth, sol)

	all, _ := w.AllAddresses() // map[hdwallet.Symbol]string for every network
	fmt.Println(all[hdwallet.ATOM])
}
```

### Reading the mnemonic safely

The mnemonic is never exposed as a field. Read it only when needed, through a
buffer that is wiped immediately afterwards:

```go
err := w.WithMnemonic(func(mnemonic []byte) error {
	fmt.Printf("%s\n", mnemonic) // do not let the slice escape this function
	return nil
})
```

### Multiple addresses per chain

`Address` returns the first receive address; `AddressIndex` derives any index by
replacing the final element of the chain's path (preserving its hardened flag):

```go
a0, _ := w.AddressIndex(hdwallet.BTC, 0) // bc1q...306fyu (same as w.Address(hdwallet.BTC))
a1, _ := w.AddressIndex(hdwallet.BTC, 1) // bc1q...rkf9g — second receive address
sol1, _ := w.AddressIndex(hdwallet.SOL, 1) // account-based chains vary the hardened element
```

### Error handling

The package exports sentinel errors for use with `errors.Is`:
`ErrInvalidMnemonic`, `ErrUnsupportedCoin`, and `ErrDestroyed`.

```go
if _, err := w.Address("NOPE"); errors.Is(err, hdwallet.ErrUnsupportedCoin) {
	// unknown symbol
}
```

### Signing (raw)

`Sign`/`SignIndex` produce a signature with the derived private key for any
supported chain. The key is wiped immediately after signing and **never leaves
the package** — there is no way to extract a private key.

There is one inherent rule, driven by the cryptography:

- **ECDSA chains** (secp256k1, nist256p1 — BTC, ETH, ATOM, NEO, …): pass the
  **32-byte digest** your chain signs. Pre-hash the message yourself with the
  chain's hash (keccak256 for Ethereum/Tron, double-SHA256 for Bitcoin, SHA-256
  for Cosmos, …).
- **ed25519 chains** (SOL, XLM, DOT, …): pass the **message**; the EdDSA scheme
  hashes internally.

```go
digest := sha256.Sum256(txBytes)         // chain-specific pre-hash for ECDSA
sig, _ := w.Sign(hdwallet.BTC, digest[:])

sig.Bytes()        // 64-byte R||S (ECDSA) or 64-byte ed25519 signature  → Cosmos, Solana
sig.Recoverable()  // 65-byte R||S||V (secp256k1 only)                   → Ethereum/EVM, Tron
sig.DER()          // ASN.1 DER (ECDSA)                                  → Bitcoin family

pub, _ := w.PublicKey(hdwallet.BTC)
ok := hdwallet.Verify(hdwallet.Secp256k1, pub, digest[:], sig)
```

`SignIndex(symbol, index, data)` and `PublicKeyIndex(symbol, index)` work with
non-zero address indices. ECDSA inputs that are not 32 bytes return
`ErrInvalidDigest`.

> This is **raw signing** only — you build and serialize the transaction (with a
> chain SDK or your own encoder) and hand the digest/message here. The signing
> primitives and `Signature` encodings are designed to be reused as the core for
> full per-chain transaction builders later.

---

## Passing a mnemonic in securely

The golden rule: **never let the mnemonic become a Go `string`** in your code — strings are immutable and can never be wiped from memory. Choose the entry point that matches how securely you can hold the secret:

| Entry point | Security | When |
|---|---|---|
| `FromMnemonicBuffer(*memguard.LockedBuffer)` | 🟢 Strongest | Mnemonic stays in page-locked, encrypted memory end-to-end; sealed zero-copy into the wallet. |
| `FromMnemonicBytes([]byte)` | 🟡 Good | You have a mutable `[]byte`; it is wiped inside the call. |
| `FromMnemonic(string)` | 🔴 Weakest | Convenience only; the string cannot be wiped. Avoid for real funds. |

### Most secure: hand off a memguard buffer (zero-copy)

The wallet takes ownership of the buffer and destroys it — there is no extra unprotected copy anywhere in your process.

```go
import (
	"os"

	"github.com/awnumar/memguard"
	hdwallet "github.com/ranjbar-dev/hd-wallet"
)

func loadWallet() (*hdwallet.HDWallet, error) {
	defer memguard.Purge()

	// Read one line straight into locked, encrypted memory — never a string.
	buf, err := memguard.NewBufferFromReaderUntil(os.Stdin, '\n')
	if err != nil {
		return nil, err
	}
	// Ownership transfers to the wallet; buf is destroyed for you.
	return hdwallet.FromMnemonicBuffer(buf)
}
```

From a secrets manager / KMS that returns raw bytes:

```go
raw := fetchFromVault()                    // []byte from your secret store
buf := memguard.NewBufferFromBytes(raw)    // copies into protected memory, wipes raw
w, err := hdwallet.FromMnemonicBuffer(buf) // takes ownership of buf
```

### Good: a mutable byte slice

```go
raw, _ := os.ReadFile("mnemonic.txt") // []byte, never a string
mn := bytes.TrimSpace(raw)
w, err := hdwallet.FromMnemonicBytes(mn) // mn is zeroed inside the call
for i := range raw {                     // wipe any trimmed remainder
	raw[i] = 0
}
```

> **Avoid `os.Getenv`** for the mnemonic: environment variables are already
> immutable strings and cannot be wiped.

> **Residual exposure:** the underlying `tyler-smith/go-bip39` API only accepts
> `string`, so the library makes a single short-lived `string` copy for
> validation and seed derivation. It is GC-bounded, and every durable copy of
> the mnemonic and seed is sealed in a memguard enclave.

---

## Supported networks

| Symbol | Network | Curve | Path |
|---|---|---|---|
| BTC | Bitcoin (native SegWit) | secp256k1 | `m/84'/0'/0'/0/0` |
| LTC | Litecoin (native SegWit) | secp256k1 | `m/84'/2'/0'/0/0` |
| DOGE | Dogecoin | secp256k1 | `m/44'/3'/0'/0/0` |
| BCH | Bitcoin Cash (CashAddr) | secp256k1 | `m/44'/145'/0'/0/0` |
| DASH | Dash | secp256k1 | `m/44'/5'/0'/0/0` |
| ZEC | Zcash (transparent) | secp256k1 | `m/44'/133'/0'/0/0` |
| ETH | Ethereum (EIP-55) | secp256k1 | `m/44'/60'/0'/0/0` |
| BNB · MATIC · AVAX · ARB · OP · FTM · BASE · CRO · GNO · CELO | EVM chains | secp256k1 | `m/44'/60'/0'/0/0` |
| TRX | Tron | secp256k1 | `m/44'/195'/0'/0/0` |
| XRP | XRP Ledger | secp256k1 | `m/44'/144'/0'/0/0` |
| ATOM · OSMO · JUNO · TIA | Cosmos SDK chains | secp256k1 | `m/44'/118'/0'/0/0` |
| SOL | Solana | ed25519 | `m/44'/501'/0'` |
| XLM | Stellar | ed25519 | `m/44'/148'/0'` |
| DOT | Polkadot (SS58) | ed25519 | `m/44'/354'/0'/0'/0'` |
| KSM | Kusama (SS58) | ed25519 | `m/44'/434'/0'/0'/0'` |
| NEAR | NEAR | ed25519 | `m/44'/397'/0'` |
| ALGO | Algorand | ed25519 | `m/44'/283'/0'/0'/0'` |
| SUI | Sui | ed25519 | `m/44'/784'/0'/0'/0'` |
| APTOS | Aptos | ed25519 | `m/44'/637'/0'/0'/0'` |
| XTZ | Tezos (tz1) | ed25519 | `m/44'/1729'/0'/0'` |
| NEO | NEO (legacy) | nist256p1 | `m/44'/888'/0'/0/0` |

All paths derive receive address index 0 and an empty BIP-39 passphrase
(Trust Wallet's default).

> **Note on Polkadot/Kusama:** Trust Wallet derives these on **ed25519** via
> SLIP-0010. The native Polkadot ecosystem (e.g. Polkadot.js) defaults to
> **sr25519** with a different scheme, so addresses there will differ. This
> library matches **Trust Wallet**, which is the stated compatibility target.

### Roadmap

Cardano (`ed25519ExtendedCardano` / CIP-1852) and Waves (`curve25519`) use
fundamentally different derivation schemes and are intentionally deferred rather
than shipped half-verified — a wrong address means lost funds. Contributions
with test vectors welcome.

---

## Verification

"Trust Wallet–compatible" is proven, not asserted. The test suite layers three
independent sources of truth:

1. **Encoders** (`encoders_test.go`) — every address encoder is run against the
   exact addresses Trust Wallet Core's `CoinAddressDerivationTests` produces for
   a fixed key, isolating address-format correctness.
2. **Derivation** (`slip10_test.go`) — ed25519 and nist256p1 derivation are
   checked against the official **SLIP-0010** specification test vectors
   (including non-hardened P-256 derivation).
3. **End-to-end** (`hdwallet_test.go`) — full mnemonic→seed→derive→encode
   against the BIP-84 spec (BTC), the canonical ETH vector, and Trust Wallet
   Core's `HDWalletTests` mnemonic vectors (NEAR ed25519, Cosmos secp256k1).

```bash
go test -race -cover ./...
```

> **Always verify before sending funds.** Import your mnemonic into Trust Wallet
> and confirm the address for any chain you intend to use with real value.

---

## API

| Function / method | Purpose |
|---|---|
| `NewHDWallet() (*HDWallet, error)` | New wallet with a fresh 12-word mnemonic. |
| `FromMnemonic(string) (*HDWallet, error)` | Import from a mnemonic string (least secure). |
| `FromMnemonicBytes([]byte) (*HDWallet, error)` | Import from a byte slice (wiped on use). |
| `FromMnemonicBuffer(*memguard.LockedBuffer) (*HDWallet, error)` | Import from a memguard buffer (most secure; zero-copy). |
| `GenerateMnemonic() (string, error)` | Generate a mnemonic without building a wallet. |
| `(*HDWallet) Address(symbol Symbol) (string, error)` | First receive address for one network. |
| `(*HDWallet) AddressIndex(symbol Symbol, index uint32) (string, error)` | Nth address/account for one network. |
| `(*HDWallet) AllAddresses() (map[Symbol]string, error)` | Addresses for all networks. |
| `(*HDWallet) Sign(symbol Symbol, data []byte) (*Signature, error)` | Sign a digest (ECDSA) / message (ed25519) at index 0. |
| `(*HDWallet) SignIndex(symbol Symbol, index uint32, data []byte) (*Signature, error)` | Sign with the key at a given index. |
| `(*HDWallet) PublicKey(symbol Symbol) ([]byte, error)` | Public key at index 0. |
| `(*HDWallet) PublicKeyIndex(symbol Symbol, index uint32) ([]byte, error)` | Public key at a given index. |
| `Verify(curve Curve, pub, data []byte, sig *Signature) bool` | Verify a signature. |
| `(*HDWallet) WithMnemonic(func([]byte) error) error` | Use the mnemonic, auto-wiped. |
| `(*HDWallet) Mnemonic() (*memguard.LockedBuffer, error)` | Mnemonic buffer (caller `Destroy`s). |
| `(*HDWallet) Destroy()` | Wipe the wallet's secrets. |
| `SupportedCoins() []Symbol` | Sorted list of symbols. |
| `CoinInfo(symbol Symbol) (Coin, bool)` | Registry entry for a symbol. |

`Symbol` is a typed string enum; the package exports a constant for every
supported network (`hdwallet.BTC`, `hdwallet.ETH`, `hdwallet.SOL`, …). Pass these
constants instead of raw strings for compile-time safety. `Symbol` also has
`String() string` and `IsValid() bool` helpers.

---

## Adding a network

Append one row to the registry in `registry.go`:

```go
"FOO": {"Foochain", "FOO", Secp256k1, "m/44'/9999'/0'/0/0", encodeFoo},
```

Provide an `Encode func(pub []byte) (string, error)` for the address format
(the compressed key for secp256k1/nist256p1, the raw 32-byte key for ed25519),
and add a test vector. EVM chains can reuse `encodeETH`; Cosmos chains can reuse
`cosmosEncoder("<hrp>")`.

---

## Demo CLI

```bash
go run ./cmd/hdwallet                       # fresh wallet, prints addresses
go run ./cmd/hdwallet -mnemonic "abandon ... about"
go run ./cmd/hdwallet -show-mnemonic        # demo only; printing defeats isolation
```

---

## Security

- Secrets are stored in `memguard` enclaves (encrypted at rest in RAM, pages
  locked against swap, guarded with canaries, auto-wiped).
- Private keys derived during an operation are zeroed immediately after the
  address is computed.
- Call `w.Destroy()` per wallet and `defer memguard.Purge()` at program exit.
- **Caveat:** `FromMnemonic(string)` and `GenerateMnemonic() string` involve a Go
  `string` that cannot be wiped (a limitation of the BIP-39 API). Prefer
  `FromMnemonicBytes` and `WithMnemonic` for the strongest guarantees.

Found a vulnerability? Please open a private security advisory rather than a
public issue.

---

## Publishing & releasing

Releases are **fully automated**. Every push to `main` that passes the test and
security gates is tagged and published by CI (`.github/workflows/ci.yml`):

1. CI runs build, tests (`-race`), `govulncheck`, and `gosec`.
2. A new semver tag is created and pushed.
3. The Go module proxy is warmed (`proxy.golang.org`), which publishes the
   version and triggers [pkg.go.dev](https://pkg.go.dev/github.com/ranjbar-dev/hd-wallet) indexing.
4. A GitHub Release with auto-generated notes is created.

Control the version bump from the **commit message**:

| Marker in commit message | Result |
|---|---|
| `[major]` | `x+1.0.0` |
| `[minor]` | `x.y+1.0` |
| _(none)_ | `x.y.z+1` (patch) |
| `[skip release]` | no release for that push |

The first release is `v0.1.0`. Requires the repo to be **public** and the
default `GITHUB_TOKEN` to have write access (Settings → Actions → General →
Workflow permissions → "Read and write permissions"). If tag protection rules
block the bot, supply a Personal Access Token instead.

To release manually instead, just push a tag (`git tag v1.2.3 && git push origin v1.2.3`).

---

## License

[MIT](LICENSE) © Amir Ranjbar

## Disclaimer

This software is provided "as is", without warranty of any kind. You are
responsible for safeguarding your own keys and funds. Always test with small
amounts first and verify addresses against a reference wallet.
