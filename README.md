# hd-wallet

[![Go Reference](https://pkg.go.dev/badge/github.com/amirranjbar/hd-wallet.svg)](https://pkg.go.dev/github.com/amirranjbar/hd-wallet)
[![Go Report Card](https://goreportcard.com/badge/github.com/amirranjbar/hd-wallet)](https://goreportcard.com/report/github.com/amirranjbar/hd-wallet)
[![CI](https://github.com/amirranjbar/hd-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/amirranjbar/hd-wallet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **Trust Wallet–compatible**, security-focused **hierarchical-deterministic (HD) wallet** library for Go.

Generate a BIP-39 mnemonic (or import one) and derive receive addresses for **33 networks across 3 elliptic-curve families** using the same derivation paths and address formats Trust Wallet uses by default — so seeds are interchangeable between the two.

Sensitive material (the mnemonic and derived seed) is **never** held as a plain Go string or a long-lived byte slice. It lives in encrypted, page-locked [memguard](https://github.com/awnumar/memguard) enclaves and is decrypted only for the microseconds of a single derivation.

---

## Why this library

- 🔐 **Secrets isolated in RAM.** Encrypted enclaves, memory locked against swap (`mlock`/`VirtualLock`), guard pages, and automatic wiping. No mnemonic-as-`string`, no exported secret fields.
- ✅ **Provably Trust Wallet–compatible.** Every address encoder is tested against Trust Wallet Core's own vectors; key derivation is tested against the SLIP-0010 specification. See [Verification](#verification).
- 🌐 **33 networks, 3 curves.** secp256k1 (Bitcoin-style, EVM, Cosmos, XRP, Tron), ed25519 (Solana, Stellar, Polkadot, …), and NIST P-256 (NEO).
- 🧩 **Extensible.** Add a network with a single registry row.
- 📦 **Small dependency surface.** btcd (secp256k1/bech32/base58), go-bip39, x/crypto, and memguard.

---

## Install

```bash
go get github.com/amirranjbar/hd-wallet
```

```go
import hdwallet "github.com/amirranjbar/hd-wallet"
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
	hdwallet "github.com/amirranjbar/hd-wallet"
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

	btc, _ := w.Address("BTC")
	eth, _ := w.Address("ETH")
	sol, _ := w.Address("SOL")
	fmt.Println(btc, eth, sol)

	all, _ := w.AllAddresses() // map[symbol]address for every network
	fmt.Println(all["ATOM"])
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
| `FromMnemonic(string) (*HDWallet, error)` | Import from a mnemonic string. |
| `FromMnemonicBytes([]byte) (*HDWallet, error)` | Import from a byte slice (wiped on use). |
| `GenerateMnemonic() (string, error)` | Generate a mnemonic without building a wallet. |
| `(*HDWallet) Address(symbol string) (string, error)` | Address for one network. |
| `(*HDWallet) AllAddresses() (map[string]string, error)` | Addresses for all networks. |
| `(*HDWallet) WithMnemonic(func([]byte) error) error` | Use the mnemonic, auto-wiped. |
| `(*HDWallet) Mnemonic() (*memguard.LockedBuffer, error)` | Mnemonic buffer (caller `Destroy`s). |
| `(*HDWallet) Destroy()` | Wipe the wallet's secrets. |
| `SupportedCoins() []string` | Sorted list of symbols. |
| `CoinInfo(symbol string) (Coin, bool)` | Registry entry for a symbol. |

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

This repo is `go get`-ready. To cut a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

pkg.go.dev indexes the module automatically once any client fetches the tag.
See the project notes for the full release checklist.

---

## License

[MIT](LICENSE) © Amir Ranjbar

## Disclaimer

This software is provided "as is", without warranty of any kind. You are
responsible for safeguarding your own keys and funds. Always test with small
amounts first and verify addresses against a reference wallet.
