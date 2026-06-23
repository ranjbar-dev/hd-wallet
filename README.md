# hd-wallet

[![Go Reference](https://pkg.go.dev/badge/github.com/ranjbar-dev/hd-wallet.svg)](https://pkg.go.dev/github.com/ranjbar-dev/hd-wallet)
[![Go Report Card](https://goreportcard.com/badge/github.com/ranjbar-dev/hd-wallet)](https://goreportcard.com/report/github.com/ranjbar-dev/hd-wallet)
[![CI](https://github.com/ranjbar-dev/hd-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/ranjbar-dev/hd-wallet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **Trust Wallet–compatible**, security-focused **hierarchical-deterministic (HD) wallet** library for Go.

Generate a BIP-39 mnemonic (or import one) and derive receive addresses for **129 networks** using the same derivation paths and address formats Trust Wallet uses by default — so seeds are interchangeable between the two. Beyond derivation it adds **EVM tooling** (RLP, ABI, EIP-191, EIP-712), **protobuf transaction signing** for core families (EVM, Tron, XRP, Cosmos, Solana — no broadcast), **secure private-key import/export**, and **address validation/parsing**.

Sensitive material (the mnemonic and derived seed) is **never** held as a plain Go string or a long-lived byte slice. It lives in encrypted, page-locked [memguard](https://github.com/awnumar/memguard) enclaves and is decrypted only for the microseconds of a single derivation.

---

## Why this library

- 🔐 **Secrets isolated in RAM.** Encrypted enclaves, memory locked against swap (`mlock`/`VirtualLock`), guard pages, and automatic wiping. No mnemonic-as-`string`, no exported secret fields. Private-key import/export goes through the same memguard pattern — there is still no raw key getter.
- ✅ **Provably Trust Wallet–compatible.** Every address encoder is tested against Trust Wallet Core's own vectors; key derivation is tested against the SLIP-0010 specification; transaction signers reproduce Trust Wallet Core's `AnySigner` vectors byte-for-byte. See [Verification](#verification).
- 🌐 **129 networks across 5 curves in use.** secp256k1 (Bitcoin-style, 50+ EVM chains, ~30 Cosmos chains, XRP, Tron), ed25519 (Solana, Stellar, …), NIST P-256 (NEO), ed25519-blake2b (Nano), and curve25519 (Waves). 8 curve schemes are implemented in total.
- ✍️ **Signing at every level.** Raw ECDSA/EdDSA signing for every network, EVM message signing (EIP-191/EIP-712), and full **protobuf transaction signing** (EVM, Tron, XRP, Cosmos, Solana) that returns broadcast-ready raw transactions. Derived keys are wiped after each use.
- 🧩 **Extensible.** Add a network with a single registry row.
- 📦 **Focused dependency surface.** btcd (secp256k1/bech32/base58), go-bip39, x/crypto, memguard, protobuf, and curve libraries (edwards25519, schnorrkel, gnark-crypto) for the additional schemes.

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

### Bitcoin address types

`Address`/`AddressIndex` return the chain default (native SegWit, BIP-84 for
BTC/LTC). `BitcoinAddress` derives any of the four standard formats at its
standard BIP path (arguments are `account, change, index`):

```go
legacy,  _ := w.BitcoinAddress(hdwallet.BTC, hdwallet.P2PKH, 0, 0, 0)      // 1…   (BIP-44)
nested,  _ := w.BitcoinAddress(hdwallet.BTC, hdwallet.P2SHP2WPKH, 0, 0, 0) // 3…   (BIP-49)
native,  _ := w.BitcoinAddress(hdwallet.BTC, hdwallet.P2WPKH, 0, 0, 0)     // bc1q… (BIP-84)
taproot, _ := w.BitcoinAddress(hdwallet.BTC, hdwallet.P2TR, 0, 0, 0)       // bc1p… (BIP-86)
```

Available for BTC and LTC; verified against the official BIP-44/49/84/86 test
vectors. `ValidateAddress`/`ParseAddress` accept all four formats.

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

> This is the low-level primitive. For Ethereum message signing and full
> transaction building, use the higher-level APIs below.

### Transaction signing (protobuf, no broadcast)

`SignTransaction` builds, serializes, and signs a **broadcast-ready raw
transaction** from a protobuf `SigningInput`, mirroring Trust Wallet Core's
`AnySigner`. It returns the signed bytes/hex — it does **not** broadcast.

> **Coverage note:** address derivation/validation spans **all 129 networks**,
> but transaction building covers only the families in the table below. For any
> other chain you can derive and validate addresses but must assemble and sign
> the transaction yourself (use the raw `Sign`/`SignIndex` primitive on the
> chain's sighash). You also supply chain state — fees/gas, nonce/sequence,
> recent blockhash, UTXOs — in the `SigningInput`; this library does no network
> I/O.

Verified against authoritative signing vectors for:

| Family | Coverage |
|---|---|
| **EVM** | legacy (EIP-155) + EIP-2930 (access list) + EIP-1559, native + ERC-20 + arbitrary contract call + contract creation (deploy) + EIP-2930/1559 access lists. Select the format with `tx_mode` (exported `hdwallet.EthTxModeLegacy`/`EthTxModeEIP2930`/`EthTxModeEIP1559`). All registered EVM chains. |
| **Tron** | TRX transfer + TRC-20 token transfer (TriggerSmartContract) |
| **XRP** | Payment |
| **Cosmos** | bank `MsgSend`, staking `MsgDelegate`/`MsgUndelegate`, `MsgWithdrawDelegatorReward`, multi-message (protobuf direct mode). All standard secp256k1 Cosmos chains, plus **EVMOS** (ethermint eth_secp256k1: keccak256 SignDoc + ethermint pubkey type URL). Other ethermint chains (INJ/CANTO/ZETA) stay roadmap — Injective uses a different pubkey type URL, so each needs its own vector. |
| **Solana** | system transfer + SPL token transfer (TransferChecked) |
| **Bitcoin** | BTC/LTC SegWit: spends **P2WPKH** (BIP-143) and **Taproot key-path** (BIP-341 / BIP-340 Schnorr) inputs; outputs to any address type; deterministic coin-selection + change. Verified against `btcd` (P2WPKH byte-identical; Taproot sighash + BIP-340 verify) and the BIP-143 spec vector. |

```go
import ethpb "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"

out, _ := w.SignTransaction(hdwallet.ETH, 0, &ethpb.SigningInput{ /* … */ })
```

> Bitcoin spending currently covers P2WPKH and Taproot key-path inputs; legacy
> P2PKH and nested P2SH-P2WPKH input spending remain on the roadmap.

### Ethereum message signing (EIP-191 / EIP-712)

```go
sig, _ := w.SignMessage(hdwallet.ETH, 0, []byte("Hello, world!"))   // EIP-191 personal_sign
addr, _ := hdwallet.RecoverEthereumAddress([]byte("Hello, world!"), sig)

sig2, _ := w.SignTypedData(hdwallet.ETH, 0, typedDataJSON)           // EIP-712
```

Plus standalone EVM tooling: `EncodeRLP`/`DecodeRLP`, `ABIEncode`/`ABIDecode`,
`ABIFunctionSelector`, `EthereumPersonalMessageHash`, `EIP712Hash`.

### Bitcoin & Solana message signing

Non-EVM message signing, each pinned byte-for-byte to its Trust Wallet Core
`MessageSigner` vector:

```go
// Bitcoin "signmessage" standard → base64; verifies against a legacy P2PKH address.
sig, _  := w.SignBitcoinMessage(hdwallet.BTC, 0, []byte("test signature"))
ok      := hdwallet.VerifyBitcoinMessage("19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X", []byte("test signature"), sig)

// Solana off-chain message (raw ed25519) → base58.
ssig, _ := w.SignSolanaMessage(hdwallet.SOL, 0, []byte("Hello world"))
sok     := hdwallet.VerifySolanaMessage(addr, []byte("Hello world"), ssig)
```

> Cosmos ADR-36 arbitrary-message signing is on the roadmap (no authoritative
> Trust Wallet Core vector to verify against yet).

### Address validation & parsing

```go
ok  := hdwallet.IsValidAddress(hdwallet.ETH, "0x…")     // bool
err := hdwallet.ValidateAddress(hdwallet.BTC, "bc1q…")  // descriptive error
payload, _ := hdwallet.ParseAddress(hdwallet.ETH, "0x…")
addr, _ := hdwallet.AddressFromPublicKey(hdwallet.ETH, pubKey) // external key → address
```

### Importing / exporting a raw private key (securely)

A wallet can be built from a single private key, and the leaf key can be exported
— always through the same memguard pattern as the mnemonic (no raw `[]byte`
getter; the key is wiped when your callback returns):

```go
w, _ := hdwallet.FromPrivateKeyBytes(keyBytes, hdwallet.Secp256k1) // wipes keyBytes
// or FromPrivateKeyBuffer(*memguard.LockedBuffer, curve) — zero-copy, strongest

_ = w.WithPrivateKey(hdwallet.ETH, 0, func(priv []byte) error {     // wiped on return
    // use priv; do not let it escape
    return nil
})
buf, _ := w.PrivateKey(hdwallet.ETH, 0)                             // caller Destroys
defer buf.Destroy()
```

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

**129 networks** across 5 curves in use. `SupportedCoins()` returns the live,
authoritative list; `CoinInfo(symbol)` gives each coin's curve and path. Every
chain below is verified against a Trust Wallet Core address vector.

#### secp256k1 (110)

| Group | Symbols | Path |
|---|---|---|
| Bitcoin-family / UTXO | BTC, LTC, DOGE, BCH, DASH, ZEC, BTG, DGB, GRS, SYS, VIA, QTUM, RVN, KMD, FIRO, MONA, XVG, PIVX, NEBL, STRAX, ZEN, BCD, XEC, FLUX | per-chain (e.g. `m/84'/0'/0'/0/0`) |
| Ethereum / EVM (same key & address) | ETH, BNB, MATIC, AVAX, ARB, OP, FTM, BASE, CRO, GNO, CELO, ETC, RBTC, KAIA, AURORA, GLMR, MOVR, BOBA, METIS, OPBNB, POLZKEVM, MANTA, ZKSYNC, LINEA, SCROLL, MANTLE, BLAST, RONIN, HECO, OKT, KCS, WAN, POA, CLO, GO, TT, VET, IOTX, THETA, NEON, MERLIN, LIGHT, SONIC, ZENEON, ONE, EVMOS, INJ, CANTO, ZETAEVM | `m/44'/60'/0'/0/0` |
| Tron | TRX | `m/44'/195'/0'/0/0` |
| XRP Ledger | XRP | `m/44'/144'/0'/0/0` |
| Cosmos SDK (bech32, per-chain HRP) | ATOM, OSMO, JUNO, TIA, LUNA, KAVA, SCRT, BAND, RUNE, STARS, AXL, STRD, BLD, CRE, KUJI, CMDX, NTRN, SOMM, FET, MARS, UMEE, COREUM, QSR, XPRT, AKT, NOBLE, SEI, DYDX, BLZ, CRYPTOORG, ZETA | `m/44'/118'/0'/0/0` (some differ) |
| EOS-family / Filecoin | EOS, WAX, FIO, FIL | per-chain |

#### ed25519 (15)

| Symbol | Network | Path |
|---|---|---|
| SOL | Solana | `m/44'/501'/0'` |
| XLM | Stellar | `m/44'/148'/0'` |
| DOT · KSM | Polkadot · Kusama (SS58) | `m/44'/354'/0'/0'/0'` · `m/44'/434'/0'/0'/0'` |
| NEAR · XTZ · SUI · APTOS · ALGO | NEAR · Tezos · Sui · Aptos · Algorand | per-chain |
| EGLD · HBAR · IOST · ROSE · KIN · AE | MultiversX · Hedera · IOST · Oasis · Kin · Aeternity | per-chain |

#### nist256p1 (2) · ed25519-blake2b (1) · curve25519 (1)

| Symbol | Network | Curve | Path |
|---|---|---|---|
| NEO | NEO (legacy) | nist256p1 | `m/44'/888'/0'/0/0` |
| ONT | Ontology | nist256p1 | `m/44'/1024'/0'/0/0` |
| XNO | Nano | ed25519-blake2b | `m/44'/165'/0'` |
| WAVES | Waves | curve25519 | `m/44'/5741564'/0'/0'/0'` |

All paths derive receive address index 0 and an empty BIP-39 passphrase
(Trust Wallet's default).

> **Note on Polkadot/Kusama:** Trust Wallet derives these on **ed25519** via
> SLIP-0010. The native Polkadot ecosystem (e.g. Polkadot.js) defaults to
> **sr25519** with a different scheme, so addresses there will differ. This
> library matches **Trust Wallet**, which is the stated compatibility target.

### Roadmap (deferred — implemented but not yet vector-matched, or scheme not wired)

Some curve schemes are implemented but **not yet wired to a registered chain**,
because a fund-critical address must match an authoritative vector first:

- **Cardano** (`ed25519-extended` / CIP-1852) — derivation needs BIP-39 *entropy*
  (not the seed); entropy is not yet plumbed into the wallet.
- **StarkNet** (`starkex`) — the EIP-2645 seed→key grind lacks an authoritative
  Trust Wallet Core vector (sign/verify are vector-verified).
- **sr25519** (native Polkadot/Kusama) — implemented; sign/verify round-trip only.
- **Zilliqa** (Schnorr), **TON**, **ICON**, and a handful of long-tail chains whose
  address scheme isn't reproduced against a vector yet (see `registry.go`).

Deferred signing features: Bitcoin transaction building now spends **P2WPKH** and
**Taproot key-path** inputs (BTC/LTC); still deferred are **legacy P2PKH** and
**nested P2SH-P2WPKH** input spending (pre-BIP-143 / wrapped-witness sighash). The
**ethermint-keyed Cosmos** chains beyond EVMOS (INJ/CANTO/ZETA — each needs its
own vector since the pubkey type URL enters the signed bytes) — see
`tx_families.go`; and **Cosmos ADR-36** message signing — see
`message_cosmos_test.go`.

Contributions with test vectors welcome.

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
| `NewHDWalletWithWordCount(words int) (*HDWallet, error)` | New wallet with a 12/15/18/21/24-word mnemonic. Also `NewHDWalletWithEntropy(bits)`. |
| `FromMnemonic(string) (*HDWallet, error)` | Import from a mnemonic string (least secure). |
| `FromMnemonicBytes([]byte) (*HDWallet, error)` | Import from a byte slice (wiped on use). |
| `FromMnemonicBuffer(*memguard.LockedBuffer) (*HDWallet, error)` | Import from a memguard buffer (most secure; zero-copy). |
| `FromMnemonicWithPassphrase([]byte, []byte) (*HDWallet, error)` | Import with a BIP-39 passphrase (the "25th word"). |
| `FromMnemonicBufferWithPassphrase(buf, pass *memguard.LockedBuffer) (*HDWallet, error)` | Passphrase import, both secrets in memguard buffers. |
| `GenerateMnemonic() (string, error)` | Generate a mnemonic without building a wallet. Also `GenerateMnemonicWithWordCount(words)`. |
| `(*HDWallet) Address(symbol Symbol) (string, error)` | First receive address for one network. |
| `(*HDWallet) AddressIndex(symbol Symbol, index uint32) (string, error)` | Nth address/account for one network. |
| `(*HDWallet) AddressPath(symbol Symbol, path string) (string, error)` | Address at an arbitrary absolute BIP-32 path. Also `SignPath`/`PublicKeyPath`/`WithPrivateKeyPath`/`PrivateKeyPath`. |
| `(*HDWallet) AddressAt(symbol Symbol, account, change, index uint32) (string, error)` | Address by BIP-44 account/change/index. Also `SignAt`/`PublicKeyAt`. |
| `(*HDWallet) AllAddresses() (map[Symbol]string, error)` | Addresses for all networks. Also `AllAddressesAt(index)` for any index. |
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

**Private-key import / export** (same memguard discipline as the mnemonic):

| Function / method | Purpose |
|---|---|
| `FromPrivateKeyBytes([]byte, Curve) (*HDWallet, error)` | Key-only wallet from a byte slice (wiped on use). Any 32-byte-scalar curve. |
| `FromPrivateKeyBuffer(*memguard.LockedBuffer, Curve) (*HDWallet, error)` | Key-only wallet from a memguard buffer (zero-copy). |
| `(*HDWallet) WithPrivateKey(symbol, index, func([]byte) error) error` | Use the leaf private key, auto-wiped. |
| `(*HDWallet) PrivateKey(symbol, index) (*memguard.LockedBuffer, error)` | Leaf key buffer (caller `Destroy`s). |
| `FromWIF([]byte) (*HDWallet, error)` · `(*HDWallet) WithWIF` / `WIF` | Import/export a Bitcoin WIF (secp256k1). |
| `(*HDWallet) AccountXPub(symbol, account) (string, error)` · `WithAccountXPrv` | Export account-level BIP-32 extended keys (secp256k1). |
| `WatchOnlyFromXPub(xpub string, symbol) (*WatchWallet, error)` | Watch-only address derivation from an xpub — no seed. |

**Transaction & Ethereum message signing:**

| Function / method | Purpose |
|---|---|
| `(*HDWallet) SignTransaction(symbol, index, proto.Message) (proto.Message, error)` | Build+sign a raw tx (EVM/Tron/XRP/Cosmos/Solana; no broadcast). |
| `(*HDWallet) SignMessage(symbol, index, []byte) ([]byte, error)` | EIP-191 `personal_sign` → 65-byte r‖s‖v. |
| `(*HDWallet) SignTypedData(symbol, index, []byte) ([]byte, error)` | EIP-712 typed-data signature. |
| `(*HDWallet) SignBitcoinMessage(symbol, index, []byte) (string, error)` | Bitcoin `signmessage` → base64. With `VerifyBitcoinMessage`. |
| `(*HDWallet) SignSolanaMessage(symbol, index, []byte) (string, error)` | Solana off-chain message → base58. With `VerifySolanaMessage`. |
| `RecoverEthereumAddress([]byte, []byte) (string, error)` · `VerifyEthereumMessage` / `…TypedData` | Recover/verify EIP-191/712 signers. |
| `EncodeRLP`/`DecodeRLP` · `ABIEncode`/`ABIDecode` · `ABIFunctionSelector` · `EIP712Hash` | Standalone EVM encoding utilities. |

**Address validation / parsing (`AnyAddress`-style):**

| Function | Purpose |
|---|---|
| `IsValidAddress(symbol, addr) bool` · `ValidateAddress(symbol, addr) error` | Validate an address for a network. |
| `ParseAddress(symbol, addr) ([]byte, error)` | Decode an address to its payload. |
| `AddressFromPublicKey(symbol, pub) (string, error)` | Derive an address from an external public key. |

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
