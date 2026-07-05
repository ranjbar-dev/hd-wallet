# hd-wallet

[![Go Reference](https://pkg.go.dev/badge/github.com/ranjbar-dev/hd-wallet.svg)](https://pkg.go.dev/github.com/ranjbar-dev/hd-wallet)
[![Go Report Card](https://goreportcard.com/badge/github.com/ranjbar-dev/hd-wallet)](https://goreportcard.com/report/github.com/ranjbar-dev/hd-wallet)
[![CI](https://github.com/ranjbar-dev/hd-wallet/actions/workflows/ci.yml/badge.svg)](https://github.com/ranjbar-dev/hd-wallet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **Trust Wallet–compatible**, security-focused **hierarchical-deterministic (HD) wallet** library for Go.

Generate a BIP-39 mnemonic (or import one) and derive receive addresses for **99 networks** using the same derivation paths and address formats Trust Wallet uses by default — so seeds are interchangeable between the two. Beyond derivation it adds **EVM tooling** (RLP, ABI, EIP-191, EIP-712), **protobuf transaction signing** for many families (EVM, Tron, XRP, Cosmos, Solana, Bitcoin/UTXO, Stellar, Algorand, Aptos, TON — no broadcast), **secure private-key import/export**, and **address validation/parsing**.

> **36 chains are explicitly not supported** by this library (no address derivation, no validation, nothing). See [Unsupported chains](#unsupported-chains).

> 🤖 **Using an LLM / AI coding assistant?** Point it at [`llms.txt`](llms.txt) — a self-contained context file summarizing the project scope, full API surface, workflows, and troubleshooting notes.

Sensitive material (the mnemonic and derived seed) is **never** held as a plain Go string or a long-lived byte slice. It lives in encrypted, page-locked [memguard](https://github.com/awnumar/memguard) enclaves and is decrypted only for the microseconds of a single derivation.

---

## Why this library

- 🔐 **Secrets isolated in RAM.** Encrypted enclaves, memory locked against swap (`mlock`/`VirtualLock`), guard pages, and automatic wiping. No mnemonic-as-`string`, no exported secret fields. Private-key import/export goes through the same memguard pattern — there is still no raw key getter.
- ✅ **Provably Trust Wallet–compatible.** Every address encoder is tested against Trust Wallet Core's own vectors; key derivation is tested against the SLIP-0010 specification; transaction signers reproduce Trust Wallet Core's `AnySigner` vectors byte-for-byte. See [Verification](#verification).
- 🌐 **99 networks across 2 curves.** secp256k1 (Bitcoin-style, 50+ EVM chains, ~30 Cosmos chains, XRP, Tron) and ed25519 (Solana, Stellar, Algorand, Aptos, TON).
- ✍️ **Signing at every level.** Raw ECDSA/EdDSA signing for every network, EVM message signing (EIP-191/EIP-712), and full **protobuf transaction signing** (EVM, Tron, XRP, Cosmos, Solana, Bitcoin/UTXO, Stellar, Algorand, Aptos, TON) that returns broadcast-ready raw transactions. Derived keys are wiped after each use.
- 🧩 **Extensible.** Add a network with a single registry row.
- 📦 **Focused dependency surface.** btcd (secp256k1/bech32/base58), go-bip39, x/crypto, memguard, protobuf.

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

	// Chains are a typed enum (hdwallet.Chain) — use the exported constants
	// for compile-time checking and autocomplete.
	btc, _ := w.Address(hdwallet.BTC)
	eth, _ := w.Address(hdwallet.ETH)
	sol, _ := w.Address(hdwallet.SOL)
	fmt.Println(btc, eth, sol)

	all, _ := w.AllAddresses() // map[hdwallet.Chain]string for every network
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
	// unknown chain
}
```

### Signing (raw)

`Sign`/`SignIndex` produce a signature with the derived private key for any
supported chain. The key is wiped immediately after signing and **never leaves
the package** — there is no way to extract a private key.

There is one inherent rule, driven by the cryptography:

- **The ECDSA chain** (secp256k1 — BTC, ETH, ATOM, …): pass the **32-byte
  digest** your chain signs. Pre-hash the message yourself with the chain's
  hash (keccak256 for Ethereum/Tron, double-SHA256 for Bitcoin, SHA-256 for
  Cosmos, …).
- **ed25519 chains** (SOL, XLM, ALGO, APTOS): pass the **message**; the EdDSA
  scheme hashes internally.

```go
digest := sha256.Sum256(txBytes)         // chain-specific pre-hash for ECDSA
sig, _ := w.Sign(hdwallet.BTC, digest[:])

sig.Bytes()        // 64-byte R||S (ECDSA) or 64-byte ed25519 signature  → Cosmos, Solana
sig.Recoverable()  // 65-byte R||S||V (secp256k1 only)                   → Ethereum/EVM, Tron
sig.DER()          // ASN.1 DER (ECDSA)                                  → Bitcoin family

pub, _ := w.PublicKey(hdwallet.BTC)
ok := hdwallet.Verify(hdwallet.Secp256k1, pub, digest[:], sig)
```

`SignIndex(chain, index, data)` and `PublicKeyIndex(chain, index)` work with
non-zero address indices. ECDSA inputs that are not 32 bytes return
`ErrInvalidDigest`.

> This is the low-level primitive. For Ethereum message signing and full
> transaction building, use the higher-level APIs below.

### Transaction signing (protobuf, no broadcast)

`SignTransaction` builds, serializes, and signs a **broadcast-ready raw
transaction** from a protobuf `SigningInput`, mirroring Trust Wallet Core's
`AnySigner`. It returns the signed bytes/hex — it does **not** broadcast.

> **Coverage note:** address derivation/validation spans **all 99 networks**,
> but transaction building covers only the families in the table below. For any
> other chain you can derive and validate addresses but must assemble and sign
> the transaction yourself (use the raw `Sign`/`SignIndex` primitive on the
> chain's sighash). You also supply chain state — fees/gas, nonce/sequence,
> recent blockhash, UTXOs — in the `SigningInput`; this library does no network
> I/O.

Verified against authoritative signing vectors for:

| Family | Coverage |
|---|---|
| **EVM** | legacy (EIP-155) + EIP-2930 (access list) + EIP-1559 + **EIP-4844** (type-3 blob tx: `max_fee_per_blob_gas` + `blob_versioned_hashes`) + **EIP-7702** (type-4 set-code tx: `authorization_list`), native + ERC-20 + arbitrary contract call + contract creation (deploy). Select the format with `tx_mode` (exported `hdwallet.EthTxModeLegacy`/`EthTxModeEIP2930`/`EthTxModeEIP1559`/`EthTxModeEIP4844`/`EthTxModeEIP7702`). Structured token intents via proto oneofs: **ERC-20 approve** (`ERC20Approve`), **ERC-721 transfer** (`ERC721Transfer`), **ERC-1155 transfer** (`ERC1155Transfer`) — each tested with Legacy + EIP-1559 TWC-vector-pinned tests. **ERC-4337 account abstraction**: UserOperation v0.6 (`EthTxModeUserOp` = 5, `SigningInput.user_operation` field 14) and v0.7 (`EthTxModeUserOpV07` = 6, `SigningInput.user_operation_v0_7` field 15, packed `uint128` `accountGasLimits`/`gasFees`). **Smart-wallet batch intents**: `SCWalletExecute` (single call, field 7) and `SCWalletBatch` (batched calls, field 8) for three wallet types — `SC_SIMPLE_ACCOUNT` (`execute`/`executeBatch(address[],uint256[],bytes[])`), `BIZ_4337` (`executeBatch(address[],bytes[])`), and `BIZ` (`executeBatch(address[],uint256[],bytes[])`). All registered EVM chains. |
| **Tron** | TRX transfer (`TransferContract`) + TRC-10 transfer (`TransferAssetContract`) + TRC-20 transfer + generic `TriggerSmartContract` (arbitrary call with `call_value`/`data`/`call_token_value`/`token_id`) + legacy Stake 1.0 `FreezeBalanceContract`/`UnfreezeBalanceContract` + `UnfreezeAssetContract` + `WithdrawBalanceContract` + `VoteAssetContract`; **raw_json mode** signs a node/DApp-provided pre-built transaction (`raw_data_hex` + txID guard) for wallet-connect flows |
| **XRP** | Payment |
| **Cosmos** | bank `MsgSend`, staking `MsgDelegate`/`MsgUndelegate`, `MsgWithdrawDelegatorReward`, multi-message (protobuf direct mode). All standard secp256k1 Cosmos chains, plus **EVMOS** and **INJ** (ethermint eth_secp256k1: keccak256 SignDoc + chain-specific pubkey type URL — INJ uses an uncompressed key). |
| **Cosmos multisig** | `LegacyAminoMultisig` **m-of-n** bank `MsgSend` (`CosmosMultisigAddress`/`SignCosmosMultisigPartial`/`CombineCosmosMultisig`), `LEGACY_AMINO_JSON` sign docs. Standard secp256k1 Cosmos chains only (Ethermint chains rejected). Pinned byte-for-byte to a cosmos-sdk-generated vector. |
| **Solana** | system transfer + SPL token transfer (`TransferChecked`) + **Token-2022** transfers (`token_program_id` selects the Token-2022 program) + **versioned v0 messages** (`v0_msg`) + associated-token-account flows (`CreateTokenAccount`, `CreateAndTransferToken` — the ATA is always derived internally via `SolanaTokenAccountAddress`, guarding against a mismatched caller-supplied token address) + durable nonces (`nonce_account` prepends `AdvanceNonceAccount` on transfer/token-transfer/create-and-transfer; plus `CreateNonceAccount`/`WithdrawNonceAccount`/`AdvanceNonceAccount` lifecycle) |
| **Bitcoin / UTXO** | BTC/LTC spends across **all four** single-key input types — legacy **P2PKH**, nested **P2SH-P2WPKH** (BIP-49), native **P2WPKH** (BIP-143), and **Taproot key-path** (BIP-341 / BIP-340 Schnorr); outputs to any address type; SIGHASH ALL/NONE/SINGLE/ANYONECANPAY (legacy + BIP-143); multiple recipients, OP_RETURN data output, opt-in **RBF** (BIP-125) + `nLockTime`/`nSequence`; deterministic coin-selection with configurable input selectors, fee-per-vByte, dust handling, send-all/use-all, and change. `PlanBitcoinTx`/`EstimateBitcoinFee` preview the plan without signing. The same engine signs the UTXO altcoins (DOGE/DASH/BCH/ZEC and DGB/SYS/VIA/STRAX/QTUM/RVN/FIRO/MONA/PIVX). Verified against `btcd` and the BIP-143 spec vector. |
| **Bitcoin PSBT** | BIP-174 (v0) **and** BIP-370 (v2) build / sign / finalize / extract over the same inputs (`BuildPSBT`/`SignPSBT`/`FinalizePSBT`/`ExtractPSBTTx` and the `…PSBTV2` variants). The v0 path is byte-identical to the direct signer. |
| **Bitcoin multisig** | P2SH and P2WSH **m-of-n** (BIP-67 sorted keys), partial-sign + finalize via BIP-174 PSBT (`BuildMultisigPSBT`/`SignMultisigPSBT`/`FinalizeMultisigPSBT`/`ExtractMultisigTx`). Pinned to `btcd`. |
| **Bitcoin Ordinals / BRC-20** | Taproot script-path primitives (`BuildInscriptionScript`, control-block builder) plus a two-phase BRC-20 transfer flow (`BuildBRC20Commit` → `SignBRC20Reveal`). Babylon BTC-staking output builders (`tx_bitcoin_babylon.go`) are also included. |
| **Stellar (XLM)** | Payment + `CreateAccount` (`TransactionV0` XDR envelope), plus Memo support (`MEMO_TEXT`/`MEMO_ID`/`MEMO_HASH`). Pinned to the Trust Wallet Core Stellar vector. |
| **Algorand (ALGO)** | Payment (canonical msgpack, `"TX"`-prefixed ed25519) plus ASA transfers (`axfer`) and opt-in (0-amount self-`axfer`). Pinned to the TWC Algorand vector. |
| **Aptos (APTOS)** | Entry-function transfer (BCS + `APTOS::RawTransaction` prehash), plus a structured `Transfer` convenience input synthesized into `aptos_account::transfer`. Pinned to the TWC Aptos vector. |
| **TON** | Native transfer (wallet v4r2), deploy-on-first-send (seqno==0), UTF-8 comments, and TEP-74 jetton transfers. Pinned to the TWC `test_ton_sign_transfer_ordinary` vector. |

```go
import ethpb "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"

out, _ := w.SignTransaction(hdwallet.ETH, 0, &ethpb.SigningInput{ /* … */ })
```

> Bitcoin spending covers all four standard single-key input types (P2PKH,
> P2SH-P2WPKH, P2WPKH, Taproot key-path) plus P2SH/P2WSH multisig via PSBT.

### What you must provide (no network I/O)

`SignTransaction` never calls the network. The caller supplies all chain state
as fields on the `SigningInput` proto before signing. `providers.go` exports
five small interfaces that formalise this contract; `doc.go` contains the full
per-family matrix mapping each `SigningInput` field to its data source:

| Interface | Used for | Chain state |
|---|---|---|
| `NonceProvider` | EVM, XRP, Cosmos | sender nonce / account sequence |
| `UTXOProvider` | Bitcoin-family | unspent outputs (txid, vout, amount, scriptPubKey) |
| `FeeOracle` | EVM, Bitcoin, XRP, Tron | gas price / sat-per-vbyte / drops |
| `RecentBlockhashProvider` | Solana | latest confirmed blockhash |
| `Broadcaster` | all families | post-signing submission sink |

None of these interfaces are called inside the package — they exist purely for
typing and documentation. Wire them as thin wrappers around your node RPC or
indexer client, call each one before building the `SigningInput`, then pass the
results in. See `example_providers_test.go` for a minimal wiring example and
`doc.go` for the field-by-field mapping.

### Ethereum message signing (EIP-191 / EIP-712)

```go
sig, _ := w.SignMessage(hdwallet.ETH, 0, []byte("Hello, world!"))   // EIP-191 personal_sign
addr, _ := hdwallet.RecoverEthereumAddress([]byte("Hello, world!"), sig)

sig2, _ := w.SignTypedData(hdwallet.ETH, 0, typedDataJSON)           // EIP-712
```

Plus standalone EVM tooling: `EncodeRLP`/`DecodeRLP`, `ABIEncode`/`ABIDecode`,
`ABIFunctionSelector`, `EthereumPersonalMessageHash`, `EIP712Hash`.

### JSON-ABI contract-call decoding

Parse a contract's JSON ABI and decode raw calldata into typed named parameters:

```go
abi, err := hdwallet.ParseContractABI(jsonABI)    // parse ABI array → selector-keyed map
name, params, err := hdwallet.DecodeContractCall(abi, calldata) // decode 4-byte selector + args
// name = "approve", params = [{Name:"spender" Value:"0x…"}, {Name:"amount" Value:"1000000"}]
sig := hdwallet.GetFunctionSignature(abi["approve"]) // "approve(address,uint256)"
```

Implemented in `eth_contractcall.go`; no new dependencies (reuses the existing `ABIDecode` primitive).

### Bitcoin, Solana, Cosmos & Tron message signing

Non-EVM message signing, each following the chain's canonical standard:

```go
// Bitcoin "signmessage" standard → base64; verifies against a legacy P2PKH address.
// Pinned byte-for-byte to Trust Wallet Core BitcoinMessageSigner vectors.
sig, _  := w.SignBitcoinMessage(hdwallet.BTC, 0, []byte("test signature"))
ok      := hdwallet.VerifyBitcoinMessage("19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X", []byte("test signature"), sig)

// Solana off-chain message (raw ed25519) → base58.
// Pinned to Trust Wallet Core SolanaMessageSigner vector.
ssig, _ := w.SignSolanaMessage(hdwallet.SOL, 0, []byte("Hello world"))
sok     := hdwallet.VerifySolanaMessage(addr, []byte("Hello world"), ssig)

// Cosmos ADR-36 arbitrary-message signing → base64 (65-byte recoverable secp256k1).
// Follows the CosmJS / Keplr makeADR36AminoSignDoc + serializeSignDoc pipeline;
// ecrecover is used for verification (no separate public key needed).
signer, _ := w.Address(hdwallet.ATOM)
csig, _ := w.SignCosmosADR36(hdwallet.ATOM, 0, signer, []byte("arbitrary cosmos data"))
cok     := hdwallet.VerifyCosmosADR36(signer, []byte("arbitrary cosmos data"), csig)

// Tron TIP-191 message signing → "0x…" hex (65-byte R‖S‖V, V ∈ {27,28}).
// Matches TronWeb trx.signMessageV2; uses keccak256("\x19TRON Signed Message:\n32" ‖ keccak256(msg)).
tsig, _ := w.SignTronMessage(hdwallet.TRX, 0, []byte("Hello World"))
tok     := hdwallet.VerifyTronMessage(tronAddr, []byte("Hello World"), tsig)
```

### Chain-neutral raw message signing

For advanced use cases, `SignRawMessage` / `VerifyRawMessage` route through the
correct curve for any registered chain without a chain-specific envelope:

```go
// secp256k1 chains: pass the 32-byte digest you pre-hashed.
digest := hdwallet.Keccak256([]byte("raw data"))
sig, _ := w.SignRawMessage(hdwallet.ETH, 0, digest)
pub, _ := w.PublicKey(hdwallet.ETH)
ok, _ := hdwallet.VerifyRawMessage(hdwallet.ETH, pub, digest, sig)

// ed25519 chains: pass the raw message; EdDSA hashes internally.
sig, _ = w.SignRawMessage(hdwallet.SOL, 0, []byte("any length"))
```

### Amount formatting

Convert between human-readable amounts and base units using each chain's native
decimals (from the registry) — or explicit decimals for tokens (ERC-20/SPL/TRC-20,
whose decimals are token-specific and supplied by you). All `big.Int` /
decimal-string math, no float:

```go
d, _ := hdwallet.NativeDecimals(hdwallet.ETH)            // 18
s   := hdwallet.FormatAmount(hdwallet.ETH, weiBigInt)    // "1.5"
wei, _ := hdwallet.ParseAmount(hdwallet.ETH, "1.5")      // *big.Int

// Token amounts: pass the token's own decimals.
usdc := hdwallet.FormatUnits(rawBigInt, 6)               // "12.34"
raw, _ := hdwallet.ParseUnits("12.34", 6)
```

> Native decimals come from `CoinInfo(chain).Decimals`; **token** decimals are
> the client's responsibility (token lists are out of scope).

### Chain-constraint helpers

Pre-flight informational sanity floors — not fund-critical signing data, no
network I/O — so a caller can warn before broadcasting a transfer that would
leave an account/UTXO below the network's floor:

```go
min, ok := hdwallet.MinimumBalance(hdwallet.XRP)     // 1_000_000 drops (base reserve)
dust, ok := hdwallet.DustThreshold(hdwallet.BTC)     // 546 sats (standard relay dust)
fee, ok := hdwallet.ActivationCost(hdwallet.TRX)     // 1_100_000 sun (new-account fee)
```

`MinimumBalance` covers XRP/XLM/SOL (ongoing reserve/rent floor); `DustThreshold`
covers every UTXO chain (reuses the signer's own dust constant); `ActivationCost`
covers TRX (a one-off account-creation fee, distinct from an ongoing reserve).
`ok` is `false` for chains with no such constraint.

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

**99 networks** across 2 curves. `SupportedCoins()` returns the live,
authoritative list; `CoinInfo(chain)` gives each coin's curve and path. Every
chain below is verified against a Trust Wallet Core address vector.

#### secp256k1 (94)

| Group | Chains | Path |
|---|---|---|
| Bitcoin-family / UTXO | BTC, LTC, DOGE, BCH, DASH, ZEC, DGB, SYS, VIA, QTUM, RVN, FIRO, MONA, PIVX, STRAX | per-chain (e.g. `m/84'/0'/0'/0/0`) |
| Ethereum / EVM (same key & address) | ETH, BNB, MATIC, AVAX, ARB, OP, FTM, BASE, CRO, GNO, CELO, ETC, RBTC, KAIA, AURORA, GLMR, MOVR, BOBA, METIS, OPBNB, POLZKEVM, MANTA, ZKSYNC, LINEA, SCROLL, MANTLE, BLAST, RONIN, HECO, OKT, KCS, WAN, POA, CLO, GO, TT, VET, IOTX, THETA, NEON, MERLIN, LIGHT, SONIC, ZENEON, EVMOS, INJ, ZETAEVM | `m/44'/60'/0'/0/0` |
| Tron | TRX | `m/44'/195'/0'/0/0` |
| XRP Ledger | XRP | `m/44'/144'/0'/0/0` |
| Cosmos SDK (bech32, per-chain HRP) | ATOM, OSMO, JUNO, TIA, LUNA, KAVA, SCRT, BAND, RUNE, STARS, AXL, STRD, BLD, CRE, KUJI, CMDX, NTRN, SOMM, FET, MARS, UMEE, COREUM, QSR, XPRT, AKT, NOBLE, SEI, DYDX, BLZ, CRYPTOORG | `m/44'/118'/0'/0/0` (some differ) |

#### ed25519 (5)

| Chain | Network | Path |
|---|---|---|
| SOL | Solana | `m/44'/501'/0'` |
| XLM | Stellar | `m/44'/148'/0'` |
| ALGO | Algorand | `m/44'/283'/0'/0'/0'` |
| APTOS | Aptos | `m/44'/637'/0'/0'/0'` |
| TON | TON | `m/44'/607'/0'` |

All paths derive receive address index 0 and an empty BIP-39 passphrase
(Trust Wallet's default).

### Unsupported chains

This library does **not** support the following 36 chains at all — no address
derivation, no validation, no registry rows, nothing:

`ADA` (Cardano), `AE` (Aeternity), `BCD` (Bitcoin Diamond), `BTG` (Bitcoin Gold),
`CANTO` (Canto), `CKB` (Nervos), `DOT` (Polkadot), `EGLD` (MultiversX),
`EOS` (EOS), `FIL` (Filecoin), `FIO` (FIO), `FLUX` (Flux), `GRS` (Groestlcoin),
`HBAR` (Hedera), `ICX` (ICON), `IOST` (IOST), `KIN` (Kin), `KMD` (Komodo),
`KSM` (Kusama), `NEAR` (NEAR), `NEBL` (Neblio), `NEO` (NEO), `ONE` (Harmony),
`ONT` (Ontology), `ROSE` (Oasis), `STRK` (StarkNet), `SUI` (Sui), `WAVES` (Waves),
`WAX` (WAX), `XEC` (eCash), `XNO` (Nano), `XTZ` (Tezos), `XVG` (Verge),
`ZEN` (Horizen), `ZETA` (ZetaChain, Cosmos-side), `ZIL` (Zilliqa).

Note: **ZETAEVM** (ZetaChain's EVM side) and **ZEC**/**BCH** remain fully
supported — only the Cosmos-side ZETA row and the non-standard-sighash UTXO
chains above were removed.

A PR re-adding any of these must follow the same rule as every other chain in
this registry: **no fund-critical address or signature ships without an
authoritative Trust Wallet Core (or equivalent) test vector.**

Contributions with test vectors welcome.

---

## Verification

"Trust Wallet–compatible" is proven, not asserted. The test suite layers three
independent sources of truth:

1. **Encoders** (`encoders_test.go`) — every address encoder is run against the
   exact addresses Trust Wallet Core's `CoinAddressDerivationTests` produces for
   a fixed key, isolating address-format correctness.
2. **Derivation** (`slip10_test.go`) — ed25519 derivation is checked against
   the official **SLIP-0010** specification test vectors.
3. **End-to-end** (`hdwallet_test.go`) — full mnemonic→seed→derive→encode
   against the BIP-84 spec (BTC), the canonical ETH vector, and Trust Wallet
   Core's `HDWalletTests` Cosmos secp256k1 mnemonic vector.

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
| `(*HDWallet) Address(chain Chain) (string, error)` | First receive address for one network. |
| `(*HDWallet) AddressIndex(chain Chain, index uint32) (string, error)` | Nth address/account for one network. |
| `(*HDWallet) AddressPath(chain Chain, path string) (string, error)` | Address at an arbitrary absolute BIP-32 path. Also `SignPath`/`PublicKeyPath`/`WithPrivateKeyPath`/`PrivateKeyPath`. |
| `(*HDWallet) AddressAt(chain Chain, account, change, index uint32) (string, error)` | Address by BIP-44 account/change/index. Also `SignAt`/`PublicKeyAt`. |
| `(*HDWallet) AllAddresses() (map[Chain]string, error)` | Addresses for all networks. Also `AllAddressesAt(index)` for any index. |
| `(*HDWallet) Sign(chain Chain, data []byte) (*Signature, error)` | Sign a digest (ECDSA) / message (ed25519) at index 0. |
| `(*HDWallet) SignIndex(chain Chain, index uint32, data []byte) (*Signature, error)` | Sign with the key at a given index. |
| `(*HDWallet) PublicKey(chain Chain) ([]byte, error)` | Public key at index 0. |
| `(*HDWallet) PublicKeyIndex(chain Chain, index uint32) ([]byte, error)` | Public key at a given index. |
| `Verify(curve Curve, pub, data []byte, sig *Signature) bool` | Verify a signature. |
| `(*HDWallet) WithMnemonic(func([]byte) error) error` | Use the mnemonic, auto-wiped. |
| `(*HDWallet) Mnemonic() (*memguard.LockedBuffer, error)` | Mnemonic buffer (caller `Destroy`s). |
| `(*HDWallet) Destroy()` | Wipe the wallet's secrets. |
| `SupportedCoins() []Chain` | Sorted list of chains. |
| `CoinInfo(chain Chain) (Coin, bool)` | Registry entry for a chain. |

**Private-key import / export** (same memguard discipline as the mnemonic):

| Function / method | Purpose |
|---|---|
| `FromPrivateKeyBytes([]byte, Curve) (*HDWallet, error)` | Key-only wallet from a byte slice (wiped on use). Any 32-byte-scalar curve. |
| `FromPrivateKeyBuffer(*memguard.LockedBuffer, Curve) (*HDWallet, error)` | Key-only wallet from a memguard buffer (zero-copy). |
| `(*HDWallet) WithPrivateKey(chain, index, func([]byte) error) error` | Use the leaf private key, auto-wiped. |
| `(*HDWallet) PrivateKey(chain, index) (*memguard.LockedBuffer, error)` | Leaf key buffer (caller `Destroy`s). |
| `FromWIF([]byte) (*HDWallet, error)` · `(*HDWallet) WithWIF` / `WIF` | Import/export a Bitcoin WIF (secp256k1). |
| `(*HDWallet) AccountXPub(chain, account) (string, error)` · `WithAccountXPrv` | Export account-level BIP-32 extended keys (secp256k1). |
| `WatchOnlyFromXPub(xpub string, chain) (*WatchWallet, error)` | Watch-only address derivation from an xpub — no seed. |

**Transaction & Ethereum message signing:**

| Function / method | Purpose |
|---|---|
| `(*HDWallet) SignTransaction(chain, index, proto.Message) (proto.Message, error)` | Build+sign a raw tx (EVM/Tron/XRP/Cosmos/Solana/Bitcoin-UTXO/Stellar/Algorand/Aptos/TON; no broadcast). |
| `BroadcastPayload(chain, proto.Message) (string, error)` | Convert a `SignTransaction` output to the exact string each chain's RPC endpoint expects: `"0x"+hex` for EVM, bare hex for Bitcoin/UTXO, base64 for Solana and Cosmos, a TronGrid JSON object for Tron, uppercase hex for XRP. |
| `TransactionID(proto.Message) (string, error)` | Extract the canonical transaction id from any `SignTransaction` output, normalised to lower-case hex (or base58 for Solana). |
| `(*HDWallet) SignMessage(chain, index, []byte) ([]byte, error)` | EIP-191 `personal_sign` → 65-byte r‖s‖v. |
| `(*HDWallet) SignTypedData(chain, index, []byte) ([]byte, error)` | EIP-712 typed-data signature. |
| `(*HDWallet) SignBitcoinMessage(chain, index, []byte) (string, error)` | Bitcoin `signmessage` → base64. With `VerifyBitcoinMessage`. |
| `(*HDWallet) SignSolanaMessage(chain, index, []byte) (string, error)` | Solana off-chain message → base58. With `VerifySolanaMessage`. |
| `(*HDWallet) SignCosmosADR36(chain, index, signer, []byte) (string, error)` | Cosmos ADR-36 arbitrary-message → base64 (65-byte recoverable). With `VerifyCosmosADR36`. |
| `(*HDWallet) SignTronMessage(chain, index, []byte) (string, error)` | Tron TIP-191 message → `0x…` hex (V ∈ {27,28}). With `VerifyTronMessage`. |
| `(*HDWallet) SignRawMessage(chain, index, []byte) (*Signature, error)` | Chain-neutral: ECDSA 32-byte digest or ed25519 raw message. With `VerifyRawMessage`. |
| `RecoverEthereumAddress([]byte, []byte) (string, error)` · `VerifyEthereumMessage` / `…TypedData` | Recover/verify EIP-191/712 signers. |
| `EncodeRLP`/`DecodeRLP` · `ABIEncode`/`ABIDecode` · `ABIFunctionSelector` · `EIP712Hash` | Standalone EVM encoding utilities. |
| `ParseContractABI(jsonABI string) (ContractABIMap, error)` · `DecodeContractCall(abi, calldata)` · `GetFunctionSignature(fn)` | JSON-ABI-driven contract-call decoding: parse a JSON ABI array into a selector-keyed map, then decode raw calldata into a function name and typed named parameters. |

**Chain-constraint helpers (informational, no network I/O):**

| Function | Purpose |
|---|---|
| `MinimumBalance(chain) (*big.Int, bool)` | Minimum on-chain reserve/rent floor (XRP/XLM/SOL). |
| `DustThreshold(chain) (*big.Int, bool)` | Standard-relay dust limit in sats (every UTXO chain). |
| `ActivationCost(chain) (*big.Int, bool)` | One-off account-activation fee (TRX). |

**Address validation / parsing (`AnyAddress`-style):**

| Function | Purpose |
|---|---|
| `IsValidAddress(chain, addr) bool` · `ValidateAddress(chain, addr) error` | Validate an address for a network. |
| `ParseAddress(chain, addr) ([]byte, error)` | Decode an address to its payload. |
| `AddressFromPublicKey(chain, pub) (string, error)` | Derive an address from an external public key. |

**Mnemonic entry-screen helpers (pure functions, no secrets):**

| Function | Purpose |
|---|---|
| `WordlistPrefix(prefix string) []string` | Up to 8 BIP-39 English words starting with prefix — for autocomplete. |
| `IsValidWord(word string) bool` | Reports whether a word is in the BIP-39 English wordlist. |
| `SuggestFinalWords(words []string) ([]string, error)` | Given the first 11/14/17/20/23 words, returns all valid final words (128 completions for a 12-word mnemonic). |
| `MnemonicStrength(mnemonic string) (bits, words int, err error)` | Validates a mnemonic and reports its entropy size and word count. |
| `ValidateMnemonic(string) error` · `ValidateMnemonicBytes([]byte) error` | Validate without building a wallet. |

`Chain` is a typed string enum; the package exports a constant for every
supported network (`hdwallet.BTC`, `hdwallet.ETH`, `hdwallet.SOL`, …). Pass these
constants instead of raw strings for compile-time safety. `Chain` also has
`String() string` and `IsValid() bool` helpers.

---

## Adding a network

Append one row to the registry in `registry.go`:

```go
"FOO": {"Foochain", "FOO", Secp256k1, "m/44'/9999'/0'/0/0", encodeFoo},
```

Provide an `Encode func(pub []byte) (string, error)` for the address format
(the compressed key for secp256k1, the raw 32-byte key for ed25519), and add a
test vector. EVM chains can reuse `encodeETH`; Cosmos chains can reuse
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
