package hdwallet

// Track 5: protobuf transaction signing.
//
// SignTransaction is a Trust Wallet Core `AnySigner` equivalent: given a chain
// symbol and a per-chain protobuf SigningInput, it builds the unsigned
// transaction, computes the chain's sighash/preimage, signs it with the existing
// derived-key signer (the private key is materialised, used and wiped inside the
// package — never returned), and returns a per-chain SigningOutput holding the
// signed serialized raw-tx bytes plus a hex/base58/base64 convenience form.
//
// It does NO networking and NEVER broadcasts.
//
// The family builders live in their own tx*.go files; each is verified against a
// Trust Wallet Core AnySigner test vector (see the *_test.go files). A family
// that cannot reproduce a TWC vector is left unimplemented with a // roadmap note
// and a skipped test recording the missing vector — a guessed builder is never
// shipped, because a wrong signature loses funds.

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	txalgo "github.com/ranjbar-dev/hd-wallet/txproto/algorand"
	txaptos "github.com/ranjbar-dev/hd-wallet/txproto/aptos"
	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
	txstellar "github.com/ranjbar-dev/hd-wallet/txproto/stellar"
	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// Transaction-signing errors.
var (
	// ErrTxUnsupported is returned when SignTransaction is asked to sign for a
	// symbol whose family has no transaction builder.
	ErrTxUnsupported = errors.New("hdwallet: transaction signing not supported for coin")
	// ErrTxInput is returned when the SigningInput proto type does not match the
	// family selected by symbol, or a required field is missing/invalid.
	ErrTxInput = errors.New("hdwallet: invalid transaction signing input")
)

// txFamily groups coins that share a transaction-building scheme.
type txFamily int

const (
	familyNone txFamily = iota
	familyEthereum
	familyTron
	familyRipple
	familyCosmos
	familyCosmosEthermint
	familySolana
	familyBitcoin
	familyAlgorand
	familyAptos   // APTOS: BCS + SHA3-256("APTOS::RawTransaction")||bcs
	familyStellar // XLM: XDR TransactionV0 + SHA256(networkId||ENVELOPE_TYPE_TX||xdr)
)

// txFamilyOf maps a symbol to its transaction-building family. EVM and standard
// Cosmos chains are resolved from the data-driven evmTxChains / cosmosTxChains
// sets (see tx_families.go) so transaction support stays in lockstep with the
// address registry; the single-chain families are matched directly.
func txFamilyOf(symbol Symbol) txFamily {
	if _, ok := evmTxChains[symbol]; ok {
		return familyEthereum
	}
	if _, ok := cosmosTxChains[symbol]; ok {
		return familyCosmos
	}
	if _, ok := ethermintTxChains[symbol]; ok {
		return familyCosmosEthermint
	}
	if _, ok := utxoTxChains[symbol]; ok {
		return familyBitcoin
	}
	switch symbol {
	case TRX:
		return familyTron
	case XRP:
		return familyRipple
	case SOL:
		return familySolana
	case BTC, LTC:
		return familyBitcoin
	case ALGO:
		return familyAlgorand
	case APTOS:
		return familyAptos
	case XLM:
		return familyStellar
	default:
		return familyNone
	}
}

// SignTransaction signs a transaction for symbol using the key derived at the
// given address index and returns a per-chain protobuf SigningOutput.
//
// input must be the SigningInput proto for symbol's family (e.g.
// *ethereum.SigningInput for ETH/EVM, *tron.SigningInput for TRX, …). The
// returned proto.Message is the matching SigningOutput, holding the signed
// serialized raw-transaction bytes plus a hex/base58/base64 convenience form. No
// network calls are made.
//
// The derived private key is wiped immediately after signing and never leaves the
// package. An unknown symbol returns ErrTxUnsupported; a wrong input type returns
// ErrTxInput.
func (w *HDWallet) SignTransaction(symbol Symbol, index uint32, input proto.Message) (proto.Message, error) {
	switch txFamilyOf(symbol) {
	case familyEthereum:
		in, ok := input.(*txeth.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *ethereum.SigningInput", ErrTxInput, symbol)
		}
		return w.signEthereumTx(symbol, index, in)
	case familyTron:
		in, ok := input.(*txtron.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *tron.SigningInput", ErrTxInput, symbol)
		}
		return w.signTronTx(symbol, index, in)
	case familyRipple:
		in, ok := input.(*txripple.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *ripple.SigningInput", ErrTxInput, symbol)
		}
		return w.signRippleTx(symbol, index, in)
	case familyCosmos:
		in, ok := input.(*txcosmos.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *cosmos.SigningInput", ErrTxInput, symbol)
		}
		return w.signCosmosTx(symbol, index, in)
	case familyCosmosEthermint:
		in, ok := input.(*txcosmos.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *cosmos.SigningInput", ErrTxInput, symbol)
		}
		return w.signCosmosEthermintTx(symbol, index, in)
	case familySolana:
		in, ok := input.(*txsolana.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *solana.SigningInput", ErrTxInput, symbol)
		}
		return w.signSolanaTx(symbol, index, in)
	case familyBitcoin:
		in, ok := input.(*txbtc.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *bitcoin.SigningInput", ErrTxInput, symbol)
		}
		return w.signBitcoinTx(symbol, index, in)
	case familyAlgorand:
		in, ok := input.(*txalgo.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *algorand.SigningInput", ErrTxInput, symbol)
		}
		return w.signALGOTx(symbol, index, in)
	case familyAptos:
		in, ok := input.(*txaptos.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *aptos.SigningInput", ErrTxInput, symbol)
		}
		return w.signAptosTx(symbol, index, in)
	case familyStellar:
		in, ok := input.(*txstellar.SigningInput)
		if !ok {
			return nil, fmt.Errorf("%w: %s expects *stellar.SigningInput", ErrTxInput, symbol)
		}
		return w.signXLMTx(symbol, index, in)
	default:
		return nil, fmt.Errorf("%w: %s", ErrTxUnsupported, symbol)
	}
}

// ValidateSigningInput performs a quick sanity check on the signing input for
// symbol. Returns ErrTxInput with a descriptive message if a required field
// appears missing. This does NOT validate chain-level correctness (nonce
// sequence, balance) — only that structurally required proto fields are
// non-zero.
func ValidateSigningInput(symbol Symbol, input proto.Message) error {
	switch txFamilyOf(symbol) {
	case familyEthereum:
		in, ok := input.(*txeth.SigningInput)
		if !ok {
			return fmt.Errorf("%w: %s expects *ethereum.SigningInput", ErrTxInput, symbol)
		}
		if len(in.GasLimit) == 0 || allZero(in.GasLimit) {
			return fmt.Errorf("%w: %s: gas_limit is required", ErrTxInput, symbol)
		}
		hasFee := (len(in.GasPrice) > 0 && !allZero(in.GasPrice)) ||
			(len(in.MaxFeePerGas) > 0 && !allZero(in.MaxFeePerGas))
		if !hasFee {
			return fmt.Errorf("%w: %s: gas_price or max_fee_per_gas is required", ErrTxInput, symbol)
		}
	case familyCosmos, familyCosmosEthermint:
		in, ok := input.(*txcosmos.SigningInput)
		if !ok {
			return fmt.Errorf("%w: %s expects *cosmos.SigningInput", ErrTxInput, symbol)
		}
		if in.AccountNumber == 0 {
			return fmt.Errorf("%w: %s: account_number is required", ErrTxInput, symbol)
		}
		if in.Fee == nil {
			return fmt.Errorf("%w: %s: fee is required", ErrTxInput, symbol)
		}
	case familyBitcoin:
		in, ok := input.(*txbtc.SigningInput)
		if !ok {
			return fmt.Errorf("%w: %s expects *bitcoin.SigningInput", ErrTxInput, symbol)
		}
		if len(in.Utxo) == 0 {
			return fmt.Errorf("%w: %s: at least one utxo input is required", ErrTxInput, symbol)
		}
		if in.ByteFee <= 0 {
			return fmt.Errorf("%w: %s: byte_fee is required", ErrTxInput, symbol)
		}
	case familySolana:
		in, ok := input.(*txsolana.SigningInput)
		if !ok {
			return fmt.Errorf("%w: %s expects *solana.SigningInput", ErrTxInput, symbol)
		}
		if in.RecentBlockhash == "" {
			return fmt.Errorf("%w: %s: recent_blockhash is required", ErrTxInput, symbol)
		}
	case familyTron:
		in, ok := input.(*txtron.SigningInput)
		if !ok {
			return fmt.Errorf("%w: %s expects *tron.SigningInput", ErrTxInput, symbol)
		}
		if in.GetRawJson() == "" {
			if in.Transaction == nil || in.Transaction.BlockHeader == nil || in.Transaction.BlockHeader.Number == 0 {
				return fmt.Errorf("%w: %s: transaction.block_header.number is required", ErrTxInput, symbol)
			}
			if in.Transaction.Expiration == 0 {
				return fmt.Errorf("%w: %s: transaction.expiration is required", ErrTxInput, symbol)
			}
		}
	case familyRipple:
		in, ok := input.(*txripple.SigningInput)
		if !ok {
			return fmt.Errorf("%w: %s expects *ripple.SigningInput", ErrTxInput, symbol)
		}
		if in.Sequence == 0 {
			return fmt.Errorf("%w: %s: sequence is required", ErrTxInput, symbol)
		}
		if in.Fee == 0 {
			return fmt.Errorf("%w: %s: fee is required", ErrTxInput, symbol)
		}
	case familyAlgorand:
		in, ok := input.(*txalgo.SigningInput)
		if !ok {
			return fmt.Errorf("%w: %s expects *algorand.SigningInput", ErrTxInput, symbol)
		}
		if len(in.GenesisHash) != 32 {
			return fmt.Errorf("%w: %s: genesis_hash must be 32 bytes", ErrTxInput, symbol)
		}
		if len(in.To) != 32 {
			return fmt.Errorf("%w: %s: to must be 32 bytes", ErrTxInput, symbol)
		}
		if in.Fee == 0 {
			return fmt.Errorf("%w: %s: fee is required", ErrTxInput, symbol)
		}
	case familyAptos:
		in, ok := input.(*txaptos.SigningInput)
		if !ok {
			return fmt.Errorf("%w: %s expects *aptos.SigningInput", ErrTxInput, symbol)
		}
		if in.GetEntryFunction() == nil {
			return fmt.Errorf("%w: %s: entry_function is required", ErrTxInput, symbol)
		}
	case familyStellar:
		in, ok := input.(*txstellar.SigningInput)
		if !ok {
			return fmt.Errorf("%w: %s expects *stellar.SigningInput", ErrTxInput, symbol)
		}
		if in.Account == "" {
			return fmt.Errorf("%w: %s: account is required", ErrTxInput, symbol)
		}
		if in.Sequence == 0 {
			return fmt.Errorf("%w: %s: sequence is required", ErrTxInput, symbol)
		}
		if in.Fee <= 0 {
			return fmt.Errorf("%w: %s: fee must be positive (got %d)", ErrTxInput, symbol, in.Fee)
		}
		if in.GetPayment() == nil {
			return fmt.Errorf("%w: %s: payment operation is required", ErrTxInput, symbol)
		}
	default:
		return fmt.Errorf("%w: %s", ErrTxUnsupported, symbol)
	}
	return nil
}

// allZero reports whether every byte in b is zero.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// bytesToHex returns the lower-case hex of b with no "0x" prefix, the form used
// by the SigningOutput *_hex convenience fields.
func bytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// sha256Sum returns the single SHA-256 digest of b. Tron uses it for the txID and
// block-reference hashes; Cosmos uses it for the SignDoc digest.
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// sha512Sum returns the full SHA-512 digest of b. XRP hashes with its first half
// (sha512Half).
func sha512Sum(b []byte) []byte {
	h := sha512.Sum512(b)
	return h[:]
}

// base64Std returns the standard (padded) base64 of b, the form Cosmos reports
// in its tx_bytes field.
func base64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// i64AsU64 reinterprets an int64 as a uint64. Protobuf encodes an int64 field as
// the bit-identical uint64 varint, so this conversion is exact and lossless (it
// is a reinterpretation, not a range-narrowing cast).
func i64AsU64(v int64) uint64 {
	return uint64(v) // #nosec G115 -- exact int64->uint64 bit reinterpretation for protobuf varint
}

// i32AsU64 sign-extends an int32 to a uint64 the same way protobuf encodes an
// int32 field (negative values become 10-byte varints); exact and lossless.
func i32AsU64(v int32) uint64 {
	return uint64(int64(v)) // #nosec G115 -- protobuf int32 varint encoding (sign-extended)
}

// lowByte returns the low 8 bits of n. Used for wire-format header/length bytes
// whose values are bounded by construction; the mask makes the truncation
// explicit and intentional.
func lowByte(n int) byte {
	return byte(n & 0xff) // #nosec G115 -- explicit low-byte mask for a bounded wire value
}

// u32Trunc returns the low 32 bits of v. Used for fields the chain defines as
// 32-bit (e.g. XRP DestinationTag) carried as a wider integer in the proto.
func u32Trunc(v uint64) uint32 {
	return uint32(v & 0xffffffff) // #nosec G115 -- explicit 32-bit mask for a 32-bit wire field
}
