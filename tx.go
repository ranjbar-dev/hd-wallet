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
	"encoding/hex"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
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
	// ErrTxRoadmap is returned by families that are planned but not yet
	// vector-verified; the corresponding builder is intentionally not shipped.
	ErrTxRoadmap = errors.New("hdwallet: transaction signing for this coin is not yet implemented")
)

// txFamily groups coins that share a transaction-building scheme.
type txFamily int

const (
	familyNone txFamily = iota
	familyEthereum
	familyTron
	familyRipple
	familyCosmos
	familySolana
	familyBitcoin
)

// txFamilyOf maps a symbol to its transaction-building family. EVM chains all map
// to familyEthereum; Cosmos chains all map to familyCosmos.
func txFamilyOf(symbol Symbol) txFamily {
	switch symbol {
	case ETH, BNB, MATIC, AVAX, ARB, OP, FTM, BASE, CRO, GNO, CELO:
		return familyEthereum
	case TRX:
		return familyTron
	case XRP:
		return familyRipple
	case ATOM, OSMO, JUNO, TIA:
		return familyCosmos
	case SOL:
		return familySolana
	case BTC, LTC:
		return familyBitcoin
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
	default:
		return nil, fmt.Errorf("%w: %s", ErrTxUnsupported, symbol)
	}
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
