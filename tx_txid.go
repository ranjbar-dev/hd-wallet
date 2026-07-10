package hdwallet

import (
	"encoding/hex"
	"errors"
	"strings"

	"google.golang.org/protobuf/proto"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
	txdot "github.com/ranjbar-dev/hd-wallet/txproto/polkadot"
	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
	txton "github.com/ranjbar-dev/hd-wallet/txproto/ton"
	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// ErrNoTxID is returned by TransactionID when a SigningOutput carries no
// transaction id (an empty id field) or when the argument is not one of the
// eight recognised per-family *…SigningOutput types (including a nil proto.Message).
var ErrNoTxID = errors.New("hdwallet: signing output has no transaction id")

// TransactionID returns one canonical transaction id for any SigningOutput
// produced by (*HDWallet).SignTransaction, hiding the per-family differences in
// field name, byte order and text encoding behind a single accessor so callers
// need not special-case each chain.
//
// out must be one of the eight per-family SigningOutput messages. The id source,
// by family, is:
//
//   - Bitcoin (and the UTXO altcoins BTC/LTC/DOGE/DASH/BCH/ZEC) — the
//     conventional "txid" reverse(sha256d(tx without witnesses)); from the bytes
//     field TransactionId.
//   - Tron — sha256(raw_data); from the bytes field Id.
//   - Ethereum / EVM — keccak256(signed RLP); from the string field TxId,
//     which the signer stores as "0x"+hex.
//   - Cosmos — sha256(TxRaw broadcast bytes); from the string field TxId, which
//     the signer stores as upper-case hex.
//   - Ripple / XRP — sha512Half(signed tx) (SHA-512(tx)[:32]); from the string
//     field TxId, which the signer stores as upper-case hex.
//   - Polkadot — BLAKE2b-256(Encoded), Substrate's standard extrinsic hash
//     (matches the on-chain/Subscan "extrinsic hash"); computed from the bytes
//     field Encoded.
//
// For these five hash-based families the result is normalised to LOWER-CASE hex
// with NO "0x" prefix, irrespective of how the underlying field stores it. The
// two byte-typed ids (Bitcoin TransactionId, Tron Id) are already in display
// (big-endian) order and are hex-encoded as-is — no reversal is applied here.
//
// Solana is the deliberate exception: its transaction id is NOT a hash but the
// base58-encoded fee-payer signature (Solana identifies a transaction by its
// first signature). It is returned exactly as the signer produced it — base58,
// unchanged — and must not be interpreted as hex.
//
// An empty id, or any message that is not one of the eight recognised
// SigningOutput types (including a nil proto.Message), returns ErrNoTxID. The
// helper reads only the public output and touches no secret material.
func TransactionID(out proto.Message) (string, error) {
	switch o := out.(type) {
	case *txbtc.SigningOutput:
		// Already reverse(sha256d) display/big-endian bytes; encode as-is.
		return hexFromTxIDBytes(o.GetTransactionId())
	case *txtron.SigningOutput:
		// sha256(raw_data) bytes; encode as-is.
		return hexFromTxIDBytes(o.GetId())
	case *txeth.SigningOutput:
		return normalizeHexTxID(o.GetTxId())
	case *txcosmos.SigningOutput:
		return normalizeHexTxID(o.GetTxId())
	case *txripple.SigningOutput:
		return normalizeHexTxID(o.GetTxId())
	case *txsolana.SigningOutput:
		// base58 of the fee-payer signature — returned verbatim, NOT hex.
		id := o.GetTxId()
		if id == "" {
			return "", ErrNoTxID
		}
		return id, nil
	case *txton.SigningOutput:
		// hex repr-hash of the external message cell (the toncenter poll key).
		return normalizeHexTxID(o.GetHash())
	case *txdot.SigningOutput:
		// Substrate's standard extrinsic hash: BLAKE2b-256 of the encoded bytes.
		encoded := o.GetEncoded()
		if len(encoded) == 0 {
			return "", ErrNoTxID
		}
		return hex.EncodeToString(blake2bPersonal(32, nil, encoded)), nil
	default:
		return "", ErrNoTxID
	}
}

// hexFromTxIDBytes hex-encodes a byte-typed txid (already in display/big-endian
// order) as lower-case hex; an empty value returns ErrNoTxID.
func hexFromTxIDBytes(b []byte) (string, error) {
	if len(b) == 0 {
		return "", ErrNoTxID
	}
	return hex.EncodeToString(b), nil
}

// normalizeHexTxID lower-cases a string txid and strips any "0x"/"0X" prefix so
// hash-based families share one canonical form; an empty value returns
// ErrNoTxID.
func normalizeHexTxID(s string) (string, error) {
	if s == "" {
		return "", ErrNoTxID
	}
	s = strings.ToLower(s)
	return strings.TrimPrefix(s, "0x"), nil
}
