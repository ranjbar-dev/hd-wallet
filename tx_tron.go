package hdwallet

import (
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"

	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// Tron transaction signing (TransferContract).
//
// Tron transactions are signed over txID = sha256(raw_data), where raw_data is
// the protobuf serialization of the on-chain Transaction.raw message. The
// resulting signature is the 65-byte recoverable secp256k1 signature (r||s||v,
// v in {0,1}) — Tron does NOT add Ethereum's 27 offset or an EIP-155 chain id.
//
// The internal raw_data layout (Tron protocol, field numbers fixed by the chain):
//
//	raw_data {
//	  1: ref_block_bytes  (bytes)  // last 2 bytes of LE(blockNumber), big-endian
//	  4: ref_block_hash   (bytes)  // sha256(blockHeader.raw)[8:16]
//	  8: expiration       (int64, ms)
//	  11: contract        (repeated Contract)
//	  14: timestamp       (int64, ms)
//	  18: fee_limit       (int64)  // omitted when zero
//	}
//	Contract {
//	  1: type      (enum; TransferContract = 1)
//	  2: parameter (google.protobuf.Any { 1: type_url, 2: value })
//	}
//	Any.value = TransferContract { 1: owner_address, 2: to_address, 3: amount }
//
// The block header used to derive ref_block_bytes/ref_block_hash is itself a
// protobuf (BlockHeader.raw): {1: timestamp, 2: tx_trie_root, 3: parent_hash,
// 7: number, 9: witness_address, 10: version}.
//
// We serialize these by hand with protowire so the bytes match Trust Wallet
// Core's protobuf output exactly; verified byte-for-byte against TWC's Tron
// AnySigner vector (see tx_tron_test.go).

// tronTransferType is the Tron ContractType enum value for TransferContract.
const tronTransferType = 1

// tronTransferTypeURL is the google.protobuf.Any type_url for a TransferContract.
const tronTransferTypeURL = "type.googleapis.com/protocol.TransferContract"

// signTronTx builds, signs and serializes a Tron TransferContract transaction.
func (w *HDWallet) signTronTx(symbol Symbol, index uint32, in *txtron.SigningInput) (*txtron.SigningOutput, error) {
	tx := in.GetTransaction()
	if tx == nil {
		return nil, fmt.Errorf("%w: tron: missing transaction", ErrTxInput)
	}
	transfer := tx.GetTransfer()
	if transfer == nil {
		return nil, fmt.Errorf("%w: tron: only TransferContract is supported", ErrTxInput)
	}

	owner, err := tronAddressBytes(transfer.GetOwnerAddress())
	if err != nil {
		return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
	}
	to, err := tronAddressBytes(transfer.GetToAddress())
	if err != nil {
		return nil, fmt.Errorf("%w: tron: to_address: %v", ErrTxInput, err)
	}

	bh := tx.GetBlockHeader()
	if bh == nil {
		return nil, fmt.Errorf("%w: tron: missing block_header", ErrTxInput)
	}
	refBlockBytes := tronRefBlockBytes(bh.GetNumber())
	refBlockHash, err := tronRefBlockHash(bh)
	if err != nil {
		return nil, err
	}

	rawData := tronRawData(in, transfer, owner, to, refBlockBytes, refBlockHash)

	// txID = sha256(raw_data); the signature is over this digest.
	id := sha256Sum(rawData)
	sig, err := w.SignIndex(symbol, index, id)
	if err != nil {
		return nil, err
	}
	rec := sig.Recoverable() // 65 bytes r||s||v with v in {0,1}; Tron uses it as-is
	if rec == nil {
		return nil, fmt.Errorf("%w: %s is not a secp256k1 coin", ErrTxInput, symbol)
	}

	return &txtron.SigningOutput{
		Id:            id,
		Signature:     rec,
		RawData:       rawData,
		RefBlockBytes: hex.EncodeToString(refBlockBytes),
	}, nil
}

// tronRawData serializes the on-chain Transaction.raw message.
func tronRawData(in *txtron.SigningInput, transfer *txtron.TransferContract, owner, to, refBlockBytes, refBlockHash []byte) []byte {
	tx := in.GetTransaction()

	// Inner TransferContract: {1: owner, 2: to, 3: amount}.
	var contract []byte
	contract = protowire.AppendTag(contract, 1, protowire.BytesType)
	contract = protowire.AppendBytes(contract, owner)
	contract = protowire.AppendTag(contract, 2, protowire.BytesType)
	contract = protowire.AppendBytes(contract, to)
	contract = protowire.AppendTag(contract, 3, protowire.VarintType)
	contract = protowire.AppendVarint(contract, uint64(transfer.GetAmount()))

	// google.protobuf.Any: {1: type_url, 2: value}.
	var anyMsg []byte
	anyMsg = protowire.AppendTag(anyMsg, 1, protowire.BytesType)
	anyMsg = protowire.AppendString(anyMsg, tronTransferTypeURL)
	anyMsg = protowire.AppendTag(anyMsg, 2, protowire.BytesType)
	anyMsg = protowire.AppendBytes(anyMsg, contract)

	// Contract: {1: type, 2: parameter(Any)}.
	var contractMsg []byte
	contractMsg = protowire.AppendTag(contractMsg, 1, protowire.VarintType)
	contractMsg = protowire.AppendVarint(contractMsg, tronTransferType)
	contractMsg = protowire.AppendTag(contractMsg, 2, protowire.BytesType)
	contractMsg = protowire.AppendBytes(contractMsg, anyMsg)

	// raw_data, fields in ascending order: 1, 4, 8, 11, 14, (18).
	var raw []byte
	raw = protowire.AppendTag(raw, 1, protowire.BytesType)
	raw = protowire.AppendBytes(raw, refBlockBytes)
	raw = protowire.AppendTag(raw, 4, protowire.BytesType)
	raw = protowire.AppendBytes(raw, refBlockHash)
	raw = protowire.AppendTag(raw, 8, protowire.VarintType)
	raw = protowire.AppendVarint(raw, uint64(tx.GetExpiration()))
	raw = protowire.AppendTag(raw, 11, protowire.BytesType)
	raw = protowire.AppendBytes(raw, contractMsg)
	raw = protowire.AppendTag(raw, 14, protowire.VarintType)
	raw = protowire.AppendVarint(raw, uint64(tx.GetTimestamp()))
	if fee := tx.GetFeeLimit(); fee != 0 {
		raw = protowire.AppendTag(raw, 18, protowire.VarintType)
		raw = protowire.AppendVarint(raw, uint64(fee))
	}
	return raw
}

// tronRefBlockBytes returns the 2-byte ref_block_bytes for a block number: the
// last two bytes of the 8-byte big-endian number (TWC encodes LE then reverses,
// equivalently bytes [6:8] of the big-endian encoding).
func tronRefBlockBytes(number int64) []byte {
	var be [8]byte
	n := uint64(number)
	for i := 7; i >= 0; i-- {
		be[i] = byte(n)
		n >>= 8
	}
	out := make([]byte, 2)
	copy(out, be[6:8])
	return out
}

// tronRefBlockHash serializes the block header's raw message, hashes it with
// sha256, and returns bytes [8:16] (ref_block_hash).
func tronRefBlockHash(bh *txtron.BlockHeader) ([]byte, error) {
	// BlockHeader.raw: {1: timestamp, 2: tx_trie_root, 3: parent_hash,
	// 7: number, 9: witness_address, 10: version}, ascending order.
	var raw []byte
	raw = protowire.AppendTag(raw, 1, protowire.VarintType)
	raw = protowire.AppendVarint(raw, uint64(bh.GetTimestamp()))
	raw = protowire.AppendTag(raw, 2, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bh.GetTxTrieRoot())
	raw = protowire.AppendTag(raw, 3, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bh.GetParentHash())
	raw = protowire.AppendTag(raw, 7, protowire.VarintType)
	raw = protowire.AppendVarint(raw, uint64(bh.GetNumber()))
	raw = protowire.AppendTag(raw, 9, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bh.GetWitnessAddress())
	raw = protowire.AppendTag(raw, 10, protowire.VarintType)
	raw = protowire.AppendVarint(raw, uint64(bh.GetVersion()))

	hash := sha256Sum(raw)
	if len(hash) < 16 {
		return nil, fmt.Errorf("%w: tron: short block hash", ErrTxInput)
	}
	return hash[8:16], nil
}

// tronAddressBytes resolves a Tron address string to its 21-byte form (0x41 ||
// 20-byte hash160). It accepts a base58check "T..." address or a raw hex string
// (with or without the 0x41 prefix already present).
func tronAddressBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty address")
	}
	// Try base58check first (Tron's external form).
	if b, err := base58CheckDecode(base58BTC, s); err == nil && len(b) == 21 && b[0] == 0x41 {
		return b, nil
	}
	// Fall back to raw hex.
	raw, err := hexToBytes(s)
	if err != nil {
		return nil, fmt.Errorf("not base58check or hex: %v", err)
	}
	switch {
	case len(raw) == 21 && raw[0] == 0x41:
		return raw, nil
	case len(raw) == 20:
		return append([]byte{0x41}, raw...), nil
	default:
		return nil, fmt.Errorf("unexpected address length %d", len(raw))
	}
}
