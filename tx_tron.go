package hdwallet

import (
	"encoding/hex"
	"fmt"
	"time"

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

// tronTriggerSmartContractType is the Tron ContractType enum value for
// TriggerSmartContract (used for TRC-20 transfers).
const tronTriggerSmartContractType = 31

// tronTransferTypeURL is the google.protobuf.Any type_url for a TransferContract.
const tronTransferTypeURL = "type.googleapis.com/protocol.TransferContract"

// tronTriggerSmartContractTypeURL is the Any type_url for a TriggerSmartContract.
const tronTriggerSmartContractTypeURL = "type.googleapis.com/protocol.TriggerSmartContract"

// signTronTx builds, signs and serializes a Tron transaction (TRX transfer or
// TRC-20 token transfer).
func (w *HDWallet) signTronTx(symbol Symbol, index uint32, in *txtron.SigningInput) (*txtron.SigningOutput, error) {
	tx := in.GetTransaction()
	if tx == nil {
		return nil, fmt.Errorf("%w: tron: missing transaction", ErrTxInput)
	}

	contractMsg, err := tronContractMsg(tx)
	if err != nil {
		return nil, err
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

	rawData := tronRawData(in, contractMsg, refBlockBytes, refBlockHash)

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

// tronContractMsg builds the field-11 Contract message for the transaction's
// contract type (TransferContract or a TRC-20 TriggerSmartContract).
func tronContractMsg(tx *txtron.Transaction) ([]byte, error) {
	switch {
	case tx.GetTransfer() != nil:
		t := tx.GetTransfer()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		to, err := tronAddressBytes(t.GetToAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: to_address: %v", ErrTxInput, err)
		}
		return tronTransferContractMsg(owner, to, t.GetAmount()), nil
	case tx.GetTransferTrc20() != nil:
		t := tx.GetTransferTrc20()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		contract, err := tronAddressBytes(t.GetContractAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: contract_address: %v", ErrTxInput, err)
		}
		recipient, err := tronAddressBytes(t.GetToAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: to_address: %v", ErrTxInput, err)
		}
		data, err := tronTRC20TransferData(recipient, t.GetAmount())
		if err != nil {
			return nil, err
		}
		return tronTriggerSmartContractMsg(owner, contract, data), nil
	default:
		return nil, fmt.Errorf("%w: tron: no supported contract set", ErrTxInput)
	}
}

// tronTransferContractMsg builds the Contract {1: type=TransferContract, 2: Any}.
func tronTransferContractMsg(owner, to []byte, amount int64) []byte {
	// Inner TransferContract: {1: owner, 2: to, 3: amount}.
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	inner = protowire.AppendTag(inner, 2, protowire.BytesType)
	inner = protowire.AppendBytes(inner, to)
	inner = protowire.AppendTag(inner, 3, protowire.VarintType)
	inner = protowire.AppendVarint(inner, i64AsU64(amount))
	return tronContractWrap(tronTransferType, tronTransferTypeURL, inner)
}

// tronTriggerSmartContractMsg builds the Contract {1: type=TriggerSmartContract,
// 2: Any} for a smart-contract call. call_value (field 3) is omitted (zero).
func tronTriggerSmartContractMsg(owner, contractAddr, data []byte) []byte {
	// TriggerSmartContract: {1: owner_address, 2: contract_address, 4: data}.
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	inner = protowire.AppendTag(inner, 2, protowire.BytesType)
	inner = protowire.AppendBytes(inner, contractAddr)
	inner = protowire.AppendTag(inner, 4, protowire.BytesType)
	inner = protowire.AppendBytes(inner, data)
	return tronContractWrap(tronTriggerSmartContractType, tronTriggerSmartContractTypeURL, inner)
}

// tronContractWrap wraps an inner contract message in its google.protobuf.Any and
// the enclosing Contract {1: type, 2: parameter(Any)} message.
func tronContractWrap(ctype uint64, typeURL string, inner []byte) []byte {
	var anyMsg []byte
	anyMsg = protowire.AppendTag(anyMsg, 1, protowire.BytesType)
	anyMsg = protowire.AppendString(anyMsg, typeURL)
	anyMsg = protowire.AppendTag(anyMsg, 2, protowire.BytesType)
	anyMsg = protowire.AppendBytes(anyMsg, inner)

	var contractMsg []byte
	contractMsg = protowire.AppendTag(contractMsg, 1, protowire.VarintType)
	contractMsg = protowire.AppendVarint(contractMsg, ctype)
	contractMsg = protowire.AppendTag(contractMsg, 2, protowire.BytesType)
	contractMsg = protowire.AppendBytes(contractMsg, anyMsg)
	return contractMsg
}

// tronTRC20TransferData builds the transfer(address,uint256) calldata for a
// TRC-20 transfer: the 4-byte selector followed by two 32-byte words.
//
// Matching Trust Wallet Core, the recipient is the FULL 21-byte Tron address
// (0x41 || hash20) left-padded to 32 bytes — the 0x41 prefix lands in the high
// (masked) bits, so it is on-chain-equivalent to the 20-byte form but is a
// distinct byte sequence that the signed txID depends on. amount is big-endian
// uint256 bytes.
func tronTRC20TransferData(recipient, amount []byte) ([]byte, error) {
	if len(recipient) != 21 {
		return nil, fmt.Errorf("%w: tron: recipient must be 21 bytes", ErrTxInput)
	}
	selector := ABIFunctionSelector("transfer", []string{"address", "uint256"}) // 0xa9059cbb
	data := make([]byte, 0, 4+32+32)
	data = append(data, selector...)
	data = append(data, leftPad(recipient, 32)...)
	data = append(data, leftPad(amount, 32)...)
	return data, nil
}

// tronRawData serializes the on-chain Transaction.raw message around a prebuilt
// Contract message. Zero-valued expiration/timestamp/fee_limit are omitted, per
// proto3 serialization (matching Trust Wallet Core).
func tronRawData(in *txtron.SigningInput, contractMsg, refBlockBytes, refBlockHash []byte) []byte {
	tx := in.GetTransaction()

	// Trust Wallet Core defaults: timestamp -> now if unset; expiration ->
	// timestamp + 10h if unset. Both are always present in raw_data; fee_limit is
	// emitted only when non-zero (no default).
	ts := tx.GetTimestamp()
	if ts == 0 {
		ts = time.Now().UnixMilli()
	}
	exp := tx.GetExpiration()
	if exp == 0 {
		exp = ts + tronDefaultExpirationMs
	}

	// raw_data, fields in ascending order: 1, 4, 8, 11, 14, (18).
	var raw []byte
	raw = protowire.AppendTag(raw, 1, protowire.BytesType)
	raw = protowire.AppendBytes(raw, refBlockBytes)
	raw = protowire.AppendTag(raw, 4, protowire.BytesType)
	raw = protowire.AppendBytes(raw, refBlockHash)
	raw = protowire.AppendTag(raw, 8, protowire.VarintType)
	raw = protowire.AppendVarint(raw, i64AsU64(exp))
	raw = protowire.AppendTag(raw, 11, protowire.BytesType)
	raw = protowire.AppendBytes(raw, contractMsg)
	raw = protowire.AppendTag(raw, 14, protowire.VarintType)
	raw = protowire.AppendVarint(raw, i64AsU64(ts))
	if fee := tx.GetFeeLimit(); fee != 0 {
		raw = protowire.AppendTag(raw, 18, protowire.VarintType)
		raw = protowire.AppendVarint(raw, i64AsU64(fee))
	}
	return raw
}

// tronDefaultExpirationMs is Trust Wallet Core's default transaction lifetime
// (10 hours) applied when no expiration is provided.
const tronDefaultExpirationMs int64 = 10 * 60 * 60 * 1000

// tronRefBlockBytes returns the 2-byte ref_block_bytes for a block number: the
// last two bytes of the 8-byte big-endian number (TWC encodes LE then reverses,
// equivalently bytes [6:8] of the big-endian encoding).
func tronRefBlockBytes(number int64) []byte {
	var be [8]byte
	n := i64AsU64(number)
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
	raw = protowire.AppendVarint(raw, i64AsU64(bh.GetTimestamp()))
	raw = protowire.AppendTag(raw, 2, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bh.GetTxTrieRoot())
	raw = protowire.AppendTag(raw, 3, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bh.GetParentHash())
	raw = protowire.AppendTag(raw, 7, protowire.VarintType)
	raw = protowire.AppendVarint(raw, i64AsU64(bh.GetNumber()))
	raw = protowire.AppendTag(raw, 9, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bh.GetWitnessAddress())
	raw = protowire.AppendTag(raw, 10, protowire.VarintType)
	raw = protowire.AppendVarint(raw, i32AsU64(bh.GetVersion()))

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
