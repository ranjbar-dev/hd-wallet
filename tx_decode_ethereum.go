package hdwallet

// "What am I signing?" decoder for Ethereum / EVM transactions.
//
// DecodeEthereumTx parses a raw (signed or unsigned) EVM transaction back into
// its plain fields so a client can render a confirmation screen WITHOUT ever
// touching a private key, a derivation path or any secret. It is the inverse of
// the tx_ethereum.go signer: it branches on the typed-envelope byte (0x02 =
// EIP-1559, 0x01 = EIP-2930, >= 0xc0 = legacy RLP list), parses the RLP tree via
// DecodeRLP, and extracts the per-type fields.
//
// It reuses, not reimplements, the existing primitives:
//   - eth_rlp.go DecodeRLP / RLPItem for the RLP tree;
//   - eth_abi.go ABIFunctionSelector / ABIDecodeParams to recognise and decode
//     the ERC-20 transfer(address,uint256) / approve(address,uint256) calldata.
//
// This file adds no signer/registry/proto changes; it is display-only.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// ErrTxDecode is returned when raw transaction bytes are malformed, truncated or
// otherwise not a transaction this decoder understands. The decoder never panics
// and never reads past the input.
var ErrTxDecode = errors.New("hdwallet: malformed transaction bytes")

// EthTxType identifies the EVM transaction envelope a raw blob decoded as.
type EthTxType int

const (
	// EthTxLegacy is a pre-EIP-2718 legacy (EIP-155) transaction: a bare RLP
	// list with no type-byte envelope.
	EthTxLegacy EthTxType = iota
	// EthTxEIP2930 is a type-1 (0x01) access-list transaction.
	EthTxEIP2930
	// EthTxEIP1559 is a type-2 (0x02) fee-market transaction.
	EthTxEIP1559
)

// String returns a short human-readable name for the transaction type.
func (t EthTxType) String() string {
	switch t {
	case EthTxLegacy:
		return "legacy"
	case EthTxEIP2930:
		return "eip-2930"
	case EthTxEIP1559:
		return "eip-1559"
	default:
		return "unknown"
	}
}

// EthAccessTuple is one decoded EIP-2930 access-list entry: the accessed address
// (0x-hex) and the 32-byte storage keys accessed under it.
type EthAccessTuple struct {
	Address     string   // "0x"-prefixed 20-byte address
	StorageKeys [][]byte // each 32 bytes
}

// ERC20Call is a decoded ERC-20 method call recognised in the transaction's
// calldata (transfer or approve). It is nil on EthTxFields unless the calldata's
// 4-byte selector and shape match one of those methods.
type ERC20Call struct {
	Method    string   // "transfer" or "approve"
	Recipient string   // "0x"-prefixed 20-byte address (the `to`/`spender`)
	Amount    *big.Int // the uint256 amount
}

// EthTxFields holds the decoded, display-ready fields of an EVM transaction.
// Numeric quantities are *big.Int (nil means absent/zero); To is a "0x"-prefixed
// hex address, empty for contract creation. The fields populated depend on Type:
// MaxPriorityFeePerGas/MaxFeePerGas/AccessList are EIP-1559/2930 only, GasPrice
// is legacy/2930 only, ChainID is decoded for all (derived from v via EIP-155 for
// a legacy tx whose v >= 35; nil for a legacy tx with the pre-155 v of 27/28).
type EthTxFields struct {
	Type     EthTxType
	ChainID  *big.Int
	Nonce    *big.Int
	GasPrice *big.Int // legacy + 2930

	MaxPriorityFeePerGas *big.Int // 1559
	MaxFeePerGas         *big.Int // 1559

	GasLimit *big.Int
	To       string // "0x"-hex; empty = contract creation
	Value    *big.Int
	Data     []byte

	AccessList []EthAccessTuple // 2930 + 1559

	// Signature scalars (present in a signed tx). YParity is the bare recovery id
	// (0/1) for typed txs; for legacy it is the raw v as a *big.Int.
	V *big.Int
	R *big.Int
	S *big.Int

	// ERC20 is set when Data decodes to a recognised ERC-20 transfer/approve call.
	ERC20 *ERC20Call
}

// DecodeEthereumTx decodes a raw EVM transaction (signed or unsigned) into its
// display fields. It branches on the first byte: 0x02 => EIP-1559, 0x01 =>
// EIP-2930, any byte >= 0xc0 (an RLP list prefix) => legacy. Malformed or
// truncated input returns ErrTxDecode; the function never panics.
func DecodeEthereumTx(raw []byte) (*EthTxFields, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: ethereum: empty input", ErrTxDecode)
	}
	switch {
	case raw[0] == 0x02:
		return decodeEthTyped(raw, EthTxEIP1559)
	case raw[0] == 0x01:
		return decodeEthTyped(raw, EthTxEIP2930)
	case raw[0] >= 0xc0:
		return decodeEthLegacy(raw)
	default:
		return nil, fmt.Errorf("%w: ethereum: unknown transaction prefix 0x%02x", ErrTxDecode, raw[0])
	}
}

// decodeEthLegacy decodes a legacy (EIP-155) transaction:
// rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s]).
func decodeEthLegacy(raw []byte) (*EthTxFields, error) {
	item, err := DecodeRLP(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: ethereum legacy: %v", ErrTxDecode, err)
	}
	if !item.IsList || len(item.List) != 9 {
		return nil, fmt.Errorf("%w: ethereum legacy: expected 9-field list, got %d", ErrTxDecode, listLen(item))
	}
	f := &EthTxFields{Type: EthTxLegacy}
	f.Nonce = quantity(item.List[0])
	f.GasPrice = quantity(item.List[1])
	f.GasLimit = quantity(item.List[2])
	to, err := decodeEthTo(item.List[3])
	if err != nil {
		return nil, err
	}
	f.To = to
	f.Value = quantity(item.List[4])
	f.Data = leafBytes(item.List[5])
	f.V = quantity(item.List[6])
	f.R = quantity(item.List[7])
	f.S = quantity(item.List[8])
	f.ChainID = chainIDFromV(f.V)
	f.ERC20 = decodeERC20(f.Data)
	return f, nil
}

// decodeEthTyped decodes a typed (EIP-2930 / EIP-1559) transaction. The first
// byte is the type; the remainder is the RLP payload list.
func decodeEthTyped(raw []byte, typ EthTxType) (*EthTxFields, error) {
	item, err := DecodeRLP(raw[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: ethereum %s: %v", ErrTxDecode, typ, err)
	}
	if !item.IsList {
		return nil, fmt.Errorf("%w: ethereum %s: payload is not a list", ErrTxDecode, typ)
	}
	f := &EthTxFields{Type: typ}
	l := item.List

	switch typ {
	case EthTxEIP2930:
		// [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, (v, r, s)]
		if len(l) != 8 && len(l) != 11 {
			return nil, fmt.Errorf("%w: ethereum eip-2930: expected 8 or 11 fields, got %d", ErrTxDecode, len(l))
		}
		f.ChainID = quantity(l[0])
		f.Nonce = quantity(l[1])
		f.GasPrice = quantity(l[2])
		f.GasLimit = quantity(l[3])
		to, err := decodeEthTo(l[4])
		if err != nil {
			return nil, err
		}
		f.To = to
		f.Value = quantity(l[5])
		f.Data = leafBytes(l[6])
		al, err := decodeAccessList(l[7])
		if err != nil {
			return nil, err
		}
		f.AccessList = al
		if len(l) == 11 {
			f.V, f.R, f.S = quantity(l[8]), quantity(l[9]), quantity(l[10])
		}
	case EthTxEIP1559:
		// [chainId, nonce, maxPriority, maxFee, gasLimit, to, value, data, accessList, (v, r, s)]
		if len(l) != 9 && len(l) != 12 {
			return nil, fmt.Errorf("%w: ethereum eip-1559: expected 9 or 12 fields, got %d", ErrTxDecode, len(l))
		}
		f.ChainID = quantity(l[0])
		f.Nonce = quantity(l[1])
		f.MaxPriorityFeePerGas = quantity(l[2])
		f.MaxFeePerGas = quantity(l[3])
		f.GasLimit = quantity(l[4])
		to, err := decodeEthTo(l[5])
		if err != nil {
			return nil, err
		}
		f.To = to
		f.Value = quantity(l[6])
		f.Data = leafBytes(l[7])
		al, err := decodeAccessList(l[8])
		if err != nil {
			return nil, err
		}
		f.AccessList = al
		if len(l) == 12 {
			f.V, f.R, f.S = quantity(l[9]), quantity(l[10]), quantity(l[11])
		}
	default:
		return nil, fmt.Errorf("%w: ethereum: unsupported typed tx", ErrTxDecode)
	}
	f.ERC20 = decodeERC20(f.Data)
	return f, nil
}

// decodeAccessList decodes the RLP access-list item
// [[address(20), [storageKey(32), ...]], ...] into EthAccessTuples. An empty list
// returns nil.
func decodeAccessList(item RLPItem) ([]EthAccessTuple, error) {
	if !item.IsList {
		return nil, fmt.Errorf("%w: ethereum: access list is not a list", ErrTxDecode)
	}
	if len(item.List) == 0 {
		return nil, nil
	}
	out := make([]EthAccessTuple, 0, len(item.List))
	for _, entry := range item.List {
		if !entry.IsList || len(entry.List) != 2 {
			return nil, fmt.Errorf("%w: ethereum: bad access-list entry", ErrTxDecode)
		}
		addr := leafBytes(entry.List[0])
		if len(addr) != 20 {
			return nil, fmt.Errorf("%w: ethereum: access-list address must be 20 bytes, got %d", ErrTxDecode, len(addr))
		}
		keysItem := entry.List[1]
		if !keysItem.IsList {
			return nil, fmt.Errorf("%w: ethereum: access-list storage keys not a list", ErrTxDecode)
		}
		keys := make([][]byte, 0, len(keysItem.List))
		for _, k := range keysItem.List {
			kb := leafBytes(k)
			if len(kb) != 32 {
				return nil, fmt.Errorf("%w: ethereum: access-list storage key must be 32 bytes, got %d", ErrTxDecode, len(kb))
			}
			keys = append(keys, kb)
		}
		out = append(out, EthAccessTuple{Address: "0x" + bytesToHex(addr), StorageKeys: keys})
	}
	return out, nil
}

// decodeERC20 recognises ERC-20 transfer(address,uint256) / approve(address,
// uint256) calldata and returns the decoded call, or nil if the calldata does not
// match either selector/shape. It reuses ABIFunctionSelector + ABIDecodeParams.
func decodeERC20(data []byte) *ERC20Call {
	if len(data) < 4 {
		return nil
	}
	sel := data[:4]
	var method string
	switch {
	case bytesEqual(sel, ABIFunctionSelector("transfer", []string{"address", "uint256"})):
		method = "transfer"
	case bytesEqual(sel, ABIFunctionSelector("approve", []string{"address", "uint256"})):
		method = "approve"
	default:
		return nil
	}
	vals, err := ABIDecodeParams([]string{"address", "uint256"}, data[4:])
	if err != nil || len(vals) != 2 {
		return nil
	}
	addr, ok := vals[0].Value.([]byte)
	if !ok || len(addr) != 20 {
		return nil
	}
	amount, ok := vals[1].Value.(*big.Int)
	if !ok {
		return nil
	}
	return &ERC20Call{
		Method:    method,
		Recipient: "0x" + bytesToHex(addr),
		Amount:    amount,
	}
}

// decodeEthTo renders the `to` field: empty leaf => "" (contract creation), a
// 20-byte leaf => "0x"+hex. Any other length is malformed.
func decodeEthTo(item RLPItem) (string, error) {
	if item.IsList {
		return "", fmt.Errorf("%w: ethereum: `to` is a list", ErrTxDecode)
	}
	b := item.Str
	switch len(b) {
	case 0:
		return "", nil
	case 20:
		return "0x" + bytesToHex(b), nil
	default:
		return "", fmt.Errorf("%w: ethereum: `to` must be 20 bytes, got %d", ErrTxDecode, len(b))
	}
}

// quantity interprets an RLP leaf as a big-endian unsigned integer. An empty leaf
// (RLP 0x80) decodes to 0. A list returns nil (caller validates shape first).
func quantity(item RLPItem) *big.Int {
	if item.IsList {
		return nil
	}
	return new(big.Int).SetBytes(item.Str)
}

// leafBytes returns a copy of an RLP leaf's bytes (nil for a list).
func leafBytes(item RLPItem) []byte {
	if item.IsList {
		return nil
	}
	return append([]byte(nil), item.Str...)
}

// listLen returns the number of children of a list item, or -1 for a leaf.
func listLen(item RLPItem) int {
	if !item.IsList {
		return -1
	}
	return len(item.List)
}

// chainIDFromV derives the EIP-155 chain id from a legacy v value: for v >= 35,
// chainId = (v - 35) / 2. Pre-155 values (27/28) carry no chain id, so nil is
// returned. A nil v (unsigned tx) also returns nil.
func chainIDFromV(v *big.Int) *big.Int {
	if v == nil {
		return nil
	}
	thirtyFive := big.NewInt(35)
	if v.Cmp(thirtyFive) < 0 {
		return nil
	}
	id := new(big.Int).Sub(v, thirtyFive)
	return id.Rsh(id, 1)
}

// ---------- Ethereum event log decoding ----------

// EthLog represents one Ethereum event log entry as returned by eth_getLogs or
// a transaction receipt. Topics is a slice of hex-encoded 32-byte values (with
// or without "0x" prefix); Data holds the non-indexed ABI-encoded parameters.
type EthLog struct {
	Address string   // contract address ("0x"-hex)
	Topics  []string // hex-encoded 32-byte topics: [eventSig, indexedParam…]
	Data    []byte   // ABI-encoded non-indexed parameters
}

// DecodeEthLog decodes the non-indexed ABI parameters from an Ethereum event
// log. abiTypes is the list of Solidity types for the non-indexed params (e.g.
// ["uint256", "address"]). Returns the decoded values using ABIDecodeParams.
func DecodeEthLog(log *EthLog, abiTypes []string) ([]ABIValue, error) {
	return ABIDecodeParams(abiTypes, log.Data)
}

// ERC20TransferLog decodes a standard ERC-20 Transfer(address,address,uint256)
// event log. Topics[1]=from (indexed), Topics[2]=to (indexed), Data=amount.
// Returns ErrTxDecode if the log does not match the Transfer event signature.
func ERC20TransferLog(log *EthLog) (from, to string, amount *big.Int, err error) {
	if len(log.Topics) < 3 {
		return "", "", nil, fmt.Errorf("%w: erc20 transfer: need ≥3 topics, got %d", ErrTxDecode, len(log.Topics))
	}
	if err := assertTransferTopic(log.Topics[0]); err != nil {
		return "", "", nil, err
	}
	fromBytes, e := decodeLogTopic(log.Topics[1])
	if e != nil {
		return "", "", nil, e
	}
	toBytes, e := decodeLogTopic(log.Topics[2])
	if e != nil {
		return "", "", nil, e
	}
	vals, e := ABIDecodeParams([]string{"uint256"}, log.Data)
	if e != nil {
		return "", "", nil, fmt.Errorf("%w: erc20 transfer: amount: %v", ErrTxDecode, e)
	}
	amt, ok := vals[0].Value.(*big.Int)
	if !ok {
		return "", "", nil, fmt.Errorf("%w: erc20 transfer: amount type assertion", ErrTxDecode)
	}
	return addressFromLogTopic(fromBytes), addressFromLogTopic(toBytes), amt, nil
}

// ERC721TransferLog decodes a standard ERC-721 Transfer(address,address,uint256)
// event log. Topics[1]=from, Topics[2]=to, Topics[3]=tokenId (all indexed).
// Returns ErrTxDecode if the log does not match the Transfer event signature.
func ERC721TransferLog(log *EthLog) (from, to string, tokenID *big.Int, err error) {
	if len(log.Topics) < 4 {
		return "", "", nil, fmt.Errorf("%w: erc721 transfer: need ≥4 topics, got %d", ErrTxDecode, len(log.Topics))
	}
	if err := assertTransferTopic(log.Topics[0]); err != nil {
		return "", "", nil, err
	}
	fromBytes, e := decodeLogTopic(log.Topics[1])
	if e != nil {
		return "", "", nil, e
	}
	toBytes, e := decodeLogTopic(log.Topics[2])
	if e != nil {
		return "", "", nil, e
	}
	tokenBytes, e := decodeLogTopic(log.Topics[3])
	if e != nil {
		return "", "", nil, e
	}
	return addressFromLogTopic(fromBytes), addressFromLogTopic(toBytes), new(big.Int).SetBytes(tokenBytes), nil
}

// assertTransferTopic checks that a topic matches the ERC-20/721 Transfer event
// signature keccak256("Transfer(address,address,uint256)").
func assertTransferTopic(topic string) error {
	b, err := decodeLogTopic(topic)
	if err != nil {
		return err
	}
	want := keccak256([]byte("Transfer(address,address,uint256)"))
	if !bytesEqual(b, want) {
		return fmt.Errorf("%w: topic[0] is not the Transfer event signature", ErrTxDecode)
	}
	return nil
}

// decodeLogTopic hex-decodes a topic string (with or without "0x" prefix) and
// returns the 32-byte value. Returns ErrTxDecode if malformed.
func decodeLogTopic(topic string) ([]byte, error) {
	s := strings.TrimPrefix(topic, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: log: topic hex: %v", ErrTxDecode, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: log: topic must be 32 bytes, got %d", ErrTxDecode, len(b))
	}
	return b, nil
}

// addressFromLogTopic extracts a 20-byte EVM address from a zero-padded
// 32-byte ABI topic value (last 20 bytes), returned as "0x"-hex.
func addressFromLogTopic(topic []byte) string {
	return "0x" + bytesToHex(topic[12:])
}
