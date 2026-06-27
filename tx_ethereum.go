package hdwallet

import (
	"fmt"
	"math/big"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// Ethereum / EVM transaction signing.
//
// Five transaction formats are produced, selected by SigningInput.tx_mode:
//
//   - tx_mode 0 — legacy (EIP-155). The signing preimage is
//     keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]))
//     and the encoded tx is rlp([nonce, gasPrice, gasLimit, to, value, data, v, r,
//     s]) with v = recid + chainId*2 + 35.
//   - tx_mode 1 — EIP-2930 (type-1, access list). The preimage is
//     keccak256(0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data,
//     accessList])) and the encoded tx is 0x01 || rlp([..., v, r, s]) with v =
//     recid (0/1).
//   - tx_mode 2 — EIP-1559 (type-2). The preimage is
//     keccak256(0x02 || rlp([chainId, nonce, maxPriority, maxFee, gasLimit, to,
//     value, data, accessList])) and the encoded tx is
//     0x02 || rlp([..., v, r, s]) with v = recid (0/1).
//   - tx_mode 3 — EIP-4844 (type-3, blob tx). The preimage is
//     keccak256(0x03 || rlp([chainId, nonce, maxPriority, maxFee, gasLimit, to,
//     value, data, accessList, maxFeePerBlobGas, blobVersionedHashes])) and the
//     encoded tx is 0x03 || rlp([..., v, r, s]) with v = recid (0/1).
//     Network-wrapper blobs/commitments/proofs are out of scope — the tx envelope
//     only is signed. Each blob_versioned_hash must be exactly 32 bytes.
//   - tx_mode 4 — EIP-7702 (type-4, set-code tx). The preimage is
//     keccak256(0x04 || rlp([chainId, nonce, maxPriority, maxFee, gasLimit, to,
//     value, data, accessList, authorizationList])) and the encoded tx is
//     0x04 || rlp([..., v, r, s]) with v = recid (0/1).
//     Each authorization_list item carries a pre-signed delegation tuple
//     [chain_id, address, nonce, y_parity, r, s].
//
// The optional EIP-2930 access list (SigningInput.access_list) is carried in the
// signed bytes for tx_mode 1–4; an empty list reproduces the no-access-list
// encoding byte-for-byte (so the existing legacy/1559 vectors are unaffected).
//
// The destination/value/data triple is built from the Transaction payload:
//   - Transfer: to = SigningInput.to_address, value = amount, data = data.
//   - ERC20Transfer: to = SigningInput.to_address (the token contract), value = 0,
//     data = transfer(recipient, amount) ABI calldata.
//
// Verified byte-for-byte against Trust Wallet Core's Ethereum AnySigner vectors
// (legacy native, legacy ERC-20, EIP-1559 ERC-20, EIP-1559 native+data) and
// the go-ethereum reference signer (EIP-2930/1559 access-list, EIP-4844, EIP-7702);
// see tx_ethereum_test.go and tx_ethereum_modern_test.go.

// EVM transaction modes, selecting the serialization format produced by
// SignTransaction for an EVM chain. They are the values of
// ethereum.SigningInput.tx_mode; use them instead of bare integers.
const (
	EthTxModeLegacy  uint32 = 0 // EIP-155 legacy
	EthTxModeEIP2930 uint32 = 1 // type-1 access-list
	EthTxModeEIP1559 uint32 = 2 // type-2 fee market
	EthTxModeEIP4844 uint32 = 3 // type-3 blob tx (EIP-4844)
	EthTxModeEIP7702 uint32 = 4 // type-4 set-code tx (EIP-7702)
)

// signEthereumTx builds, signs and serializes an EVM transaction.
func (w *HDWallet) signEthereumTx(symbol Symbol, index uint32, in *txeth.SigningInput) (*txeth.SigningOutput, error) {
	to, value, data, err := ethDestination(in)
	if err != nil {
		return nil, err
	}
	switch in.GetTxMode() {
	case EthTxModeLegacy:
		return w.signEthereumLegacy(symbol, index, in, to, value, data)
	case EthTxModeEIP2930:
		return w.signEthereumEIP2930(symbol, index, in, to, value, data)
	case EthTxModeEIP1559:
		return w.signEthereumEIP1559(symbol, index, in, to, value, data)
	case EthTxModeEIP4844:
		return w.signEthereumEIP4844(symbol, index, in, to, value, data)
	case EthTxModeEIP7702:
		return w.signEthereumEIP7702(symbol, index, in, to, value, data)
	default:
		return nil, fmt.Errorf("%w: %s unsupported tx_mode %d (want 0 legacy, 1 eip-2930, 2 eip-1559, 3 eip-4844 or 4 eip-7702)", ErrTxInput, symbol, in.GetTxMode())
	}
}

// ethAccessList builds the RLP item for an EIP-2930 access list:
// [[address(20), [storageKey(32), ...]], ...]. An empty/absent list encodes as
// the empty RLP list (0xc0), reproducing the no-access-list serialization. The
// address is a 20-byte hex string; each storage key must be exactly 32 bytes
// (storage keys are fixed-width, NOT quantity-minimized like integers).
func ethAccessList(accesses []*txeth.Access) (RLPItem, error) {
	entries := make([]RLPItem, 0, len(accesses))
	for _, a := range accesses {
		addr, err := hexToBytes(a.GetAddress())
		if err != nil || len(addr) != 20 {
			return RLPItem{}, fmt.Errorf("%w: ethereum: bad access-list address %q", ErrTxInput, a.GetAddress())
		}
		keys := make([]RLPItem, 0, len(a.GetStoredKeys()))
		for _, k := range a.GetStoredKeys() {
			if len(k) != 32 {
				return RLPItem{}, fmt.Errorf("%w: ethereum: access-list storage key must be 32 bytes, got %d", ErrTxInput, len(k))
			}
			keys = append(keys, RLPString(k))
		}
		entries = append(entries, RLPList(RLPString(addr), RLPList(keys...)))
	}
	return RLPList(entries...), nil
}

// ethDestination resolves the (to, value, data) triple from the SigningInput's
// Transaction payload. to is the 20-byte recipient/contract address.
func ethDestination(in *txeth.SigningInput) (to, value, data []byte, err error) {
	tx := in.GetTransaction()
	if tx == nil {
		return nil, nil, nil, fmt.Errorf("%w: ethereum: missing transaction", ErrTxInput)
	}
	switch {
	case tx.GetTransfer() != nil:
		t := tx.GetTransfer()
		addr, aerr := hexToBytes(in.GetToAddress())
		if aerr != nil || len(addr) != 20 {
			return nil, nil, nil, fmt.Errorf("%w: ethereum: bad to_address", ErrTxInput)
		}
		return addr, append([]byte(nil), t.GetAmount()...), append([]byte(nil), t.GetData()...), nil
	case tx.GetErc20Transfer() != nil:
		t := tx.GetErc20Transfer()
		contract, cerr := hexToBytes(in.GetToAddress())
		if cerr != nil || len(contract) != 20 {
			return nil, nil, nil, fmt.Errorf("%w: ethereum: bad token contract to_address", ErrTxInput)
		}
		recipient, rerr := hexToBytes(t.GetTo())
		if rerr != nil || len(recipient) != 20 {
			return nil, nil, nil, fmt.Errorf("%w: ethereum: bad erc20 recipient", ErrTxInput)
		}
		calldata, derr := ABIEncode("transfer", []ABIValue{
			{Type: "address", Value: recipient},
			{Type: "uint256", Value: new(big.Int).SetBytes(t.GetAmount())},
		})
		if derr != nil {
			return nil, nil, nil, fmt.Errorf("%w: ethereum: erc20 abi: %v", ErrTxInput, derr)
		}
		// ERC-20 transfers move zero native value; the contract is the destination.
		return contract, nil, calldata, nil
	case tx.GetContractGeneric() != nil:
		t := tx.GetContractGeneric()
		// An empty to_address means contract creation (deploy): `to` is left
		// empty (RLP 0x80) and `data` is the init code. A non-empty to_address is
		// an arbitrary contract call.
		var addr []byte
		if hexAddr := in.GetToAddress(); hexAddr != "" {
			a, aerr := hexToBytes(hexAddr)
			if aerr != nil || len(a) != 20 {
				return nil, nil, nil, fmt.Errorf("%w: ethereum: bad contract to_address", ErrTxInput)
			}
			addr = a
		}
		return addr, append([]byte(nil), t.GetAmount()...), append([]byte(nil), t.GetData()...), nil
	default:
		return nil, nil, nil, fmt.Errorf("%w: ethereum: empty transaction payload", ErrTxInput)
	}
}

// signEthereumLegacy produces an EIP-155 legacy transaction.
func (w *HDWallet) signEthereumLegacy(symbol Symbol, index uint32, in *txeth.SigningInput, to, value, data []byte) (*txeth.SigningOutput, error) {
	chainID := new(big.Int).SetBytes(in.GetChainId())

	// Preimage list: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0].
	preList := RLPList(
		ethQuantity(in.GetNonce()),
		ethQuantity(in.GetGasPrice()),
		ethQuantity(in.GetGasLimit()),
		RLPString(to),
		ethQuantity(value),
		RLPString(data),
		ethQuantity(in.GetChainId()),
		RLPString(nil),
		RLPString(nil),
	)
	digest := keccak256(EncodeRLP(preList))

	r, s, recid, err := w.ethSign(symbol, index, digest)
	if err != nil {
		return nil, err
	}

	// EIP-155 v = recid + chainId*2 + 35.
	v := new(big.Int).Add(big.NewInt(int64(recid)), big.NewInt(35))
	v.Add(v, new(big.Int).Lsh(chainID, 1))

	signed := RLPList(
		ethQuantity(in.GetNonce()),
		ethQuantity(in.GetGasPrice()),
		ethQuantity(in.GetGasLimit()),
		RLPString(to),
		ethQuantity(value),
		RLPString(data),
		RLPString(v.Bytes()),
		RLPString(r),
		RLPString(s),
	)
	encoded := EncodeRLP(signed)
	return ethOutput(encoded, r, s, v.Bytes()), nil
}

// signEthereumEIP2930 produces a type-1 (EIP-2930) access-list transaction. It
// is a legacy-shaped tx (gasPrice, not the 1559 fee market) wrapped in the typed
// 0x01 envelope, with the access list carried in the signed bytes and v as the
// bare recovery id.
func (w *HDWallet) signEthereumEIP2930(symbol Symbol, index uint32, in *txeth.SigningInput, to, value, data []byte) (*txeth.SigningOutput, error) {
	accessList, err := ethAccessList(in.GetAccessList())
	if err != nil {
		return nil, err
	}
	// payload: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList].
	fields := func(extra ...RLPItem) RLPItem {
		base := make([]RLPItem, 0, 8+len(extra))
		base = append(base,
			ethQuantity(in.GetChainId()),
			ethQuantity(in.GetNonce()),
			ethQuantity(in.GetGasPrice()),
			ethQuantity(in.GetGasLimit()),
			RLPString(to),
			ethQuantity(value),
			RLPString(data),
			accessList,
		)
		return RLPList(append(base, extra...)...)
	}
	preimage := append([]byte{0x01}, EncodeRLP(fields())...)
	digest := keccak256(preimage)

	r, s, recid, err := w.ethSign(symbol, index, digest)
	if err != nil {
		return nil, err
	}
	v := []byte{recid}
	signed := fields(ethQuantity(v), RLPString(r), RLPString(s))
	encoded := append([]byte{0x01}, EncodeRLP(signed)...)
	return ethOutput(encoded, r, s, v), nil
}

// signEthereumEIP1559 produces a type-2 (EIP-1559) transaction.
func (w *HDWallet) signEthereumEIP1559(symbol Symbol, index uint32, in *txeth.SigningInput, to, value, data []byte) (*txeth.SigningOutput, error) {
	accessList, err := ethAccessList(in.GetAccessList())
	if err != nil {
		return nil, err
	}
	// payload: [chainId, nonce, maxPriority, maxFee, gasLimit, to, value, data, accessList].
	fields := func(extra ...RLPItem) RLPItem {
		base := make([]RLPItem, 0, 9+len(extra))
		base = append(base,
			ethQuantity(in.GetChainId()),
			ethQuantity(in.GetNonce()),
			ethQuantity(in.GetMaxInclusionFeePerGas()),
			ethQuantity(in.GetMaxFeePerGas()),
			ethQuantity(in.GetGasLimit()),
			RLPString(to),
			ethQuantity(value),
			RLPString(data),
			accessList,
		)
		return RLPList(append(base, extra...)...)
	}
	preimage := append([]byte{0x02}, EncodeRLP(fields())...)
	digest := keccak256(preimage)

	r, s, recid, err := w.ethSign(symbol, index, digest)
	if err != nil {
		return nil, err
	}

	// type-2 v is the bare recovery id (0 or 1).
	v := []byte{recid}
	signed := fields(ethQuantity(v), RLPString(r), RLPString(s))
	encoded := append([]byte{0x02}, EncodeRLP(signed)...)
	return ethOutput(encoded, r, s, v), nil
}

// ethSign signs a 32-byte digest and returns the canonical R, S (32-byte each)
// and the recovery id (0/1).
func (w *HDWallet) ethSign(symbol Symbol, index uint32, digest []byte) (r, s []byte, recid byte, err error) {
	sig, err := w.SignIndex(symbol, index, digest)
	if err != nil {
		return nil, nil, 0, err
	}
	rec := sig.Recoverable()
	if rec == nil {
		return nil, nil, 0, fmt.Errorf("%w: %s is not a secp256k1 coin", ErrTxInput, symbol)
	}
	return append([]byte(nil), rec[:32]...), append([]byte(nil), rec[32:64]...), rec[64], nil
}

// ethQuantity encodes a big-endian byte quantity as an RLP integer: leading zero
// bytes are stripped so the value is minimal (RLP/Ethereum require this), and an
// all-zero or empty value encodes as the empty string (0x80).
func ethQuantity(b []byte) RLPItem {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return RLPString(b[i:])
}

// ethOutput assembles the SigningOutput for a signed EVM transaction. The tx id
// is the canonical Ethereum tx hash, "0x" + hex(keccak256(encoded)); for typed
// (EIP-2930/1559) txs the keccak is over the type-prefixed encoded bytes, which
// is exactly what `encoded` already holds.
func ethOutput(encoded, r, s, v []byte) *txeth.SigningOutput {
	return &txeth.SigningOutput{
		Encoded:    encoded,
		R:          r,
		S:          s,
		V:          v,
		EncodedHex: bytesToHex(encoded),
		TxId:       "0x" + bytesToHex(keccak256(encoded)),
	}
}

// signEthereumEIP4844 produces a type-3 (EIP-4844) blob transaction. It is an
// EIP-1559-shaped tx with two additional fields: max_fee_per_blob_gas and a list
// of blob_versioned_hashes. The hashes must be exactly 32 bytes each and are
// encoded as fixed-length strings (NOT quantity-minimized), matching the
// common.Hash RLP convention in go-ethereum. At least one hash is required.
// Network-wrapper blobs/commitments/proofs are out of scope; only the tx
// envelope is signed.
//
// Layout: 0x03 || rlp([chainId, nonce, maxPriority, maxFee, gasLimit, to,
//
//	value, data, accessList, maxFeePerBlobGas, blobVersionedHashes, v, r, s])
func (w *HDWallet) signEthereumEIP4844(symbol Symbol, index uint32, in *txeth.SigningInput, to, value, data []byte) (*txeth.SigningOutput, error) {
	blobHashes := in.GetBlobVersionedHashes()
	if len(blobHashes) == 0 {
		return nil, fmt.Errorf("%w: %s eip-4844: at least one blob_versioned_hash is required", ErrTxInput, symbol)
	}
	for i, h := range blobHashes {
		if len(h) != 32 {
			return nil, fmt.Errorf("%w: %s eip-4844: blob_versioned_hash[%d] must be 32 bytes, got %d", ErrTxInput, symbol, i, len(h))
		}
	}
	if len(in.GetMaxFeePerBlobGas()) == 0 {
		return nil, fmt.Errorf("%w: %s eip-4844: max_fee_per_blob_gas is required", ErrTxInput, symbol)
	}

	accessList, err := ethAccessList(in.GetAccessList())
	if err != nil {
		return nil, err
	}

	// blob_versioned_hashes: each hash is a fixed 32-byte blob, NOT quantity-minimized.
	hashItems := make([]RLPItem, len(blobHashes))
	for i, h := range blobHashes {
		hashItems[i] = RLPString(append([]byte(nil), h...))
	}
	blobHashList := RLPList(hashItems...)

	// payload: [chainId, nonce, maxPriority, maxFee, gasLimit, to, value, data,
	//           accessList, maxFeePerBlobGas, blobVersionedHashes].
	fields := func(extra ...RLPItem) RLPItem {
		base := make([]RLPItem, 0, 11+len(extra))
		base = append(base,
			ethQuantity(in.GetChainId()),
			ethQuantity(in.GetNonce()),
			ethQuantity(in.GetMaxInclusionFeePerGas()),
			ethQuantity(in.GetMaxFeePerGas()),
			ethQuantity(in.GetGasLimit()),
			RLPString(to),
			ethQuantity(value),
			RLPString(data),
			accessList,
			ethQuantity(in.GetMaxFeePerBlobGas()),
			blobHashList,
		)
		return RLPList(append(base, extra...)...)
	}
	preimage := append([]byte{0x03}, EncodeRLP(fields())...)
	digest := keccak256(preimage)

	r, s, recid, err := w.ethSign(symbol, index, digest)
	if err != nil {
		return nil, err
	}
	v := []byte{recid}
	signed := fields(ethQuantity(v), RLPString(r), RLPString(s))
	encoded := append([]byte{0x03}, EncodeRLP(signed)...)
	return ethOutput(encoded, r, s, v), nil
}

// signEthereumEIP7702 produces a type-4 (EIP-7702) set-code transaction. It is
// an EIP-1559-shaped tx with an additional authorization_list field. Each
// authorization carries a pre-signed delegation tuple
// [chain_id, address, nonce, y_parity, r, s] that was signed off-band by the
// EOA that wants to delegate its code to a contract address. The tx signer
// (wallet key) does NOT sign the individual authorization tuples. At least one
// authorization is required.
//
// Authorization RLP tuple: [chain_id (qty), address (20 bytes fixed), nonce
// (qty), y_parity (qty), r (qty), s (qty)].
//
// Layout: 0x04 || rlp([chainId, nonce, maxPriority, maxFee, gasLimit, to,
//
//	value, data, accessList, authorizationList, v, r, s])
func (w *HDWallet) signEthereumEIP7702(symbol Symbol, index uint32, in *txeth.SigningInput, to, value, data []byte) (*txeth.SigningOutput, error) {
	authList := in.GetAuthorizationList()
	if len(authList) == 0 {
		return nil, fmt.Errorf("%w: %s eip-7702: authorization_list must not be empty", ErrTxInput, symbol)
	}

	accessList, err := ethAccessList(in.GetAccessList())
	if err != nil {
		return nil, err
	}

	authorizationList, err := ethAuthorizationList(authList, symbol)
	if err != nil {
		return nil, err
	}

	// payload: [chainId, nonce, maxPriority, maxFee, gasLimit, to, value, data,
	//           accessList, authorizationList].
	fields := func(extra ...RLPItem) RLPItem {
		base := make([]RLPItem, 0, 10+len(extra))
		base = append(base,
			ethQuantity(in.GetChainId()),
			ethQuantity(in.GetNonce()),
			ethQuantity(in.GetMaxInclusionFeePerGas()),
			ethQuantity(in.GetMaxFeePerGas()),
			ethQuantity(in.GetGasLimit()),
			RLPString(to),
			ethQuantity(value),
			RLPString(data),
			accessList,
			authorizationList,
		)
		return RLPList(append(base, extra...)...)
	}
	preimage := append([]byte{0x04}, EncodeRLP(fields())...)
	digest := keccak256(preimage)

	r, s, recid, err := w.ethSign(symbol, index, digest)
	if err != nil {
		return nil, err
	}
	v := []byte{recid}
	signed := fields(ethQuantity(v), RLPString(r), RLPString(s))
	encoded := append([]byte{0x04}, EncodeRLP(signed)...)
	return ethOutput(encoded, r, s, v), nil
}

// ethAuthorizationList builds the RLP item for an EIP-7702 authorization list.
// Each entry is encoded as a list:
//
//	[chain_id (qty), address (20 bytes fixed), nonce (qty), y_parity (qty),
//	 r (qty), s (qty)]
//
// The address is a fixed-size 20-byte string (NOT quantity-minimized). The
// nonce is a uint64 quantity. The y_parity is 0 or 1 as a quantity. The r and
// s components are big-endian scalars (quantity-minimized, matching go-ethereum
// *big.Int RLP encoding).
func ethAuthorizationList(auths []*txeth.EthAuthorization, symbol Symbol) (RLPItem, error) {
	entries := make([]RLPItem, 0, len(auths))
	for i, a := range auths {
		addr, err := hexToBytes(a.GetAddress())
		if err != nil || len(addr) != 20 {
			return RLPItem{}, fmt.Errorf("%w: %s eip-7702: authorization[%d]: bad address %q", ErrTxInput, symbol, i, a.GetAddress())
		}
		// nonce: uint64 → big-endian bytes → quantity (strip leading zeros).
		nonceBytes := new(big.Int).SetUint64(a.GetNonce()).Bytes()

		// y_parity: 0 or 1 as a quantity (0 → empty, 1 → [0x01]).
		var yParityByte byte
		if a.GetYParity() != 0 {
			yParityByte = 1
		}

		entry := RLPList(
			ethQuantity(a.GetChainId()),      // chain_id: quantity
			RLPString(addr),                  // address: fixed 20 bytes (NOT quantity)
			ethQuantity(nonceBytes),          // nonce: quantity
			ethQuantity([]byte{yParityByte}), // y_parity: quantity
			ethQuantity(a.GetR()),            // r: quantity (big-endian scalar)
			ethQuantity(a.GetS()),            // s: quantity (big-endian scalar)
		)
		entries = append(entries, entry)
	}
	return RLPList(entries...), nil
}
