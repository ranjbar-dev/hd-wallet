package hdwallet

import (
	"fmt"
	"math/big"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// Ethereum / EVM transaction signing.
//
// Three transaction formats are produced, selected by SigningInput.tx_mode:
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
//
// The optional EIP-2930 access list (SigningInput.access_list) is carried in the
// signed bytes for tx_mode 1 and 2; an empty list reproduces the no-access-list
// encoding byte-for-byte (so the existing legacy/1559 vectors are unaffected).
//
// The destination/value/data triple is built from the Transaction payload:
//   - Transfer: to = SigningInput.to_address, value = amount, data = data.
//   - ERC20Transfer: to = SigningInput.to_address (the token contract), value = 0,
//     data = transfer(recipient, amount) ABI calldata.
//
// Verified byte-for-byte against Trust Wallet Core's Ethereum AnySigner vectors
// (legacy native, legacy ERC-20, EIP-1559 ERC-20, EIP-1559 native+data); see
// tx_ethereum_test.go.

// signEthereumTx builds, signs and serializes an EVM transaction.
func (w *HDWallet) signEthereumTx(symbol Symbol, index uint32, in *txeth.SigningInput) (*txeth.SigningOutput, error) {
	to, value, data, err := ethDestination(in)
	if err != nil {
		return nil, err
	}
	switch in.GetTxMode() {
	case 0:
		return w.signEthereumLegacy(symbol, index, in, to, value, data)
	case 1:
		return w.signEthereumEIP2930(symbol, index, in, to, value, data)
	case 2:
		return w.signEthereumEIP1559(symbol, index, in, to, value, data)
	default:
		return nil, fmt.Errorf("%w: %s unsupported tx_mode %d (want 0 legacy, 1 eip-2930 or 2 eip-1559)", ErrTxInput, symbol, in.GetTxMode())
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

// ethOutput assembles the SigningOutput for a signed EVM transaction.
func ethOutput(encoded, r, s, v []byte) *txeth.SigningOutput {
	return &txeth.SigningOutput{
		Encoded:    encoded,
		R:          r,
		S:          s,
		V:          v,
		EncodedHex: bytesToHex(encoded),
	}
}
