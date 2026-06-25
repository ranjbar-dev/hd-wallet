package hdwallet

// "What am I signing?" decoder for Tron transactions.
//
// DecodeTronTx parses a raw_data protobuf blob (the SigningOutput.RawData the
// tx_tron.go signer produces and signs over) back into its plain fields so a
// client can render a confirmation screen WITHOUT touching a private key or any
// secret. It is the inverse of tronRawData / tronContractMsg:
//
//	raw_data {
//	  1: ref_block_bytes  4: ref_block_hash  8: expiration
//	  11: contract (repeated)  14: timestamp  18: fee_limit
//	}
//	Contract { 1: type, 2: parameter Any { 1: type_url, 2: value } }
//	  TransferContract      { 1: owner, 2: to, 3: amount }
//	  TriggerSmartContract  { 1: owner, 2: contract, 4: data }
//
// It reuses the shared protobuf walker pbParse (tx_decode_cosmos.go) and renders
// the 21-byte (0x41 || hash160) Tron addresses back to their base58check "T..."
// form via base58CheckEncode (the reverse of tronAddressBytes).
//
// This file adds no signer/registry/proto changes; it is display-only. Malformed
// or truncated input returns ErrTxDecode and the decoder never panics.

import "fmt"

// TronContract is one decoded contract entry. Type is the Tron ContractType enum
// value; the populated fields depend on it.
type TronContract struct {
	Type     int32  // 1 = TransferContract, 31 = TriggerSmartContract
	TypeName string // "TransferContract" / "TriggerSmartContract" / "" (unknown)
	TypeURL  string // the google.protobuf.Any type_url

	OwnerAddress string // base58check "T..." address

	// TransferContract.
	ToAddress string // base58check "T..." address
	Amount    int64

	// TriggerSmartContract.
	ContractAddress string // base58check "T..." address
	Data            []byte // raw call data (e.g. TRC-20 transfer calldata)
}

// TronTxFields holds the decoded, display-ready fields of a Tron transaction's
// raw_data.
type TronTxFields struct {
	RefBlockBytes []byte
	RefBlockHash  []byte
	Expiration    int64
	Timestamp     int64
	FeeLimit      int64 // 0 when absent
	Contracts     []TronContract
}

// DecodeTronTx decodes a raw_data protobuf blob into its display fields. Malformed
// or truncated input returns ErrTxDecode; the function never panics.
func DecodeTronTx(raw []byte) (*TronTxFields, error) {
	fields, err := pbParse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: tron: %v", ErrTxDecode, err)
	}

	f := &TronTxFields{}
	if b, ok := pbFieldBytes(fields, 1); ok {
		f.RefBlockBytes = append([]byte(nil), b...)
	}
	if b, ok := pbFieldBytes(fields, 4); ok {
		f.RefBlockHash = append([]byte(nil), b...)
	}
	if v, ok := pbFieldVarint(fields, 8); ok {
		f.Expiration = int64(v) // #nosec G115 -- protobuf int64 varint bit-reinterpretation
	}
	if v, ok := pbFieldVarint(fields, 14); ok {
		f.Timestamp = int64(v) // #nosec G115 -- protobuf int64 varint bit-reinterpretation
	}
	if v, ok := pbFieldVarint(fields, 18); ok {
		f.FeeLimit = int64(v) // #nosec G115 -- protobuf int64 varint bit-reinterpretation
	}

	for _, cb := range pbFieldAll(fields, 11) {
		c, err := decodeTronContract(cb)
		if err != nil {
			return nil, err
		}
		f.Contracts = append(f.Contracts, c)
	}
	if len(f.Contracts) == 0 {
		return nil, fmt.Errorf("%w: tron: no contract in raw_data", ErrTxDecode)
	}
	return f, nil
}

// decodeTronContract decodes one Contract { 1: type, 2: Any } message.
func decodeTronContract(b []byte) (TronContract, error) {
	fields, err := pbParse(b)
	if err != nil {
		return TronContract{}, fmt.Errorf("%w: tron contract: %v", ErrTxDecode, err)
	}
	ctype, _ := pbFieldVarint(fields, 1)
	anyBytes, ok := pbFieldBytes(fields, 2)
	if !ok {
		return TronContract{}, fmt.Errorf("%w: tron contract: missing parameter", ErrTxDecode)
	}
	anyFields, err := pbParse(anyBytes)
	if err != nil {
		return TronContract{}, fmt.Errorf("%w: tron contract any: %v", ErrTxDecode, err)
	}
	typeURL := pbFieldString(anyFields, 1)
	value, ok := pbFieldBytes(anyFields, 2)
	if !ok {
		return TronContract{}, fmt.Errorf("%w: tron contract: missing value", ErrTxDecode)
	}

	c := TronContract{
		Type:    int32(ctype), // #nosec G115 -- ContractType enum, small positive value
		TypeURL: typeURL,
	}
	inner, err := pbParse(value)
	if err != nil {
		return TronContract{}, fmt.Errorf("%w: tron %s: %v", ErrTxDecode, typeURL, err)
	}

	switch ctype {
	case tronTransferType:
		c.TypeName = "TransferContract"
		ownerBytes, _ := pbFieldBytes(inner, 1)
		owner, err := tronRenderAddress(ownerBytes)
		if err != nil {
			return TronContract{}, fmt.Errorf("%w: tron transfer owner: %v", ErrTxDecode, err)
		}
		toBytes, _ := pbFieldBytes(inner, 2)
		to, err := tronRenderAddress(toBytes)
		if err != nil {
			return TronContract{}, fmt.Errorf("%w: tron transfer to: %v", ErrTxDecode, err)
		}
		amount, _ := pbFieldVarint(inner, 3)
		c.OwnerAddress = owner
		c.ToAddress = to
		c.Amount = int64(amount) // #nosec G115 -- protobuf int64 varint bit-reinterpretation
	case tronTriggerSmartContractType:
		c.TypeName = "TriggerSmartContract"
		ownerBytes, _ := pbFieldBytes(inner, 1)
		owner, err := tronRenderAddress(ownerBytes)
		if err != nil {
			return TronContract{}, fmt.Errorf("%w: tron trigger owner: %v", ErrTxDecode, err)
		}
		contractBytes, _ := pbFieldBytes(inner, 2)
		contract, err := tronRenderAddress(contractBytes)
		if err != nil {
			return TronContract{}, fmt.Errorf("%w: tron trigger contract: %v", ErrTxDecode, err)
		}
		c.OwnerAddress = owner
		c.ContractAddress = contract
		if data, ok := pbFieldBytes(inner, 4); ok {
			c.Data = append([]byte(nil), data...)
		}
	default:
		// Unknown contract type: surface type/url only.
	}
	return c, nil
}

// tronRenderAddress renders a 21-byte (0x41 || hash160) Tron address as its
// base58check "T..." form, the reverse of tronAddressBytes.
func tronRenderAddress(b []byte) (string, error) {
	if len(b) != 21 || b[0] != 0x41 {
		return "", fmt.Errorf("expected 21-byte 0x41-prefixed address, got %d bytes", len(b))
	}
	return base58CheckEncode(base58BTC, b[:1], b[1:]), nil
}
