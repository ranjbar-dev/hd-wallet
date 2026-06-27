package hdwallet

// "What am I signing?" decoder for Cardano (Shelley/Babbage) transactions.
//
// A Cardano transaction is CBOR-encoded:
//   [transaction_body, transaction_witness_set, bool, transaction_metadata]
//
// The transaction_body is a CBOR map keyed by unsigned integers:
//   0 = inputs  ([tx_hash(bytes,32), output_index(uint)])
//   1 = outputs ([address(bytes), coin_or_value])
//   2 = fee     (uint, lovelace)
//   3 = ttl     (uint, optional)
//
// Supports the Shelley legacy array output format [address, coin_or_multiasset]
// and the post-Babbage map format {0: address, 1: value, ...}.
//
// This file is display-only and adds no signer/registry/proto changes.

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// CardanoTxInput is one Cardano transaction input.
type CardanoTxInput struct {
	TxHash string // hex-encoded 32 bytes
	Index  uint32
}

// CardanoTxOutput is one Cardano transaction output.
type CardanoTxOutput struct {
	Address string // hex-encoded address bytes
	Coin    uint64 // lovelace
}

// CardanoTxFields holds the decoded display fields from a Cardano transaction.
type CardanoTxFields struct {
	Inputs  []CardanoTxInput
	Outputs []CardanoTxOutput
	Fee     uint64
	TTL     uint64 // 0 = not set
}

// DecodeCardanoTx decodes a CBOR-encoded Cardano transaction array
// [transaction_body, transaction_witness_set, bool, transaction_metadata].
// Returns ErrTxDecode on malformed input; never panics.
func DecodeCardanoTx(raw []byte) (*CardanoTxFields, error) {
	var outer []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &outer); err != nil {
		return nil, fmt.Errorf("%w: cardano: %v", ErrTxDecode, err)
	}
	if len(outer) < 1 {
		return nil, fmt.Errorf("%w: cardano: empty outer array", ErrTxDecode)
	}

	var body map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(outer[0], &body); err != nil {
		return nil, fmt.Errorf("%w: cardano: body: %v", ErrTxDecode, err)
	}

	f := &CardanoTxFields{}
	if v, ok := body[0]; ok {
		if err := cardanoDecodeInputs(v, f); err != nil {
			return nil, err
		}
	}
	if v, ok := body[1]; ok {
		if err := cardanoDecodeOutputs(v, f); err != nil {
			return nil, err
		}
	}
	if v, ok := body[2]; ok {
		if err := cbor.Unmarshal(v, &f.Fee); err != nil {
			return nil, fmt.Errorf("%w: cardano: fee: %v", ErrTxDecode, err)
		}
	}
	if v, ok := body[3]; ok {
		if err := cbor.Unmarshal(v, &f.TTL); err != nil {
			return nil, fmt.Errorf("%w: cardano: ttl: %v", ErrTxDecode, err)
		}
	}
	return f, nil
}

func cardanoDecodeInputs(raw cbor.RawMessage, f *CardanoTxFields) error {
	var rawInputs []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &rawInputs); err != nil {
		return fmt.Errorf("%w: cardano: inputs: %v", ErrTxDecode, err)
	}
	for _, ri := range rawInputs {
		var pair []cbor.RawMessage
		if err := cbor.Unmarshal(ri, &pair); err != nil || len(pair) != 2 {
			return fmt.Errorf("%w: cardano: input: expected 2-element array", ErrTxDecode)
		}
		var txHash []byte
		if err := cbor.Unmarshal(pair[0], &txHash); err != nil {
			return fmt.Errorf("%w: cardano: input tx_hash: %v", ErrTxDecode, err)
		}
		if len(txHash) != 32 {
			return fmt.Errorf("%w: cardano: input tx_hash must be 32 bytes, got %d", ErrTxDecode, len(txHash))
		}
		var idx uint32
		if err := cbor.Unmarshal(pair[1], &idx); err != nil {
			return fmt.Errorf("%w: cardano: input index: %v", ErrTxDecode, err)
		}
		f.Inputs = append(f.Inputs, CardanoTxInput{
			TxHash: bytesToHex(txHash),
			Index:  idx,
		})
	}
	return nil
}

func cardanoDecodeOutputs(raw cbor.RawMessage, f *CardanoTxFields) error {
	var rawOutputs []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &rawOutputs); err != nil {
		return fmt.Errorf("%w: cardano: outputs: %v", ErrTxDecode, err)
	}
	for _, ro := range rawOutputs {
		out, err := decodeCardanoOutput(ro)
		if err != nil {
			return err
		}
		f.Outputs = append(f.Outputs, out)
	}
	return nil
}

// decodeCardanoOutput handles the Shelley legacy array format [address, value] and
// the post-Babbage map format {0: address, 1: value}.
func decodeCardanoOutput(raw cbor.RawMessage) (CardanoTxOutput, error) {
	var pair []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &pair); err == nil && len(pair) == 2 {
		var addr []byte
		if err := cbor.Unmarshal(pair[0], &addr); err != nil {
			return CardanoTxOutput{}, fmt.Errorf("%w: cardano: output address: %v", ErrTxDecode, err)
		}
		coin, err := cardanoExtractCoin(pair[1])
		if err != nil {
			return CardanoTxOutput{}, err
		}
		return CardanoTxOutput{Address: bytesToHex(addr), Coin: coin}, nil
	}
	// Post-Babbage map: {0: address_bytes, 1: value, ...}
	var m map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(raw, &m); err != nil {
		return CardanoTxOutput{}, fmt.Errorf("%w: cardano: output: %v", ErrTxDecode, err)
	}
	var addr []byte
	if v, ok := m[0]; ok {
		if err := cbor.Unmarshal(v, &addr); err != nil {
			return CardanoTxOutput{}, fmt.Errorf("%w: cardano: output address: %v", ErrTxDecode, err)
		}
	}
	var coin uint64
	if v, ok := m[1]; ok {
		var err error
		coin, err = cardanoExtractCoin(v)
		if err != nil {
			return CardanoTxOutput{}, err
		}
	}
	return CardanoTxOutput{Address: bytesToHex(addr), Coin: coin}, nil
}

// cardanoExtractCoin pulls the lovelace amount from a Cardano output value.
// The value is either a bare uint (Ada only) or [uint, multiasset_map].
func cardanoExtractCoin(raw cbor.RawMessage) (uint64, error) {
	var coin uint64
	if err := cbor.Unmarshal(raw, &coin); err == nil {
		return coin, nil
	}
	// Multi-asset: [coin, {policyId -> {name -> amount}}]
	var ma []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &ma); err != nil || len(ma) < 1 {
		return 0, fmt.Errorf("%w: cardano: unrecognised output value format", ErrTxDecode)
	}
	if err := cbor.Unmarshal(ma[0], &coin); err != nil {
		return 0, fmt.Errorf("%w: cardano: output coin: %v", ErrTxDecode, err)
	}
	return coin, nil
}
