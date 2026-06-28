package hdwallet

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// DecodeCardanoTx proven by:
//   - round-trip: build a minimal Cardano tx body with cbor.Marshal, assert
//     DecodeCardanoTx returns exactly the same inputs/outputs/fee/ttl.
//   - multi-asset output: value as [coin, multiasset_map] — extract coin only.
//   - malformed: empty/non-CBOR/wrong types return ErrTxDecode, never panic.

func buildCardanoTx(t *testing.T, body interface{}) []byte {
	t.Helper()
	outer := []interface{}{body, map[string]interface{}{}, true, nil}
	raw, err := cbor.Marshal(outer)
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	return raw
}

func TestDecodeCardanoTxRoundTrip(t *testing.T) {
	txHash := make([]byte, 32)
	for i := range txHash {
		txHash[i] = byte(i + 1)
	}
	addrBytes := make([]byte, 29)
	addrBytes[0] = 0x61 // enterprise mainnet prefix

	body := map[uint64]interface{}{
		0: []interface{}{[]interface{}{txHash, uint64(1)}},
		1: []interface{}{[]interface{}{addrBytes, uint64(2000000)}},
		2: uint64(170000),
		3: uint64(100),
	}
	raw := buildCardanoTx(t, body)

	f, err := DecodeCardanoTx(raw)
	if err != nil {
		t.Fatalf("DecodeCardanoTx: %v", err)
	}

	if len(f.Inputs) != 1 {
		t.Fatalf("inputs = %d, want 1", len(f.Inputs))
	}
	if f.Inputs[0].TxHash != bytesToHex(txHash) {
		t.Fatalf("input tx_hash = %s, want %s", f.Inputs[0].TxHash, bytesToHex(txHash))
	}
	if f.Inputs[0].Index != 1 {
		t.Fatalf("input index = %d, want 1", f.Inputs[0].Index)
	}

	if len(f.Outputs) != 1 {
		t.Fatalf("outputs = %d, want 1", len(f.Outputs))
	}
	if f.Outputs[0].Address != bytesToHex(addrBytes) {
		t.Fatalf("output address = %s, want %s", f.Outputs[0].Address, bytesToHex(addrBytes))
	}
	if f.Outputs[0].Coin != 2000000 {
		t.Fatalf("output coin = %d, want 2000000", f.Outputs[0].Coin)
	}

	if f.Fee != 170000 {
		t.Fatalf("fee = %d, want 170000", f.Fee)
	}
	if f.TTL != 100 {
		t.Fatalf("ttl = %d, want 100", f.TTL)
	}
}

func TestDecodeCardanoTxMultiAssetOutput(t *testing.T) {
	addr := make([]byte, 29)
	addr[0] = 0x71
	// Multi-asset value: [coin, multiasset_map] — use an empty map for the asset
	// portion since cardanoExtractCoin only reads the first element (the coin).
	multiAssetValue := []interface{}{
		uint64(3000000),
		map[string]interface{}{}, // simplified multiasset (cbor encodes as text-key map)
	}
	body := map[uint64]interface{}{
		0: []interface{}{[]interface{}{make([]byte, 32), uint64(0)}},
		1: []interface{}{[]interface{}{addr, multiAssetValue}},
		2: uint64(200000),
	}
	raw := buildCardanoTx(t, body)

	f, err := DecodeCardanoTx(raw)
	if err != nil {
		t.Fatalf("DecodeCardanoTx multiasset: %v", err)
	}
	if len(f.Outputs) != 1 {
		t.Fatalf("outputs = %d, want 1", len(f.Outputs))
	}
	if f.Outputs[0].Coin != 3000000 {
		t.Fatalf("coin = %d, want 3000000", f.Outputs[0].Coin)
	}
}

func TestDecodeCardanoTxMalformed(t *testing.T) {
	badBody, _ := cbor.Marshal([]interface{}{uint64(0)})

	cases := map[string][]byte{
		"empty":        {},
		"not cbor":     {0xff, 0xff},
		"not array":    {0xa0},  // CBOR empty map, not an array
		"body not map": badBody, // array containing an integer, not a map
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCardanoTx(b); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}
