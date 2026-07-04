package hdwallet

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

// These tests exercise paths not covered by the per-feature vector tests: the
// ABI array/tuple/signed-int/dynamic-bytes codec branches, the EIP-712 signing
// method, and a few small helpers. They are round-trip / property tests where an
// authoritative external vector isn't the point (the vector tests cover those).

// --- ABI: arrays, tuples, signed ints, fixed/dynamic bytes round-trips ---

func TestABIDynamicArrayRoundTrip(t *testing.T) {
	// uint256[] with three values.
	vals := []ABIValue{{
		Type: "uint256[]",
		Value: []ABIValue{
			{Type: "uint256", Value: big.NewInt(1)},
			{Type: "uint256", Value: big.NewInt(2)},
			{Type: "uint256", Value: big.NewInt(0x1234)},
		},
	}}
	enc, err := ABIEncodeParams(vals)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := ABIDecodeParams([]string{"uint256[]"}, enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := out[0].Value.([]ABIValue)
	if len(got) != 3 || got[2].Value.(*big.Int).Int64() != 0x1234 {
		t.Fatalf("dynamic array round-trip mismatch: %+v", got)
	}
}

func TestABIFixedArrayRoundTrip(t *testing.T) {
	vals := []ABIValue{{
		Type: "uint256[2]",
		Value: []ABIValue{
			{Type: "uint256", Value: big.NewInt(7)},
			{Type: "uint256", Value: big.NewInt(8)},
		},
	}}
	enc, err := ABIEncodeParams(vals)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := ABIDecodeParams([]string{"uint256[2]"}, enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := out[0].Value.([]ABIValue)
	if len(got) != 2 || got[0].Value.(*big.Int).Int64() != 7 || got[1].Value.(*big.Int).Int64() != 8 {
		t.Fatalf("fixed array round-trip mismatch: %+v", got)
	}
}

func TestABITupleRoundTrip(t *testing.T) {
	addr, _ := hex.DecodeString("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
	// (address,uint256,bytes) — mixes static and dynamic fields.
	vals := []ABIValue{{
		Type: "(address,uint256,bytes)",
		Value: []ABIValue{
			{Type: "address", Value: addr},
			{Type: "uint256", Value: big.NewInt(99)},
			{Type: "bytes", Value: []byte("hello world payload")},
		},
	}}
	enc, err := ABIEncodeParams(vals)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := ABIDecodeParams([]string{"(address,uint256,bytes)"}, enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	fields := out[0].Value.([]ABIValue)
	if !bytes.Equal(fields[0].Value.([]byte), addr) {
		t.Errorf("tuple address mismatch")
	}
	if fields[1].Value.(*big.Int).Int64() != 99 {
		t.Errorf("tuple uint mismatch")
	}
	if string(fields[2].Value.([]byte)) != "hello world payload" {
		t.Errorf("tuple bytes mismatch: %q", fields[2].Value.([]byte))
	}
}

func TestABISignedIntRoundTrip(t *testing.T) {
	for _, n := range []int64{0, 1, -1, 127, -128, 1 << 40, -(1 << 40)} {
		vals := []ABIValue{{Type: "int256", Value: big.NewInt(n)}}
		enc, err := ABIEncodeParams(vals)
		if err != nil {
			t.Fatalf("encode %d: %v", n, err)
		}
		out, err := ABIDecodeParams([]string{"int256"}, enc)
		if err != nil {
			t.Fatalf("decode %d: %v", n, err)
		}
		if got := out[0].Value.(*big.Int).Int64(); got != n {
			t.Errorf("int256 round-trip: got %d, want %d", got, n)
		}
	}
}

func TestABIFixedBytesRoundTrip(t *testing.T) {
	raw := make([]byte, 4)
	copy(raw, []byte{0xde, 0xad, 0xbe, 0xef})
	vals := []ABIValue{{Type: "bytes4", Value: raw}}
	enc, err := ABIEncodeParams(vals)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := ABIDecodeParams([]string{"bytes4"}, enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(out[0].Value.([]byte), raw) {
		t.Fatalf("bytes4 round-trip mismatch: %x", out[0].Value.([]byte))
	}
	// fixedBytesSize rejects out-of-range sizes.
	if _, err := ABIEncodeParams([]ABIValue{{Type: "bytes33", Value: make([]byte, 33)}}); err == nil {
		t.Error("bytes33 should be rejected (1..32)")
	}
}

// --- EIP-712 signing method (SignTypedData) end-to-end ---

func TestSignTypedDataRecoversToWalletAddress(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	sig, err := w.SignTypedData(ETH, 0, []byte(eip712MailExample))
	if err != nil {
		t.Fatalf("SignTypedData: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65", len(sig))
	}
	addr, err := w.Address(ETH)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEthereumTypedData(addr, []byte(eip712MailExample), sig) {
		t.Fatalf("typed-data signature did not recover to %s", addr)
	}
}

// parseLooseBool path: a bool transmitted as the string "true".
func TestEIP712LooseBool(t *testing.T) {
	const td = `{
      "types": {
        "EIP712Domain": [{"name":"name","type":"string"}],
        "Flag": [{"name":"on","type":"bool"}]
      },
      "primaryType": "Flag",
      "domain": {"name": "X"},
      "message": {"on": "true"}
    }`
	if _, err := EIP712Hash([]byte(td)); err != nil {
		t.Fatalf("EIP712Hash with loose bool: %v", err)
	}
}

// --- small helpers ---

func TestGenerateMnemonicValid(t *testing.T) {
	mn, err := GenerateMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	w, err := FromMnemonic(mn)
	if err != nil {
		t.Fatalf("generated mnemonic failed to import: %v", err)
	}
	w.Destroy()
}

func TestChainIsValid(t *testing.T) {
	if !ETH.IsValid() {
		t.Error("ETH should be valid")
	}
	if Chain("NOPE").IsValid() {
		t.Error("NOPE should be invalid")
	}
}
