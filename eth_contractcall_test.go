package hdwallet

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

// Vector 1: ERC-20 approve — pinned to TWC ContractCallTests.cpp
func TestDecodeContractCall_Approve(t *testing.T) {
	jsonABI := []byte(`[{"name":"approve","type":"function","inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}]}]`)
	abiMap, err := ParseContractABI(jsonABI)
	if err != nil {
		t.Fatalf("ParseContractABI: %v", err)
	}

	calldata := decodeHex(t, "095ea7b3"+
		"0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed"+
		"0000000000000000000000000000000000000000000000000000000000000001")

	var sel [4]byte
	copy(sel[:], calldata[:4])
	if sig := GetFunctionSignature(abiMap[sel]); sig != "approve(address,uint256)" {
		t.Fatalf("signature = %q, want %q", sig, "approve(address,uint256)")
	}

	funcName, params, err := DecodeContractCall(abiMap, calldata)
	if err != nil {
		t.Fatalf("DecodeContractCall: %v", err)
	}
	if funcName != "approve" {
		t.Fatalf("funcName = %q, want %q", funcName, "approve")
	}
	if len(params) != 2 {
		t.Fatalf("params len = %d, want 2", len(params))
	}

	if params[0].Name != "_spender" {
		t.Errorf("params[0].Name = %q, want %q", params[0].Name, "_spender")
	}
	wantSpender := decodeHex(t, "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
	gotSpender, ok := params[0].Value.([]byte)
	if !ok || !bytes.Equal(gotSpender, wantSpender) {
		t.Errorf("params[0].Value = %x, want %x", params[0].Value, wantSpender)
	}

	if params[1].Name != "_value" {
		t.Errorf("params[1].Name = %q, want %q", params[1].Name, "_value")
	}
	gotValue, ok := params[1].Value.(*big.Int)
	if !ok || gotValue.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("params[1].Value = %v, want 1", params[1].Value)
	}
}

// Vector 2: ERC-721 setApprovalForAll — pinned to TWC ContractCallTests.cpp
func TestDecodeContractCall_SetApprovalForAll(t *testing.T) {
	jsonABI := []byte(`[{"name":"setApprovalForAll","type":"function","inputs":[{"name":"to","type":"address"},{"name":"approved","type":"bool"}]}]`)
	abiMap, err := ParseContractABI(jsonABI)
	if err != nil {
		t.Fatalf("ParseContractABI: %v", err)
	}

	calldata := decodeHex(t, "a22cb465"+
		"00000000000000000000000088341d1a8f672d2780c8dc725902aae72f143b0c"+
		"0000000000000000000000000000000000000000000000000000000000000001")

	var sel [4]byte
	copy(sel[:], calldata[:4])
	if sig := GetFunctionSignature(abiMap[sel]); sig != "setApprovalForAll(address,bool)" {
		t.Fatalf("signature = %q, want %q", sig, "setApprovalForAll(address,bool)")
	}

	funcName, params, err := DecodeContractCall(abiMap, calldata)
	if err != nil {
		t.Fatalf("DecodeContractCall: %v", err)
	}
	if funcName != "setApprovalForAll" {
		t.Fatalf("funcName = %q, want %q", funcName, "setApprovalForAll")
	}
	if len(params) != 2 {
		t.Fatalf("params len = %d, want 2", len(params))
	}

	if params[0].Name != "to" {
		t.Errorf("params[0].Name = %q, want %q", params[0].Name, "to")
	}
	wantTo := decodeHex(t, "88341d1a8f672d2780c8dc725902aae72f143b0c")
	gotTo, ok := params[0].Value.([]byte)
	if !ok || !bytes.Equal(gotTo, wantTo) {
		t.Errorf("params[0].Value = %x, want %x", params[0].Value, wantTo)
	}

	if params[1].Name != "approved" {
		t.Errorf("params[1].Name = %q, want %q", params[1].Name, "approved")
	}
	gotApproved, ok := params[1].Value.(bool)
	if !ok || !gotApproved {
		t.Errorf("params[1].Value = %v, want true", params[1].Value)
	}
}

// Vector 3: setName(string,uint256,int32) round-trip — encode then decode.
func TestDecodeContractCall_SetNameRoundTrip(t *testing.T) {
	jsonABI := []byte(`[{"name":"setName","type":"function","inputs":[{"name":"name","type":"string"},{"name":"age","type":"uint256"},{"name":"height","type":"int32"}]}]`)
	abiMap, err := ParseContractABI(jsonABI)
	if err != nil {
		t.Fatalf("ParseContractABI: %v", err)
	}

	calldata, err := ABIEncode("setName", []ABIValue{
		{Type: "string", Value: []byte("trusty")},
		{Type: "uint256", Value: big.NewInt(3)},
		{Type: "int32", Value: big.NewInt(100)},
	})
	if err != nil {
		t.Fatalf("ABIEncode: %v", err)
	}

	if hex.EncodeToString(calldata[:4]) != hex.EncodeToString(ABIFunctionSelector("setName", []string{"string", "uint256", "int32"})) {
		t.Fatal("calldata selector does not match expected setName(string,uint256,int32) selector")
	}

	funcName, params, err := DecodeContractCall(abiMap, calldata)
	if err != nil {
		t.Fatalf("DecodeContractCall: %v", err)
	}
	if funcName != "setName" {
		t.Fatalf("funcName = %q, want %q", funcName, "setName")
	}
	if len(params) != 3 {
		t.Fatalf("params len = %d, want 3", len(params))
	}

	if params[0].Name != "name" {
		t.Errorf("params[0].Name = %q, want %q", params[0].Name, "name")
	}
	if got, ok := params[0].Value.([]byte); !ok || string(got) != "trusty" {
		t.Errorf("params[0].Value = %q, want %q", params[0].Value, "trusty")
	}

	if params[1].Name != "age" {
		t.Errorf("params[1].Name = %q, want %q", params[1].Name, "age")
	}
	if got, ok := params[1].Value.(*big.Int); !ok || got.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("params[1].Value = %v, want 3", params[1].Value)
	}

	if params[2].Name != "height" {
		t.Errorf("params[2].Name = %q, want %q", params[2].Name, "height")
	}
	if got, ok := params[2].Value.(*big.Int); !ok || got.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("params[2].Value = %v, want 100", params[2].Value)
	}
}
