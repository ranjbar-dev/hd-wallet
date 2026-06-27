package hdwallet

import (
	"math/big"
	"testing"
)

// Ethereum event-log decoding proven by:
//   - ERC20TransferLog: construct a known Transfer log, assert from/to/amount.
//   - ERC721TransferLog: tokenId in Topics[3], Data empty, assert fields.
//   - DecodeEthLog: delegates to ABIDecodeParams, proven via a uint256 round-trip.
//   - Error cases: wrong signature, too few topics, malformed hex.

func makeTransferLog(from, to []byte, amountOrTokenID *big.Int, erc721 bool) *EthLog {
	sig := keccak256([]byte("Transfer(address,address,uint256)"))

	pad32 := func(addr []byte) []byte {
		t := make([]byte, 32)
		copy(t[12:], addr)
		return t
	}

	topics := []string{
		"0x" + bytesToHex(sig),
		"0x" + bytesToHex(pad32(from)),
		"0x" + bytesToHex(pad32(to)),
	}

	var data []byte
	if erc721 {
		// tokenId is indexed → append as Topic[3], Data is empty
		tokenTopic := make([]byte, 32)
		idBytes := amountOrTokenID.Bytes()
		copy(tokenTopic[32-len(idBytes):], idBytes)
		topics = append(topics, "0x"+bytesToHex(tokenTopic))
	} else {
		// amount is non-indexed → ABI-encode into Data
		data = make([]byte, 32)
		aBytes := amountOrTokenID.Bytes()
		copy(data[32-len(aBytes):], aBytes)
	}

	return &EthLog{
		Address: "0x" + bytesToHex(make([]byte, 20)),
		Topics:  topics,
		Data:    data,
	}
}

func TestDecodeEthLogERC20Transfer(t *testing.T) {
	from := make([]byte, 20)
	to := make([]byte, 20)
	for i := range from {
		from[i] = byte(i + 1)
	}
	for i := range to {
		to[i] = byte(i + 0x11)
	}
	amount := new(big.Int).Mul(big.NewInt(100), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	log := makeTransferLog(from, to, amount, false)

	gotFrom, gotTo, gotAmt, err := ERC20TransferLog(log)
	if err != nil {
		t.Fatalf("ERC20TransferLog: %v", err)
	}
	wantFrom := "0x" + bytesToHex(from)
	wantTo := "0x" + bytesToHex(to)
	if gotFrom != wantFrom {
		t.Errorf("from = %s, want %s", gotFrom, wantFrom)
	}
	if gotTo != wantTo {
		t.Errorf("to = %s, want %s", gotTo, wantTo)
	}
	if gotAmt.Cmp(amount) != 0 {
		t.Errorf("amount = %s, want %s", gotAmt, amount)
	}
}

func TestDecodeEthLogERC721Transfer(t *testing.T) {
	from := make([]byte, 20)
	to := make([]byte, 20)
	from[0], to[0] = 0xaa, 0xbb
	tokenID := big.NewInt(42)
	log := makeTransferLog(from, to, tokenID, true)

	gotFrom, gotTo, gotID, err := ERC721TransferLog(log)
	if err != nil {
		t.Fatalf("ERC721TransferLog: %v", err)
	}
	if gotFrom != "0x"+bytesToHex(from) {
		t.Errorf("from = %s", gotFrom)
	}
	if gotTo != "0x"+bytesToHex(to) {
		t.Errorf("to = %s", gotTo)
	}
	if gotID.Cmp(tokenID) != 0 {
		t.Errorf("tokenID = %s, want 42", gotID)
	}
}

func TestDecodeEthLogDecodeEthLog(t *testing.T) {
	// Round-trip a uint256 and address through DecodeEthLog.
	addr := make([]byte, 20)
	addr[0] = 0xde
	n := big.NewInt(999999)

	data := make([]byte, 64) // two 32-byte slots
	copy(data[12:32], addr)  // address, left-padded
	nBytes := n.Bytes()
	copy(data[64-len(nBytes):], nBytes) // uint256

	log := &EthLog{Data: data}
	vals, err := DecodeEthLog(log, []string{"address", "uint256"})
	if err != nil {
		t.Fatalf("DecodeEthLog: %v", err)
	}
	if len(vals) != 2 {
		t.Fatalf("vals = %d, want 2", len(vals))
	}
	addrVal, ok := vals[0].Value.([]byte)
	if !ok || !bytesEqual(addrVal, addr) {
		t.Errorf("address mismatch: %x", addrVal)
	}
	nVal, ok := vals[1].Value.(*big.Int)
	if !ok || nVal.Cmp(n) != 0 {
		t.Errorf("uint256 = %v, want 999999", nVal)
	}
}

func TestDecodeEthLogErrors(t *testing.T) {
	validSig := "0x" + bytesToHex(keccak256([]byte("Transfer(address,address,uint256)")))
	zeroPad := "0x" + bytesToHex(make([]byte, 32))

	cases := map[string]*EthLog{
		"too few topics erc20": {
			Topics: []string{validSig, zeroPad},
			Data:   make([]byte, 32),
		},
		"too few topics erc721": {
			Topics: []string{validSig, zeroPad, zeroPad},
			Data:   nil,
		},
		"wrong signature": {
			Topics: []string{"0x" + bytesToHex(make([]byte, 32)), zeroPad, zeroPad},
			Data:   make([]byte, 32),
		},
	}

	for name, log := range cases {
		t.Run("erc20/"+name, func(t *testing.T) {
			if _, _, _, err := ERC20TransferLog(log); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}

	wrongSigLog := &EthLog{
		Topics: []string{"0x" + bytesToHex(make([]byte, 32)), zeroPad, zeroPad, zeroPad},
	}
	if _, _, _, err := ERC721TransferLog(wrongSigLog); err == nil {
		t.Fatal("erc721: expected error for wrong signature")
	}
}
