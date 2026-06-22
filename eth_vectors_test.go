package hdwallet

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Authoritative vectors for the Ethereum tooling (ABI, EIP-191, EIP-712).
// These pin correctness to external references; a wrong digest or encoding fails.

// ERC-20 transfer(address,uint256) has the well-known selector 0xa9059cbb.
func TestABIFunctionSelectorERC20Transfer(t *testing.T) {
	sel := ABIFunctionSelector("transfer", []string{"address", "uint256"})
	if got := hex.EncodeToString(sel); got != "a9059cbb" {
		t.Fatalf("transfer selector = %s, want a9059cbb", got)
	}
}

// Full ABI encoding of transfer(addr, 1e18) per the ABI spec (selector + two
// 32-byte words: left-padded address, left-padded amount).
func TestABIEncodeERC20Transfer(t *testing.T) {
	addr, _ := hex.DecodeString("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
	amount, _ := new(big.Int).SetString("0de0b6b3a7640000", 16) // 1e18
	enc, err := ABIEncode("transfer", []ABIValue{
		{Type: "address", Value: addr},
		{Type: "uint256", Value: amount},
	})
	if err != nil {
		t.Fatalf("ABIEncode: %v", err)
	}
	want := "a9059cbb" +
		"0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed" +
		"0000000000000000000000000000000000000000000000000de0b6b3a7640000"
	if got := hex.EncodeToString(enc); got != want {
		t.Fatalf("ABIEncode transfer:\n got  %s\n want %s", got, want)
	}
	// Round-trip decode.
	sel, vals, err := ABIDecode([]string{"address", "uint256"}, enc)
	if err != nil {
		t.Fatalf("ABIDecode: %v", err)
	}
	if hex.EncodeToString(sel) != "a9059cbb" {
		t.Fatalf("decoded selector = %x", sel)
	}
	if gotAmt := vals[1].Value.(*big.Int); gotAmt.Cmp(amount) != 0 {
		t.Fatalf("decoded amount = %s, want %s", gotAmt, amount)
	}
}

// The canonical EIP-712 specification "Mail" example. The reference private key
// keccak256("cow") signs the typed data to the well-known signature below, which
// recovers to the reference address. This pins EIP712Hash to the spec: recovery
// only yields the right address if the digest matches the reference exactly.
const eip712MailExample = `{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"},
      {"name": "verifyingContract", "type": "address"}
    ],
    "Person": [
      {"name": "name", "type": "string"},
      {"name": "wallet", "type": "address"}
    ],
    "Mail": [
      {"name": "from", "type": "Person"},
      {"name": "to", "type": "Person"},
      {"name": "contents", "type": "string"}
    ]
  },
  "primaryType": "Mail",
  "domain": {
    "name": "Ether Mail",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
  },
  "message": {
    "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
    "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
    "contents": "Hello, Bob!"
  }
}`

func TestEIP712MailExample(t *testing.T) {
	const wantAddr = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
	// Reference signature from the EIP-712 spec (r || s || v=0x1c).
	sigHex := "4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d" +
		"07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562" + "1c"
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("bad sig hex: %v", err)
	}
	if !VerifyEthereumTypedData(wantAddr, []byte(eip712MailExample), sig) {
		// Surface the computed digest to localize a failure.
		d, derr := EIP712Hash([]byte(eip712MailExample))
		t.Fatalf("EIP-712 Mail signature did not recover to %s (digest=%x, err=%v)", wantAddr, d, derr)
	}
}

// EIP-191 personal_sign end-to-end: sign with the canonical BIP-39 test wallet,
// then ecrecover must return its known Ethereum address.
func TestEIP191SignRecoverRoundTrip(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	const wantAddr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
	w, err := FromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	msg := []byte("Hello, world!")
	sig, err := w.SignMessage(ETH, 0, msg)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65", len(sig))
	}
	if v := sig[64]; v != 27 && v != 28 {
		t.Fatalf("recovery byte = %d, want 27/28", v)
	}
	got, err := RecoverEthereumAddress(msg, sig)
	if err != nil {
		t.Fatalf("RecoverEthereumAddress: %v", err)
	}
	if got != wantAddr {
		t.Fatalf("recovered %s, want %s", got, wantAddr)
	}
	if !VerifyEthereumMessage(wantAddr, msg, sig) {
		t.Fatal("VerifyEthereumMessage returned false for a valid signature")
	}
	// Determinism: signing the same message again yields the same signature.
	sig2, _ := w.SignMessage(ETH, 0, msg)
	if hex.EncodeToString(sig) != hex.EncodeToString(sig2) {
		t.Fatal("EIP-191 signatures are not deterministic (RFC 6979 expected)")
	}
}
