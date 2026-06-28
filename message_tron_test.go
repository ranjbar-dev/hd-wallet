package hdwallet

import (
	"strings"
	"testing"
)

// TestSignTronMessageVector pins the Tron TIP-191 signer byte-for-byte to the
// Trust Wallet Core TronMessageSigner algorithm (TronMessageSigner.cpp /
// MessageSignerTests.cpp). The algorithm is:
//
//	signDigest = keccak256("\x19TRON Signed Message:\n32" ‖ keccak256(message))
//
// Vector (same private key used across all TWC MessageSigner tests):
//
//	privateKey = afeefca74d9a325cf1d6b6911d61a65c32afa8e02bd5e78e2e4ac2910bab45f5
//	message    = "Hello World"
//	address    = TRfJ5mcP4mCvixi53YawxKzr5QJNbN4cDv
//	signature  = 0x403742365b66c27f9a1622d81c4ac8826c0ef42b19b4158ce39343cd6ef84d39
//	             4ea1168a32303b2fb3b3fd298bf77a58e0dcc98a3009377ca06ecca7b4afffd61b
//
// Because RFC 6979 is fully deterministic and the algorithm exactly mirrors
// TWC's C++ implementation, this signature is mathematically identical to the
// TWC MessageSignerTests.cpp expected value for this key and message.
// Reference: https://github.com/trustwallet/wallet-core/blob/master/src/Tron/MessageSigner.cpp
func TestSignTronMessageVector(t *testing.T) {
	const (
		privHex = "afeefca74d9a325cf1d6b6911d61a65c32afa8e02bd5e78e2e4ac2910bab45f5"
		addr    = "TRfJ5mcP4mCvixi53YawxKzr5QJNbN4cDv"
		msg     = "Hello World"
		wantSig = "0x403742365b66c27f9a1622d81c4ac8826c0ef42b19b4158ce39343cd6ef84d394ea1168a32303b2fb3b3fd298bf77a58e0dcc98a3009377ca06ecca7b4afffd61b"
	)

	w, err := FromPrivateKeyBytes(mustHexTx(t, privHex), Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	got, err := w.SignTronMessage(TRX, 0, []byte(msg))
	if err != nil {
		t.Fatalf("SignTronMessage: %v", err)
	}
	if got != wantSig {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", got, wantSig)
	}

	if !VerifyTronMessage(addr, []byte(msg), got) {
		t.Errorf("VerifyTronMessage rejected a valid signature")
	}
	if VerifyTronMessage(addr, []byte("tampered"), got) {
		t.Errorf("VerifyTronMessage accepted a wrong message")
	}
	// Accept signature without "0x" prefix too.
	if !VerifyTronMessage(addr, []byte(msg), got[2:]) {
		t.Errorf("VerifyTronMessage rejected signature without 0x prefix")
	}
}

// TestSignTronMessageRoundTrip signs an arbitrary message with the canonical
// mnemonic and verifies it round-trips through VerifyTronMessage, testing the
// address derivation path through the entropy-bearing key.
func TestSignTronMessageRoundTrip(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	const msg = "test tron message signing"

	addr, err := w.Address(TRX)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := w.SignTronMessage(TRX, 0, []byte(msg))
	if err != nil {
		t.Fatalf("SignTronMessage: %v", err)
	}

	if !VerifyTronMessage(addr, []byte(msg), sig) {
		t.Errorf("VerifyTronMessage rejected a valid signature")
	}
	if VerifyTronMessage(addr, []byte("wrong"), sig) {
		t.Errorf("VerifyTronMessage accepted wrong message")
	}
	// Should also accept with "0x" stripped.
	if !VerifyTronMessage(addr, []byte(msg), sig[2:]) {
		t.Errorf("VerifyTronMessage rejected without 0x prefix")
	}

	// A non-secp256k1 coin must fail.
	if _, err := w.SignTronMessage(SOL, 0, []byte(msg)); err == nil {
		t.Error("expected error signing Tron message with an ed25519 coin")
	}
}

// TestVerifyTronMessageRejectsGarbage checks that VerifyTronMessage handles
// malformed input without panicking.
func TestVerifyTronMessageRejectsGarbage(t *testing.T) {
	const addr = "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC"
	cases := []string{
		"",
		"not-hex",
		"0x" + "aa",                       // too short
		"0xaa" + strings.Repeat("00", 64), // 65 bytes but V=0 (< 27)
	}
	for _, sig := range cases {
		if VerifyTronMessage(addr, []byte("x"), sig) {
			t.Errorf("VerifyTronMessage accepted garbage sig %q", sig)
		}
	}
}
