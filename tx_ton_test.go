package hdwallet

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	txton "github.com/ranjbar-dev/hd-wallet/txproto/ton"
)

// TON native transfer signing — vector-pinned test.
//
// Source: Trust Wallet Core, test "test_ton_sign_transfer_ordinary".
// Wallet v4r2, ed25519, no comment, seqno>0 (no StateInit).
//
// Wire summary (all cells verified byte-for-byte against the vector):
//   - internal message cell: int_msg_info + addr_std dest + grams + empty body ref
//   - unsigned body cell (wallet v4): subwallet_id || expire_at || seqno || op=0 || mode || ref(internal)
//   - sign the unsigned body's repr hash with ed25519
//   - signed body cell: signature(512) || <unsigned body bits/refs>
//   - external message cell: ext_in_msg_info + addr_std(wallet) + body ref(signed)
//   - Output: encoded = base64(BoC(external)), hash = hex(reprHash(external))

// tonTestPrivKey is the ed25519 private-key seed for the TWC TON test vector.
var tonTestPrivKey, _ = hex.DecodeString("c38f49de2fb13223a9e7d37d5d0ffbdd89a5eb7c8b0ee4d1c299f2cefe7dc4a0")

// TestSignTxTON pins the TON wallet-v4r2 ordinary-transfer signer byte-for-byte
// to the TWC vector (both encoded BoC and repr hash).
func TestSignTxTON(t *testing.T) {
	// FromPrivateKeyBytes wipes its input slice; copy the shared package-level key.
	privKey := append([]byte(nil), tonTestPrivKey...)
	w, err := FromPrivateKeyBytes(privKey, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txton.SigningInput{
		SequenceNumber: 6,
		ExpireAt:       1671132440,
		Transfer: &txton.Transfer{
			Dest:       "EQBm--PFwDv1yCeS-QTJ-L8oiUpqo9IT1BwgVptlSq3ts90Q",
			Amount:     10,
			Mode:       3,
			Bounceable: true,
		},
	}

	out, err := w.SignTransaction(TON, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	got, ok := out.(*txton.SigningOutput)
	if !ok {
		t.Fatalf("expected *ton.SigningOutput, got %T", out)
	}
	if got.Error != "" {
		t.Fatalf("signing error: %s", got.Error)
	}

	const wantEncoded = "te6ccgICAAQAAQAAALAAAAFFiAGwt/q8k4SrjbFbQCjJZfQr64ExRxcUMsWqaQODqTUijgwAAQGcEUPkil2aZ4s8KKparSep/OKHMC8vuXafFbW2HGp/9AcTRv0J5T4dwyW1G0JpHw+g5Ov6QI3Xo0O9RFr3KidICimpoxdjm3UYAAAABgADAAIBYmIAM33x4uAd+uQTyXyCZPxflESlNVHpCeoOECtNsqVW9tmIUAAAAAAAAAAAAAAAAAEAAwAA"
	const wantHash = "3908cf8b570c1d3d261c62620c9f368db11f6e821a07614cff64de2e7319f81b"

	if got.Encoded != wantEncoded {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantEncoded)
	}
	if got.Hash != wantHash {
		t.Errorf("hash mismatch\n got: %s\nwant: %s", got.Hash, wantHash)
	}

	// raw must be the exact bytes that base64-encode to encoded.
	wantRaw, _ := base64.StdEncoding.DecodeString(wantEncoded)
	if hex.EncodeToString(got.Raw) != hex.EncodeToString(wantRaw) {
		t.Errorf("raw mismatch\n got: %x\nwant: %x", got.Raw, wantRaw)
	}
}

// TestTONModeConstants pins the exported send-mode constant values.
func TestTONModeConstants(t *testing.T) {
	if TONModePayFeesSeparately != 1 {
		t.Errorf("TONModePayFeesSeparately = %d, want 1", TONModePayFeesSeparately)
	}
	if TONModeIgnoreActionPhaseErrors != 2 {
		t.Errorf("TONModeIgnoreActionPhaseErrors = %d, want 2", TONModeIgnoreActionPhaseErrors)
	}
	if TONModePayFeesSeparately|TONModeIgnoreActionPhaseErrors != 3 {
		t.Errorf("default combined mode = %d, want 3", TONModePayFeesSeparately|TONModeIgnoreActionPhaseErrors)
	}
}

// TestSignTxTONNilInput verifies a nil input returns an error (not a panic).
func TestSignTxTONNilInput(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()

	_, err := w.SignTransaction(TON, 0, nil)
	if err == nil {
		t.Fatal("expected error for nil input, got nil")
	}
}

// TestSignTxTONMissingTransfer verifies a missing transfer returns ErrTxInput.
func TestSignTxTONMissingTransfer(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()

	_, err := w.SignTransaction(TON, 0, &txton.SigningInput{SequenceNumber: 1})
	if err == nil {
		t.Fatal("expected error for missing transfer")
	}
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("expected ErrTxInput, got %v", err)
	}
}

// TestTONBroadcastAndTxID verifies the txid/broadcast accessors surface the TON
// hash and base64 BoC.
func TestTONBroadcastAndTxID(t *testing.T) {
	privKey := append([]byte(nil), tonTestPrivKey...)
	w, err := FromPrivateKeyBytes(privKey, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txton.SigningInput{
		SequenceNumber: 6,
		ExpireAt:       1671132440,
		Transfer: &txton.Transfer{
			Dest:       "EQBm--PFwDv1yCeS-QTJ-L8oiUpqo9IT1BwgVptlSq3ts90Q",
			Amount:     10,
			Mode:       3,
			Bounceable: true,
		},
	}
	out, err := w.SignTransaction(TON, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	id, err := TransactionID(out)
	if err != nil {
		t.Fatalf("TransactionID: %v", err)
	}
	if id != "3908cf8b570c1d3d261c62620c9f368db11f6e821a07614cff64de2e7319f81b" {
		t.Errorf("TransactionID = %s", id)
	}

	payload, err := BroadcastPayload(TON, out)
	if err != nil {
		t.Fatalf("BroadcastPayload: %v", err)
	}
	got := out.(*txton.SigningOutput)
	if payload != got.Encoded {
		t.Errorf("BroadcastPayload = %s, want %s", payload, got.Encoded)
	}
}
