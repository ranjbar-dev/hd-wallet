package hdwallet

import (
	"testing"

	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
)

// "What am I signing?" XRP decoder, proven by:
//   - round-trip: sign the TWC Ripple Payment vector with the EXISTING signer and
//     assert DecodeRippleTx recovers TransactionType, Account, Destination,
//     Amount, Fee, Sequence, Flags, LastLedgerSequence and the SigningPubKey /
//     TxnSignature;
//   - a DestinationTag round-trip to exercise the optional-field branch;
//   - malformed: truncated/garbage bytes return ErrTxDecode, never a panic.

func TestDecodeRippleRoundTripPayment(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "a5576c0f63da10e584568c8d134569ff44017b0a249eb70657127ae04f38cc77"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	const (
		account     = "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq"
		destination = "rU893viamSnsfP3zjzM2KPxjqZjXSXK6VF"
	)
	in := &txripple.SigningInput{
		Fee:                10,
		Sequence:           32268248,
		LastLedgerSequence: 32268269,
		Account:            account,
		Payment: &txripple.Payment{
			Amount:      10,
			Destination: destination,
		},
	}

	out, err := w.SignTransaction(XRP, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	encoded := out.(*txripple.SigningOutput).GetEncoded()

	f, err := DecodeRippleTx(encoded)
	if err != nil {
		t.Fatalf("DecodeRippleTx: %v", err)
	}
	if f.TransactionType != 0 || f.TransactionName != "Payment" {
		t.Fatalf("type = %d/%s, want 0/Payment", f.TransactionType, f.TransactionName)
	}
	if f.Account != account || f.Destination != destination {
		t.Fatalf("account/destination = %s / %s", f.Account, f.Destination)
	}
	if f.Amount != 10 || f.Fee != 10 {
		t.Fatalf("amount/fee = %d / %d, want 10 / 10", f.Amount, f.Fee)
	}
	if f.Sequence != 32268248 || f.Flags != 0 {
		t.Fatalf("sequence/flags = %d / %d", f.Sequence, f.Flags)
	}
	if f.LastLedgerSequence == nil || *f.LastLedgerSequence != 32268269 {
		t.Fatalf("last ledger sequence = %v, want 32268269", f.LastLedgerSequence)
	}
	if f.DestinationTag != nil {
		t.Fatalf("destination tag = %v, want nil", *f.DestinationTag)
	}
	if len(f.SigningPubKey) != 33 {
		t.Fatalf("signing pub key len = %d, want 33", len(f.SigningPubKey))
	}
	if len(f.TxnSignature) == 0 {
		t.Fatalf("txn signature is empty")
	}
}

func TestDecodeRippleRoundTripDestinationTag(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "a5576c0f63da10e584568c8d134569ff44017b0a249eb70657127ae04f38cc77"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txripple.SigningInput{
		Fee:                12,
		Sequence:           1,
		LastLedgerSequence: 100,
		Flags:              0x80000000,
		Account:            "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
		Payment: &txripple.Payment{
			Amount:         2000000,
			Destination:    "rU893viamSnsfP3zjzM2KPxjqZjXSXK6VF",
			DestinationTag: 12345,
		},
	}

	out, err := w.SignTransaction(XRP, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	f, err := DecodeRippleTx(out.(*txripple.SigningOutput).GetEncoded())
	if err != nil {
		t.Fatalf("DecodeRippleTx: %v", err)
	}
	if f.Amount != 2000000 || f.Fee != 12 || f.Sequence != 1 {
		t.Fatalf("amount/fee/seq = %d/%d/%d", f.Amount, f.Fee, f.Sequence)
	}
	if f.Flags != 0x80000000 {
		t.Fatalf("flags = %#x, want 0x80000000", f.Flags)
	}
	if f.DestinationTag == nil || *f.DestinationTag != 12345 {
		t.Fatalf("destination tag = %v, want 12345", f.DestinationTag)
	}
}

// TestDecodeRippleVector decodes the exact published Trust Wallet Core Ripple
// AnySigner output (the `want` blob pinned in tx_ripple_test.go) directly, an
// anchor independent of re-running the signer.
func TestDecodeRippleVector(t *testing.T) {
	const wantHex = "12000022000000002401ec5fd8201b01ec5fed61400000000000000a68400000000000000a732103d13e1152965a51a4a9fd9a8b4ea3dd82a4eba6b25fcad5f460a2342bb650333f74463044022037d32835c9394f39b2cfd4eaf5b0a80e0db397ace06630fa2b099ff73e425dbc02205288f780330b7a88a1980fa83c647b5908502ad7de9a44500c08f0750b0d9e8481144c55f5a78067206507580be7bb2686c8460adff983148132e4e20aecf29090ac428a9c43f230a829220d"

	f, err := DecodeRippleTx(mustHexTx(t, wantHex))
	if err != nil {
		t.Fatalf("DecodeRippleTx: %v", err)
	}
	if f.TransactionName != "Payment" {
		t.Fatalf("type name = %s, want Payment", f.TransactionName)
	}
	if f.Account != "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq" {
		t.Fatalf("account = %s", f.Account)
	}
	if f.Destination != "rU893viamSnsfP3zjzM2KPxjqZjXSXK6VF" {
		t.Fatalf("destination = %s", f.Destination)
	}
	if f.Amount != 10 || f.Fee != 10 || f.Sequence != 32268248 {
		t.Fatalf("amount/fee/seq = %d/%d/%d", f.Amount, f.Fee, f.Sequence)
	}
	if f.LastLedgerSequence == nil || *f.LastLedgerSequence != 32268269 {
		t.Fatalf("last ledger sequence = %v", f.LastLedgerSequence)
	}
	if len(f.SigningPubKey) != 33 || len(f.TxnSignature) == 0 {
		t.Fatalf("pubkey/sig len = %d/%d", len(f.SigningPubKey), len(f.TxnSignature))
	}
}

func TestDecodeRippleMalformed(t *testing.T) {
	w, _ := FromPrivateKeyBytes(
		mustHexTx(t, "a5576c0f63da10e584568c8d134569ff44017b0a249eb70657127ae04f38cc77"),
		Secp256k1,
	)
	defer w.Destroy()
	in := &txripple.SigningInput{
		Fee:                10,
		Sequence:           32268248,
		LastLedgerSequence: 32268269,
		Account:            "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
		Payment:            &txripple.Payment{Amount: 10, Destination: "rU893viamSnsfP3zjzM2KPxjqZjXSXK6VF"},
	}
	out, _ := w.SignTransaction(XRP, 0, in)
	full := out.(*txripple.SigningOutput).GetEncoded()

	cases := map[string][]byte{
		"empty":             {},
		"truncated":         full[:len(full)/2],
		"dangling header":   {0x20},                                     // UInt32 small-type/large-field header, no field byte
		"truncated uint32":  {0x24, 0x00},                               // Sequence field, only 2 of 4 value bytes
		"unknown type code": {0x31},                                     // type code 3 (UInt64) not handled
		"short account id":  {0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}, // AccountID len 5, not 20
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRippleTx(b); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}
