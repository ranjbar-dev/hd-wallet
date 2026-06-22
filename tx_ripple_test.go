package hdwallet

import (
	"testing"

	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
)

// XRP Payment signing verified against Trust Wallet Core's Ripple AnySigner
// vector (swift/Tests/Blockchains/RippleTests.swift). The expected encoded blob
// pins the canonical field-ordered serialization, the STX-prefixed sha512Half
// signing digest, and the low-S DER signature; any deviation changes the bytes.
func TestSignTxRipplePayment(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "a5576c0f63da10e584568c8d134569ff44017b0a249eb70657127ae04f38cc77"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txripple.SigningInput{
		Fee:                10,
		Sequence:           32268248,
		LastLedgerSequence: 32268269,
		Account:            "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
		Payment: &txripple.Payment{
			Amount:      10,
			Destination: "rU893viamSnsfP3zjzM2KPxjqZjXSXK6VF",
		},
	}

	const want = "12000022000000002401ec5fd8201b01ec5fed61400000000000000a68400000000000000a732103d13e1152965a51a4a9fd9a8b4ea3dd82a4eba6b25fcad5f460a2342bb650333f74463044022037d32835c9394f39b2cfd4eaf5b0a80e0db397ace06630fa2b099ff73e425dbc02205288f780330b7a88a1980fa83c647b5908502ad7de9a44500c08f0750b0d9e8481144c55f5a78067206507580be7bb2686c8460adff983148132e4e20aecf29090ac428a9c43f230a829220d"

	out, err := w.SignTransaction(XRP, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	ro, ok := out.(*txripple.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *ripple.SigningOutput", out)
	}
	if ro.GetError() != "" {
		t.Fatalf("signing error: %s", ro.GetError())
	}
	if ro.GetEncodedHex() != want {
		t.Fatalf("encoded mismatch:\n got  %s\n want %s", ro.GetEncodedHex(), want)
	}
}
