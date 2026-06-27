package hdwallet

import (
	"encoding/hex"
	"strings"
	"testing"

	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
)

// testXRPWallet returns a key-only wallet using the same private key as the
// existing Ripple Payment TWC vector so new tx-type tests share the same key pair.
func testXRPWallet(t *testing.T) *HDWallet {
	t.Helper()
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "a5576c0f63da10e584568c8d134569ff44017b0a249eb70657127ae04f38cc77"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	return w
}

// xrpSignHex is a test helper that signs and returns the lower-case hex.
func xrpSignHex(t *testing.T, w *HDWallet, in *txripple.SigningInput) (hexOut string, encoded []byte) {
	t.Helper()
	out, err := w.SignTransaction(XRP, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	ro := out.(*txripple.SigningOutput)
	if ro.GetError() != "" {
		t.Fatalf("signing error: %s", ro.GetError())
	}
	return ro.GetEncodedHex(), ro.GetEncoded()
}

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
		Transaction: &txripple.SigningInput_Payment{Payment: &txripple.Payment{
			Amount:      10,
			Destination: "rU893viamSnsfP3zjzM2KPxjqZjXSXK6VF",
		}},
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
	// tx_id is the XRP tx hash: upper-case hex of sha512Half over the (locked)
	// signed blob. Derived from the pinned output to pin and wire-check the field.
	wantTxID := strings.ToUpper(hex.EncodeToString(sha512Half(ro.GetEncoded())))
	if ro.GetTxId() != wantTxID {
		t.Fatalf("tx_id mismatch:\n got  %s\n want %s", ro.GetTxId(), wantTxID)
	}
}

// The vectors below were produced by this library's own signer and verified for
// internal consistency (round-trip decode + signature validity). External
// validation with xrpl-py or xrpl.js should be added before mainnet use.

// TestSignTxRippleTrustSet pins the serialization of a USD trust-line creation.
func TestSignTxRippleTrustSet(t *testing.T) {
	w := testXRPWallet(t)
	defer w.Destroy()
	const want = "12001422000000002400000001201b0000006463d5038d7ea4c680000000000000000000000000005553440000000000b5f762798a53d543a014caf8b297cff8f2f937e868400000000000000c732103d13e1152965a51a4a9fd9a8b4ea3dd82a4eba6b25fcad5f460a2342bb650333f74463044022048a0b12d5c92f08b745652dbfbbee579bd0686049b712594de404dd9e739b7ae02205c3e1d654e22141fc50b97dff79904cd81696c5fec0e128ba62fa8f3ef0f0eca81144c55f5a78067206507580be7bb2686c8460adff9"
	got, _ := xrpSignHex(t, w, &txripple.SigningInput{
		Fee: 12, Sequence: 1, LastLedgerSequence: 100,
		Account: "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
		Transaction: &txripple.SigningInput_TrustSet{TrustSet: &txripple.TrustSet{
			LimitAmountCurrency: "USD",
			LimitAmountIssuer:   "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
			LimitAmountValue:    "100",
		}},
	})
	if got != want {
		t.Fatalf("TrustSet mismatch:\n got  %s\n want %s", got, want)
	}
}

// TestSignTxRippleOfferCreate pins the serialization of a DEX order
// (sell 10 XRP for 100 USD).
func TestSignTxRippleOfferCreate(t *testing.T) {
	w := testXRPWallet(t)
	defer w.Destroy()
	const want = "12000722000000002400000002201b0000006464400000000098968065d5038d7ea4c680000000000000000000000000005553440000000000b5f762798a53d543a014caf8b297cff8f2f937e868400000000000000c732103d13e1152965a51a4a9fd9a8b4ea3dd82a4eba6b25fcad5f460a2342bb650333f7446304402201f68fe2584ffee3b6e22e00353c8217165fca847dfa625d686f47862e9bb9fa0022013798d9906384c4c926384ad3da9afe4e39578929050e9b01929a6bc10f8fcf681144c55f5a78067206507580be7bb2686c8460adff9"
	got, _ := xrpSignHex(t, w, &txripple.SigningInput{
		Fee: 12, Sequence: 2, LastLedgerSequence: 100,
		Account: "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
		Transaction: &txripple.SigningInput_OfferCreate{OfferCreate: &txripple.OfferCreate{
			TakerPaysCurrency: "",         // native XRP
			TakerPaysValue:    "10000000", // 10 XRP in drops
			TakerGetsCurrency: "USD",
			TakerGetsIssuer:   "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
			TakerGetsValue:    "100",
		}},
	})
	if got != want {
		t.Fatalf("OfferCreate mismatch:\n got  %s\n want %s", got, want)
	}
}

// TestSignTxRippleOfferCancel pins the serialization of an OfferCancel.
func TestSignTxRippleOfferCancel(t *testing.T) {
	w := testXRPWallet(t)
	defer w.Destroy()
	const want = "12000822000000002400000003201900000002201b0000006468400000000000000c732103d13e1152965a51a4a9fd9a8b4ea3dd82a4eba6b25fcad5f460a2342bb650333f74463044022048d74fdd43ba71cceee78a4ad2f65146941b5ff56edf750ab2b3e6313ddd688302204cabaf76b5d02ff99599409cfa9d478d8317f45d5ebb2b581f7f6e03ce758c0a81144c55f5a78067206507580be7bb2686c8460adff9"
	got, _ := xrpSignHex(t, w, &txripple.SigningInput{
		Fee: 12, Sequence: 3, LastLedgerSequence: 100,
		Account: "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
		Transaction: &txripple.SigningInput_OfferCancel{OfferCancel: &txripple.OfferCancel{
			OfferSequence: 2,
		}},
	})
	if got != want {
		t.Fatalf("OfferCancel mismatch:\n got  %s\n want %s", got, want)
	}
}

// TestSignTxRippleEscrowCreate pins the serialization of a time-locked payment.
func TestSignTxRippleEscrowCreate(t *testing.T) {
	w := testXRPWallet(t)
	defer w.Destroy()
	const want = "12000122000000002400000004201b0000006420251fc78d666140000000000f424068400000000000000c732103d13e1152965a51a4a9fd9a8b4ea3dd82a4eba6b25fcad5f460a2342bb650333f7446304402207f1b0a734af4c3924540f7056bfac4e97df2327116d9559ba1e52e255779083f0220245fb263e7c60785817a240ebc47be15a06c34ac043054c639cc0360b0fec79b81144c55f5a78067206507580be7bb2686c8460adff983148132e4e20aecf29090ac428a9c43f230a829220d"
	got, _ := xrpSignHex(t, w, &txripple.SigningInput{
		Fee: 12, Sequence: 4, LastLedgerSequence: 100,
		Account: "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
		Transaction: &txripple.SigningInput_EscrowCreate{EscrowCreate: &txripple.EscrowCreate{
			Amount:      "1000000",
			Destination: "rU893viamSnsfP3zjzM2KPxjqZjXSXK6VF",
			FinishAfter: 533171558,
		}},
	})
	if got != want {
		t.Fatalf("EscrowCreate mismatch:\n got  %s\n want %s", got, want)
	}
}

// TestSignTxRippleEscrowFinish pins the serialization of an escrow release.
func TestSignTxRippleEscrowFinish(t *testing.T) {
	w := testXRPWallet(t)
	defer w.Destroy()
	const want = "12000222000000002400000005201900000004201b0000006468400000000000000c732103d13e1152965a51a4a9fd9a8b4ea3dd82a4eba6b25fcad5f460a2342bb650333f74473045022100b58352c0d20366f85551468a916ad57da1667b3ad9c9d5c4d417f08bca131e97022041b84fb8608b63957214ab3856cb30c411b51ee9180be2263c249c81e362fa1981144c55f5a78067206507580be7bb2686c8460adff982144c55f5a78067206507580be7bb2686c8460adff9"
	got, _ := xrpSignHex(t, w, &txripple.SigningInput{
		Fee: 12, Sequence: 5, LastLedgerSequence: 100,
		Account: "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
		Transaction: &txripple.SigningInput_EscrowFinish{EscrowFinish: &txripple.EscrowFinish{
			Owner:         "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
			OfferSequence: 4,
		}},
	})
	if got != want {
		t.Fatalf("EscrowFinish mismatch:\n got  %s\n want %s", got, want)
	}
}

// TestSignTxRippleAccountSet pins the serialization of an account flag change.
func TestSignTxRippleAccountSet(t *testing.T) {
	w := testXRPWallet(t)
	defer w.Destroy()
	const want = "12000322000000002400000006201b0000006420210000000368400000000000000c732103d13e1152965a51a4a9fd9a8b4ea3dd82a4eba6b25fcad5f460a2342bb650333f7446304402204d4a84e557b56686531ac68f1cb389e77a63ad468d1daec13267f7eecf05f5a80220010db21f755cb794c91eaadfa00f76dd24ac71f3d182649a0f27a226c162961881144c55f5a78067206507580be7bb2686c8460adff9"
	got, _ := xrpSignHex(t, w, &txripple.SigningInput{
		Fee: 12, Sequence: 6, LastLedgerSequence: 100,
		Account: "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
		Transaction: &txripple.SigningInput_AccountSet{AccountSet: &txripple.AccountSet{
			SetFlag: 3, // asfDisallowXRP
		}},
	})
	if got != want {
		t.Fatalf("AccountSet mismatch:\n got  %s\n want %s", got, want)
	}
}
