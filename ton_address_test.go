package hdwallet

import (
	"encoding/hex"
	"testing"
)

// tonPrivToAddr holds the 15 (private-key hex → non-bounceable UQ address) pairs
// from Trust Wallet Core's rust `ton_address.rs` test_ton_address_derive. Each is
// fund-critical and must match byte-exact.
var tonPrivToAddr = [][2]string{
	{"5849481021e305dfdf9f0eaf87e07f15efec3fde8d8ed639c9fcf0bc351d998b", "UQAACKJfEIfI5vkht_w3NYk8k-OU5Xl_jq9XNmmkcPaUO-tB"},
	{"4a22d994755145e4a4ce7263bdb3a8a70e449c1fccdd299f80df862bd4dcb930", "UQA3fRa_AHKBo1Lu8QF5xm_fiCLi197NfoPbeta0VJyvKa76"},
	{"287d4c0fcc445173fe211e4ade3518c75cff7a9dd79070f54395058cdd53e485", "UQCbJ0QdlDmC0ofyCtH15PHBzrj9sMLoLjNjkgTYaxR8gn9z"},
	{"136e464280c4222a99ac34d5077a2edf11e4468a076741e495d9f31ca7939a1f", "UQAliC8yJh-Ru2uwEWgEaEV9LHEs0-c1blYr_XZe7CpEwm9D"},
	{"f15bb09a2cf37f6e6b6515be4000cdf271338c56fb1ec81848f2f1407b3a4003", "UQCeAQaIFwwjmcJkYfqGiyHo2ag7qUMMfsUi28HLWmtpA7zF"},
	{"532005268411b3b4ac85b080c8a3bc4a52600be75f758013302745ac05ac18f0", "UQDD0YS5pQSe3fgHEKd-D7qTieRxmSknlQQW6fb7IFu7ky9T"},
	{"15e5a13ec259bb4515105ba0a84ee93eaa9f56f6fdf73bf6179d1ed80b6a399c", "UQAx8JmUT4p14RUAu9gpXqmTzkQz4e3GZz8VQjqWXFDxG6-S"},
	{"9b503ff85debe95093acf0f9b057607a0a5be91cb47e2e6ec342d7825c7fafbc", "UQD91HEk-TJVublA57dgkSwgrRORj48ubEIfjEPZIjQ08oZl"},
	{"97075969876382280ff7598738b3fd2c1748f9a549dd6f5d6aa5694c21deddce", "UQBrL2lNG3ThmYbf9gaA_-tsPfdrcGy27LP0M-qg-1TpG_wR"},
	{"57d86027989f8ec649cce3be862d68564d471395c5694918b0348e17c7ef6ffe", "UQDUJLg8MYZPT2C-2n-ulyNSkBsdDaUzqEq71dBx3l6fhnuL"},
	{"b1ad2bff14fc018493c32c37cded62892ec507471e34a25da0b5b5f05e131751", "UQD079e5CETiOrR_iS0atJukl7ixS6EYbtaWRSGykFAtwRhL"},
	{"16ad201c59ecd7ace74e1677160106923a3d2ee11c495be5c3b88ba6f7ef3d17", "UQDuU7NOk_eGzP5CLs_Zeg0LBpySAGy02qqGv0cO_zX5WN1n"},
	{"3d935b7a8c24e7dc55ef7c0c890806cee3af1174a62165d4d2fb64ccf2e2260b", "UQALRogl66QrJIb3KbStOd-ZadA6Ye2g23ME6JAMU1HOXRG2"},
	{"68f3a87d12514854774300b8a4c449616e208336f1b609c96fcd8b1a87d4e064", "UQALrF1c2UeoCybOsSeAdUmip4yhcCtrUAhKZ-9bxv6_okVx"},
	{"fbfbc640c4cd4649161a935562217f1caecf6e7f3a2818921f9ee336741a48cb", "UQAzCS7JoSiOi1BdH4nFkuvUwbBjxUzPx1AhQKwiwXAv27Xs"},
}

// TestTONAddressDerivePrivateKey verifies all 15 TWC private-key → address
// vectors via the key-only wallet path FromPrivateKeyBytes + Address(TON).
func TestTONAddressDerivePrivateKey(t *testing.T) {
	for _, tc := range tonPrivToAddr {
		priv, err := hex.DecodeString(tc[0])
		if err != nil {
			t.Fatalf("bad hex %s: %v", tc[0], err)
		}
		w, err := FromPrivateKeyBytes(priv, Ed25519)
		if err != nil {
			t.Fatalf("FromPrivateKeyBytes(%s): %v", tc[0], err)
		}
		got, err := w.Address(TON)
		if err != nil {
			w.Destroy()
			t.Fatalf("Address(TON) for %s: %v", tc[0], err)
		}
		w.Destroy()
		if got != tc[1] {
			t.Errorf("priv %s: address = %s, want %s", tc[0], got, tc[1])
		}
	}
}

// TestTONAddressFormatEquivalence verifies raw / bounceable-EQ / non-bounceable-UQ
// forms of the same account all parse to the same 32-byte hash, that std-alphabet
// base64 variants are accepted, and that a corrupted CRC is rejected.
func TestTONAddressFormatEquivalence(t *testing.T) {
	const rawHashHex = "8a8627861a5dd96c9db3ce0807b122da5ed473934ce7568a5b4b1c361cbb28ae"
	wantHash, _ := hex.DecodeString(rawHashHex)

	forms := []string{
		"0:8a8627861a5dd96c9db3ce0807b122da5ed473934ce7568a5b4b1c361cbb28ae",
		"EQCKhieGGl3ZbJ2zzggHsSLaXtRzk0znVopbSxw2HLsorkdl", // bounceable, url-safe
		"UQCKhieGGl3ZbJ2zzggHsSLaXtRzk0znVopbSxw2HLsorhqg", // non-bounceable, url-safe
	}
	for _, f := range forms {
		got, err := ParseAddress(TON, f)
		if err != nil {
			t.Fatalf("ParseAddress(TON, %q): %v", f, err)
		}
		if !bytesEqual(got, wantHash) {
			t.Errorf("ParseAddress(TON, %q) = %x, want %x", f, got, wantHash)
		}
	}

	// Standard-alphabet base64 variant must also be accepted.
	stdAlpha := "EQAN6Dr3vziti1Kp9D3aEFqJX4bBVfCaV57Z+9jwKTBXICv8"
	if !IsValidAddress(TON, stdAlpha) {
		t.Errorf("std-alphabet address %q should be valid", stdAlpha)
	}

	// Corrupted CRC must be rejected (flip a char in the checksum region).
	corrupt := "UQCKhieGGl3ZbJ2zzggHsSLaXtRzk0znVopbSxw2HLsorhqA"
	if IsValidAddress(TON, corrupt) {
		t.Errorf("corrupted-CRC address %q should be invalid", corrupt)
	}

	// Raw -1: workchain form must parse too.
	rawMaster := "-1:8a8627861a5dd96c9db3ce0807b122da5ed473934ce7568a5b4b1c361cbb28ae"
	if _, err := ParseAddress(TON, rawMaster); err != nil {
		t.Errorf("raw masterchain form should parse: %v", err)
	}
}

// TestTONBoCRoundTrip serializes the parsed wallet-v4r2 code cell back to a BoC
// and re-parses it, asserting the repr hash is preserved. This structurally
// exercises tonCellToBoC (whose exact byte layout is pinned by Task 12's signing
// vector) without depending on a specific serialized form.
func TestTONBoCRoundTrip(t *testing.T) {
	code, err := tonWalletV4R2Code()
	if err != nil {
		t.Fatalf("load v4r2 code: %v", err)
	}
	want := hex.EncodeToString(code.reprHash())

	reser := tonCellToBoC(code)
	back, err := tonCellFromBoC(reser)
	if err != nil {
		t.Fatalf("re-parse serialized BoC: %v", err)
	}
	got := hex.EncodeToString(back.reprHash())
	if got != want {
		t.Errorf("repr hash changed across serialize round-trip: got %s, want %s", got, want)
	}
}

// TestTONWalletCodeLoads sanity-checks that the wallet-v4r2 code BoC constant
// parses into a non-trivial cell tree. The authoritative correctness proof for
// the code cell (and thus its repr hash) is the 15 address vectors above, which
// each embed the code cell in the StateInit hash.
func TestTONWalletCodeLoads(t *testing.T) {
	code, err := tonWalletV4R2Code()
	if err != nil {
		t.Fatalf("load v4r2 code: %v", err)
	}
	if code.depth() == 0 {
		t.Errorf("v4r2 code cell should have refs (depth > 0), got depth 0")
	}
	if len(code.reprHash()) != 32 {
		t.Errorf("repr hash length = %d, want 32", len(code.reprHash()))
	}
}
