package hdwallet

import "testing"

// Trust Wallet Core BitcoinMessageSigner vectors
// (tests/chains/Bitcoin/MessageSignerTests.cpp). The compressed key
// afee…45f5 over each message yields the exact base64 signature, and the
// signature verifies against the key's legacy P2PKH address.
func TestSignBitcoinMessageVectors(t *testing.T) {
	const (
		privHex = "afeefca74d9a325cf1d6b6911d61a65c32afa8e02bd5e78e2e4ac2910bab45f5"
		addr    = "19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X" // compressed legacy P2PKH
	)
	cases := []struct {
		message string
		wantSig string
	}{
		{"test signature", "ILH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo="},
		{"another text", "H7vrF2C+TlFiHyegAw3QLv6SK0myuEEXUOgfx0+Qio1YVDuSa6p/OHpoQVlUt3F8QJdbdZN9M1h/fYEAnEz16V0="},
	}

	w, err := FromPrivateKeyBytes(mustHexTx(t, privHex), Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	for _, tc := range cases {
		got, err := w.SignBitcoinMessage(BTC, 0, []byte(tc.message))
		if err != nil {
			t.Fatalf("%q: SignBitcoinMessage: %v", tc.message, err)
		}
		if got != tc.wantSig {
			t.Fatalf("%q signature mismatch:\n got  %s\n want %s", tc.message, got, tc.wantSig)
		}
		if !VerifyBitcoinMessage(addr, []byte(tc.message), got) {
			t.Errorf("%q: VerifyBitcoinMessage rejected a valid signature", tc.message)
		}
		if VerifyBitcoinMessage(addr, []byte("wrong message"), got) {
			t.Errorf("%q: VerifyBitcoinMessage accepted a wrong message", tc.message)
		}
	}
}

// A non-secp256k1 coin cannot produce a recoverable signature.
func TestSignBitcoinMessageWrongCurve(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	if _, err := w.SignBitcoinMessage(SOL, 0, []byte("x")); err == nil {
		t.Error("expected error signing a Bitcoin message with an ed25519 coin")
	}
}
