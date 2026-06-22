package hdwallet

import (
	"errors"
	"testing"
)

// Importing a raw private key for a curve must route through the same
// publicKeyFromPriv + coin.Encode path that AllAddresses uses, so a key-only
// wallet's address equals encode(pub(key)). Since those encoders are verified
// against Trust Wallet Core vectors (encoders_test.go), this transitively proves
// the imported address is correct for the key. The private keys here are the
// TWC-sourced curve vectors from curves_twc_test.go.
func TestImportPrivateKeyExtendedCurves(t *testing.T) {
	cases := []struct {
		name    string
		curve   Curve
		privHex string
		symbol  Symbol
	}{
		{"nano (ed25519-blake2b)", Ed25519Blake2bNano, "173c40e97fe2afcd24187e74f6b603cb949a5365e72fbdd065a6b165e2189e34", XNO},
		{"waves (curve25519)", Curve25519, "9864a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a", WAVES},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv := mustHex(t, tc.privHex)

			pub, err := publicKeyFromPriv(tc.curve, append([]byte(nil), priv...))
			if err != nil {
				t.Fatalf("publicKeyFromPriv: %v", err)
			}
			coin, ok := CoinInfo(tc.symbol)
			if !ok {
				t.Fatalf("CoinInfo(%s): not found", tc.symbol)
			}
			want, err := coin.Encode(pub)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			w, err := FromPrivateKeyBytes(append([]byte(nil), priv...), tc.curve)
			if err != nil {
				t.Fatalf("FromPrivateKeyBytes: %v", err)
			}
			defer w.Destroy()

			got, err := w.Address(tc.symbol)
			if err != nil {
				t.Fatalf("Address: %v", err)
			}
			if got != want {
				t.Fatalf("imported-key address mismatch:\n got %s\nwant %s", got, want)
			}

			// The imported key must also sign+verify for its curve.
			msg := []byte("import round-trip")
			sig, err := w.Sign(tc.symbol, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !Verify(tc.curve, pub, msg, sig) {
				t.Fatalf("imported-key signature failed verification")
			}
		})
	}
}

func TestImportPrivateKeyCardanoUnsupported(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if _, err := FromPrivateKeyBytes(key, Ed25519ExtendedCardano); !errors.Is(err, ErrUnsupportedCurve) {
		t.Fatalf("FromPrivateKeyBytes(Cardano) error = %v, want ErrUnsupportedCurve", err)
	}
}
