package hdwallet_test

import (
	"encoding/hex"
	"errors"
	"testing"

	hd "github.com/ranjbar-dev/hd-wallet"
)

// BIP-38 test vectors (non-EC-multiply mode).
//
// Compressed vectors are self-contained: the encrypt test encodes a known private
// key and the decrypt test reverses it. The spec's own test vectors are "known
// good" in the sense that the spec's ciphertext for key CBF4B9F7… with passphrase
// TestingOneTwoThree is exactly 6PYNKZ1E…, which our encrypt produces byte-for-byte.
//
// Uncompressed decryption is tested separately (EncryptWIF always uses compressed;
// the uncompressed path only exercises bip38Decrypt handling of the C0 flagbyte).

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

var bip38CompressedVectors = []struct {
	name       string
	privKeyHex string
	passphrase string
	encrypted  string
	wantWIF    string
}{
	{
		// Private key CBF4B9F7… encrypted with "TestingOneTwoThree".
		// The encrypted string 6PYNKZ1E… is byte-for-byte the BIP-38 spec ciphertext
		// for this passphrase; its addresshash (43be4179) matches the compressed
		// P2PKH address of CBF4B9F7… (164MQi977u9GUteHr4EPH27VkkdxmfCvGW).
		name:       "compressed-TestingOneTwoThree",
		privKeyHex: "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5",
		passphrase: "TestingOneTwoThree",
		encrypted:  "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
		wantWIF:    "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
	},
	{
		// Private key 09C268… encrypted with "Satoshi".
		name:       "compressed-Satoshi",
		privKeyHex: "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE",
		passphrase: "Satoshi",
		encrypted:  "6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
		wantWIF:    "KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
	},
}

func TestBIP38EncryptWIF(t *testing.T) {
	for _, v := range bip38CompressedVectors {
		t.Run(v.name, func(t *testing.T) {
			priv := mustHexBytes(t, v.privKeyHex)
			w, err := hd.FromPrivateKeyBytes(priv, hd.Secp256k1)
			if err != nil {
				t.Fatalf("FromPrivateKeyBytes: %v", err)
			}
			defer w.Destroy()

			got, err := w.EncryptWIF(hd.BTC, 0, []byte(v.passphrase))
			if err != nil {
				t.Fatalf("EncryptWIF: %v", err)
			}
			if got != v.encrypted {
				t.Errorf("encrypted: got %q, want %q", got, v.encrypted)
			}
		})
	}
}

func TestBIP38DecryptWIF(t *testing.T) {
	// Compressed vectors (round-trip with EncryptWIF).
	for _, v := range bip38CompressedVectors {
		t.Run(v.name, func(t *testing.T) {
			var gotWIF string
			err := hd.DecryptWIF(v.encrypted, []byte(v.passphrase), func(wif []byte) {
				gotWIF = string(wif)
			})
			if err != nil {
				t.Fatalf("DecryptWIF: %v", err)
			}
			if gotWIF != v.wantWIF {
				t.Errorf("WIF: got %q, want %q", gotWIF, v.wantWIF)
			}
		})
	}

	// Uncompressed decrypt (spec ciphertext with flagbyte 0xC0 — same private key as
	// compressed-TestingOneTwoThree but encrypted under the uncompressed P2PKH address).
	// EncryptWIF always uses compressed keys; this test exercises the decrypt-only path.
	t.Run("uncompressed-TestingOneTwoThree", func(t *testing.T) {
		const (
			encUncomp = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"
			wantWIF   = "5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR"
		)
		var gotWIF string
		err := hd.DecryptWIF(encUncomp, []byte("TestingOneTwoThree"), func(wif []byte) {
			gotWIF = string(wif)
		})
		if err != nil {
			t.Fatalf("DecryptWIF uncompressed: %v", err)
		}
		if gotWIF != wantWIF {
			t.Errorf("uncompressed WIF: got %q, want %q", gotWIF, wantWIF)
		}
	})
}

func TestBIP38WrongPassphrase(t *testing.T) {
	err := hd.DecryptWIF(
		"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
		[]byte("wrongpassphrase"),
		func([]byte) {},
	)
	if !errors.Is(err, hd.ErrInvalidWIF) {
		t.Fatalf("expected ErrInvalidWIF, got %v", err)
	}
}

func TestBIP38RoundTrip(t *testing.T) {
	w, err := hd.FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	passphrase := []byte("test-passphrase-123")
	enc, err := w.EncryptWIF(hd.BTC, 0, passphrase)
	if err != nil {
		t.Fatalf("EncryptWIF: %v", err)
	}

	var decryptedWIF string
	if err := hd.DecryptWIF(enc, passphrase, func(wif []byte) { decryptedWIF = string(wif) }); err != nil {
		t.Fatalf("DecryptWIF: %v", err)
	}

	// Also get WIF directly from wallet and compare.
	var directWIF string
	if err := w.WithWIF(hd.BTC, 0, func(wif []byte) error { directWIF = string(wif); return nil }); err != nil {
		t.Fatalf("WithWIF: %v", err)
	}
	if decryptedWIF != directWIF {
		t.Errorf("round-trip WIF mismatch: got %q, want %q", decryptedWIF, directWIF)
	}
}
