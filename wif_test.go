package hdwallet

import (
	"encoding/hex"
	"errors"
	"testing"
)

// Canonical Bitcoin "Wallet Import Format" vectors (Bitcoin wiki): the private
// key 0x0C28...AA1D encodes to a known uncompressed and compressed mainnet WIF.
const (
	wifTestKeyHex   = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
	wifUncompressed = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
	wifCompressed   = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
)

func TestDecodeWIFVectors(t *testing.T) {
	for _, wif := range []string{wifUncompressed, wifCompressed} {
		key, err := decodeWIF([]byte(wif))
		if err != nil {
			t.Fatalf("decodeWIF(%s): %v", wif, err)
		}
		if got := hex.EncodeToString(key); got != wifTestKeyHex {
			t.Fatalf("decoded key mismatch for %s:\n got %s\nwant %s", wif, got, wifTestKeyHex)
		}
	}
}

func TestFromWIFRoundTrip(t *testing.T) {
	w, err := FromWIF([]byte(wifCompressed))
	if err != nil {
		t.Fatalf("FromWIF: %v", err)
	}
	defer w.Destroy()

	err = w.WithPrivateKey(BTC, 0, func(priv []byte) error {
		if got := hex.EncodeToString(priv); got != wifTestKeyHex {
			t.Fatalf("imported key mismatch:\n got %s\nwant %s", got, wifTestKeyHex)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithPrivateKey: %v", err)
	}
}

func TestWithWIFExportMatchesCompressedVector(t *testing.T) {
	key := mustHex(t, wifTestKeyHex)
	w, err := FromPrivateKeyBytes(key, Secp256k1)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	var got string
	if err := w.WithWIF(BTC, 0, func(wif []byte) error {
		got = string(wif)
		return nil
	}); err != nil {
		t.Fatalf("WithWIF: %v", err)
	}
	if got != wifCompressed {
		t.Fatalf("exported WIF mismatch:\n got %s\nwant %s", got, wifCompressed)
	}

	// memguard-buffer form matches too.
	buf, err := w.WIF(BTC, 0)
	if err != nil {
		t.Fatalf("WIF: %v", err)
	}
	defer buf.Destroy()
	if string(buf.Bytes()) != wifCompressed {
		t.Fatalf("WIF buffer mismatch:\n got %s\nwant %s", string(buf.Bytes()), wifCompressed)
	}
}

func TestWIFErrors(t *testing.T) {
	// Bad base58 / checksum.
	if _, err := FromWIF([]byte("not-a-wif")); !errors.Is(err, ErrInvalidWIF) {
		t.Fatalf("FromWIF(bad) error = %v, want ErrInvalidWIF", err)
	}
	// WIF export for a non-secp256k1 coin must fail.
	mn := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	sw, err := FromMnemonic(mn)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer sw.Destroy()
	if err := sw.WithWIF(SOL, 0, func([]byte) error { return nil }); !errors.Is(err, ErrInvalidWIF) {
		t.Fatalf("WithWIF(SOL) error = %v, want ErrInvalidWIF", err)
	}
}
