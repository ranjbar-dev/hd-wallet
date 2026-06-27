package hdwallet_test

import (
	"encoding/hex"
	"testing"

	hd "github.com/ranjbar-dev/hd-wallet"
)

// BIP-85 test vectors use the library's canonical 12-word test mnemonic.
// The BIP-85 spec itself specifies root keys as xprvs without mandating a
// mnemonic; these values are independently computed from the same secp256k1
// BIP-32 derivation and HMAC-SHA512 algorithm.

const bip85TestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestBIP85Entropy(t *testing.T) {
	w, err := hd.FromMnemonic(bip85TestMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	// path m/83696968'/39'/0'/12'/0' → first 16 bytes of HMAC-SHA512
	var got []byte
	if err := w.BIP85Entropy("39'/0'/12'", 0, 16, func(e []byte) {
		got = make([]byte, len(e))
		copy(got, e)
	}); err != nil {
		t.Fatal(err)
	}
	const wantHex = "ac98dac5d4f4ebad6056682ac95eb9ad"
	if hex.EncodeToString(got) != wantHex {
		t.Errorf("entropy: got %s, want %s", hex.EncodeToString(got), wantHex)
	}
}

func TestBIP85Mnemonic(t *testing.T) {
	w, err := hd.FromMnemonic(bip85TestMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	// 12-word child at index 0
	var got12 []byte
	if err := w.BIP85Mnemonic(12, 0, func(m []byte) {
		got12 = make([]byte, len(m))
		copy(got12, m)
	}); err != nil {
		t.Fatal(err)
	}
	const want12 = "prosper short ramp prepare exchange stove life snack client enough purpose fold"
	if string(got12) != want12 {
		t.Errorf("12-word: got %q, want %q", got12, want12)
	}

	// 24-word child at index 0
	var got24 []byte
	if err := w.BIP85Mnemonic(24, 0, func(m []byte) {
		got24 = make([]byte, len(m))
		copy(got24, m)
	}); err != nil {
		t.Fatal(err)
	}
	const want24 = "stick exact spice sock filter ginger museum horse kit multiply manual wear grief demand derive alert quiz fault december lava picture immune decade jaguar"
	if string(got24) != want24 {
		t.Errorf("24-word: got %q, want %q", got24, want24)
	}
}

func TestBIP85Errors(t *testing.T) {
	w, err := hd.FromMnemonic(bip85TestMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	if err := w.BIP85Mnemonic(15, 0, func([]byte) {}); err == nil {
		t.Error("expected error for unsupported word count 15")
	}
	if err := w.BIP85Entropy("39'/0'/12'", 0, 0, func([]byte) {}); err == nil {
		t.Error("expected error for length 0")
	}
	if err := w.BIP85Entropy("39'/0'/12'", 0, 65, func([]byte) {}); err == nil {
		t.Error("expected error for length 65")
	}
}
