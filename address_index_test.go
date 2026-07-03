package hdwallet

import (
	"errors"
	"testing"
)

// TestAddressIndexBIP84Vectors anchors AddressIndex against the BIP-84
// specification's first two receive addresses for the canonical mnemonic.
func TestAddressIndexBIP84Vectors(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	cases := []struct {
		index uint32
		want  string
	}{
		{0, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"},
		{1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"},
	}
	for _, tc := range cases {
		got, err := w.AddressIndex("BTC", tc.index)
		if err != nil {
			t.Fatalf("AddressIndex(BTC, %d): %v", tc.index, err)
		}
		if got != tc.want {
			t.Errorf("AddressIndex(BTC, %d) = %q, want %q", tc.index, got, tc.want)
		}
	}
}

// TestAddressIndexZeroMatchesAddress checks that AddressIndex(symbol, 0) is
// identical to the original Address(symbol) across every supported curve.
func TestAddressIndexZeroMatchesAddress(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	// BTC/ETH: secp256k1; SOL: ed25519 (final hardened); ATOM: cosmos
	// secp256k1.
	for _, symbol := range []Symbol{BTC, ETH, SOL, ATOM} {
		want, err := w.Address(symbol)
		if err != nil {
			t.Fatalf("Address(%s): %v", symbol, err)
		}
		got, err := w.AddressIndex(symbol, 0)
		if err != nil {
			t.Fatalf("AddressIndex(%s, 0): %v", symbol, err)
		}
		if got != want {
			t.Errorf("AddressIndex(%s, 0) = %q, want Address = %q", symbol, got, want)
		}
	}
}

// TestAddressIndexDistinctIndices verifies that different indices yield
// different addresses, for both a path ending in /0/0 (BTC) and a path ending
// in a hardened element (SOL, m/44'/501'/0').
func TestAddressIndexDistinctIndices(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	for _, symbol := range []Symbol{BTC, SOL} {
		a0, err := w.AddressIndex(symbol, 0)
		if err != nil {
			t.Fatalf("AddressIndex(%s, 0): %v", symbol, err)
		}
		a1, err := w.AddressIndex(symbol, 1)
		if err != nil {
			t.Fatalf("AddressIndex(%s, 1): %v", symbol, err)
		}
		if a0 == a1 {
			t.Errorf("AddressIndex(%s, 0) == AddressIndex(%s, 1) = %q; expected distinct", symbol, symbol, a0)
		}
	}
}

// TestAddressIndexOutOfRange rejects indices at or above the hardened boundary.
func TestAddressIndexOutOfRange(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	for _, index := range []uint32{hardenedOffset, hardenedOffset + 1, ^uint32(0)} {
		if _, err := w.AddressIndex("BTC", index); err == nil {
			t.Errorf("AddressIndex(BTC, %d) = nil error, want out-of-range error", index)
		}
	}
}

// TestAddressIndexUnsupportedCoin returns an ErrUnsupportedCoin-wrapped error
// for an unknown symbol.
func TestAddressIndexUnsupportedCoin(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	_, err = w.AddressIndex("NOPE", 0)
	if !errors.Is(err, ErrUnsupportedCoin) {
		t.Errorf("AddressIndex(NOPE, 0) error = %v, want wrapping ErrUnsupportedCoin", err)
	}
}
