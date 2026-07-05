package hdwallet

import (
	"errors"
	"testing"
)

// TestAddressRangeMatchesAddressIndex confirms AddressRange returns the same
// addresses, in order, as successive AddressIndex calls.
func TestAddressRangeMatchesAddressIndex(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	const start, count = 0, 5
	got, err := w.AddressRange(BTC, start, count)
	if err != nil {
		t.Fatalf("AddressRange(BTC, %d, %d): %v", start, count, err)
	}
	if len(got) != count {
		t.Fatalf("AddressRange returned %d addresses, want %d", len(got), count)
	}
	for i := uint32(0); i < count; i++ {
		want, err := w.AddressIndex(BTC, start+i)
		if err != nil {
			t.Fatalf("AddressIndex(BTC, %d): %v", start+i, err)
		}
		if got[i] != want {
			t.Errorf("AddressRange[%d] = %q, AddressIndex(%d) = %q", i, got[i], start+i, want)
		}
	}
}

// TestAddressRangeNonZeroStart checks an offset start index lines up with
// AddressIndex.
func TestAddressRangeNonZeroStart(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	const start, count = 10, 3
	got, err := w.AddressRange(ETH, start, count)
	if err != nil {
		t.Fatalf("AddressRange(ETH, %d, %d): %v", start, count, err)
	}
	for i := uint32(0); i < count; i++ {
		want, _ := w.AddressIndex(ETH, start+i)
		if got[i] != want {
			t.Errorf("AddressRange[%d] = %q, AddressIndex(%d) = %q", i, got[i], start+i, want)
		}
	}
}

// TestAddressRangeZeroCount returns an empty, non-nil slice.
func TestAddressRangeZeroCount(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	got, err := w.AddressRange(BTC, 7, 0)
	if err != nil {
		t.Fatalf("AddressRange(BTC, 7, 0): %v", err)
	}
	if got == nil {
		t.Error("AddressRange(count=0) returned nil, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("AddressRange(count=0) len = %d, want 0", len(got))
	}
}

// TestAddressRangeUnsupportedCoin wraps ErrUnsupportedCoin for an unknown chain.
func TestAddressRangeUnsupportedCoin(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	if _, err := w.AddressRange(Chain("NOPE"), 0, 3); !errors.Is(err, ErrUnsupportedCoin) {
		t.Errorf("AddressRange(NOPE) err = %v, want ErrUnsupportedCoin", err)
	}
}

// TestAddressRangeOutOfRange rejects a start+count window that crosses the
// hardened boundary (2^31).
func TestAddressRangeOutOfRange(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	// start+count == 2^31 is the maximum allowed (last index 2^31-1); +1 is over.
	if _, err := w.AddressRange(BTC, (1<<31)-1, 2); err == nil {
		t.Error("AddressRange crossing 2^31 should error (out of range)")
	}
	// A range ending exactly at 2^31 (last index 2^31-1) is allowed.
	if _, err := w.AddressRange(BTC, (1<<31)-1, 1); err != nil {
		t.Errorf("AddressRange ending at 2^31-1 unexpectedly errored: %v", err)
	}
}

// TestAddressRangeDestroyed returns ErrDestroyed after Destroy.
func TestAddressRangeDestroyed(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	w.Destroy()
	if _, err := w.AddressRange(BTC, 0, 3); !errors.Is(err, ErrDestroyed) {
		t.Errorf("AddressRange after Destroy err = %v, want ErrDestroyed", err)
	}
}

// TestAddressRangeKeyOnlyWallet returns ErrKeyOnlyWallet for a private-key-only
// wallet, which has no seed to enumerate.
func TestAddressRangeKeyOnlyWallet(t *testing.T) {
	priv := make([]byte, 32)
	priv[31] = 1
	w, err := FromPrivateKeyBytes(priv, Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	if _, err := w.AddressRange(BTC, 0, 3); !errors.Is(err, ErrKeyOnlyWallet) {
		t.Errorf("AddressRange on key-only wallet err = %v, want ErrKeyOnlyWallet", err)
	}
}
