package hdwallet

import "testing"

// AllAddressesAt(index) must agree with AddressIndex(chain, index) for every
// supported coin, and AllAddresses() must equal AllAddressesAt(0).
func TestAllAddressesAtMatchesAddressIndex(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	for _, index := range []uint32{0, 1, 5, 100} {
		all, err := w.AllAddressesAt(index)
		if err != nil {
			t.Fatalf("AllAddressesAt(%d): %v", index, err)
		}
		if len(all) != len(SupportedCoins()) {
			t.Fatalf("AllAddressesAt(%d) returned %d entries, want %d", index, len(all), len(SupportedCoins()))
		}
		for _, sym := range SupportedCoins() {
			want, err := w.AddressIndex(sym, index)
			if err != nil {
				t.Fatalf("AddressIndex(%s,%d): %v", sym, index, err)
			}
			if all[sym] != want {
				t.Errorf("AllAddressesAt(%d)[%s] = %q, AddressIndex = %q", index, sym, all[sym], want)
			}
		}
	}
}

func TestAllAddressesEqualsAllAddressesAtZero(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	a, err := w.AllAddresses()
	if err != nil {
		t.Fatal(err)
	}
	b, err := w.AllAddressesAt(0)
	if err != nil {
		t.Fatal(err)
	}
	for sym, addr := range a {
		if b[sym] != addr {
			t.Errorf("%s: AllAddresses=%q AllAddressesAt(0)=%q", sym, addr, b[sym])
		}
	}
}

func TestAllAddressesAtRejectsHardenedIndex(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	if _, err := w.AllAddressesAt(1 << 31); err == nil {
		t.Error("AllAddressesAt(2^31) should error (index out of range)")
	}
}

func TestAllAddressesAtKeyOnlyWallet(t *testing.T) {
	// A key-only wallet has no seed to enumerate; AllAddressesAt must reject it.
	priv := make([]byte, 32)
	priv[31] = 1
	w, err := FromPrivateKeyBytes(priv, Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	if _, err := w.AllAddressesAt(0); err != ErrKeyOnlyWallet {
		t.Errorf("AllAddressesAt on key-only wallet err = %v, want ErrKeyOnlyWallet", err)
	}
}
