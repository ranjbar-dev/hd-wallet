package hdwallet

import (
	"errors"
	"testing"
)

// The custom-path methods are anchored to Address/AddressIndex, which are
// themselves verified byte-for-byte against Trust Wallet Core vectors. Where a
// custom path names the same leaf as an index-based call, the two MUST agree —
// so these consistency checks transitively inherit the TWC-vector guarantee,
// while the sign/verify round-trips and error cases exercise the new code paths.

func newPathTestWallet(t *testing.T) *HDWallet {
	t.Helper()
	w, err := FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	return w
}

func TestAddressPathMatchesIndexMethods(t *testing.T) {
	w := newPathTestWallet(t)
	defer w.Destroy()

	cases := []struct {
		name string
		got  func() (string, error)
		want func() (string, error)
	}{
		{"ETH default == Address", func() (string, error) { return w.AddressPath(ETH, "m/44'/60'/0'/0/0") }, func() (string, error) { return w.Address(ETH) }},
		{"ETH index1 == AddressIndex", func() (string, error) { return w.AddressPath(ETH, "m/44'/60'/0'/0/1") }, func() (string, error) { return w.AddressIndex(ETH, 1) }},
		{"BTC index1 == AddressIndex", func() (string, error) { return w.AddressPath(BTC, "m/84'/0'/0'/0/1") }, func() (string, error) { return w.AddressIndex(BTC, 1) }},
		{"AddressAt(0,0,5) == AddressPath", func() (string, error) { return w.AddressAt(ETH, 0, 0, 5) }, func() (string, error) { return w.AddressPath(ETH, "m/44'/60'/0'/0/5") }},
		{"AddressAt(0,0,1) == AddressIndex", func() (string, error) { return w.AddressAt(BTC, 0, 0, 1) }, func() (string, error) { return w.AddressIndex(BTC, 1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.got()
			if err != nil {
				t.Fatalf("got: %v", err)
			}
			want, err := tc.want()
			if err != nil {
				t.Fatalf("want: %v", err)
			}
			if got != want {
				t.Fatalf("mismatch: got %s, want %s", got, want)
			}
		})
	}
}

// TestAccountDerivationDistinctAndStable confirms that varying the (hardened)
// account element produces a different, valid, deterministic address.
func TestAccountDerivationDistinctAndStable(t *testing.T) {
	w := newPathTestWallet(t)
	defer w.Destroy()

	acct0, err := w.AddressAt(ETH, 0, 0, 0)
	if err != nil {
		t.Fatalf("account 0: %v", err)
	}
	acct1, err := w.AddressAt(ETH, 1, 0, 0)
	if err != nil {
		t.Fatalf("account 1: %v", err)
	}
	if acct0 == acct1 {
		t.Fatalf("account 1 derived the same address as account 0 (%s)", acct0)
	}
	def, _ := w.Address(ETH)
	if acct0 != def {
		t.Fatalf("account 0 / change 0 / index 0 (%s) != default Address (%s)", acct0, def)
	}
	// Deterministic.
	acct1again, err := w.AddressAt(ETH, 1, 0, 0)
	if err != nil || acct1again != acct1 {
		t.Fatalf("account-1 derivation not stable: %s vs %s (err %v)", acct1, acct1again, err)
	}
}

// TestSignPathRoundTrip signs a digest at a custom path and verifies with the
// public key derived at the same path.
func TestSignPathRoundTrip(t *testing.T) {
	w := newPathTestWallet(t)
	defer w.Destroy()

	const path = "m/44'/60'/2'/0/3"
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	sig, err := w.SignPath(ETH, path, digest)
	if err != nil {
		t.Fatalf("SignPath: %v", err)
	}
	pub, err := w.PublicKeyPath(ETH, path)
	if err != nil {
		t.Fatalf("PublicKeyPath: %v", err)
	}
	if !Verify(Secp256k1, pub, digest, sig) {
		t.Fatalf("signature from SignPath failed verification against PublicKeyPath")
	}
	// A different path must not verify the same signature.
	otherPub, err := w.PublicKeyPath(ETH, "m/44'/60'/2'/0/4")
	if err != nil {
		t.Fatalf("PublicKeyPath other: %v", err)
	}
	if Verify(Secp256k1, otherPub, digest, sig) {
		t.Fatalf("signature verified under the wrong path's public key")
	}
}

// TestWithPrivateKeyPathConsistency confirms the exported leaf key at a custom
// path produces the same public key PublicKeyPath reports.
func TestWithPrivateKeyPathConsistency(t *testing.T) {
	w := newPathTestWallet(t)
	defer w.Destroy()

	const path = "m/84'/0'/1'/0/2"
	want, err := w.PublicKeyPath(BTC, path)
	if err != nil {
		t.Fatalf("PublicKeyPath: %v", err)
	}
	err = w.WithPrivateKeyPath(BTC, path, func(priv []byte) error {
		got, e := publicKeyFromPriv(Secp256k1, priv)
		if e != nil {
			return e
		}
		if string(got) != string(want) {
			t.Fatalf("WithPrivateKeyPath public key mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithPrivateKeyPath: %v", err)
	}
}

func TestPathErrorCases(t *testing.T) {
	w := newPathTestWallet(t)
	defer w.Destroy()

	// SOL's template is "m/44'/501'/0'" (3 elements) -> structured helper rejects.
	if _, err := w.AddressAt(SOL, 0, 0, 0); !errors.Is(err, ErrPathArity) {
		t.Fatalf("AddressAt(SOL) error = %v, want ErrPathArity", err)
	}
	// Unknown chain.
	if _, err := w.AddressPath("NOPE", "m/44'/60'/0'/0/0"); !errors.Is(err, ErrUnsupportedCoin) {
		t.Fatalf("AddressPath(NOPE) error = %v, want ErrUnsupportedCoin", err)
	}
	// Malformed path.
	if _, err := w.AddressPath(ETH, "not-a-path"); err == nil {
		t.Fatalf("AddressPath with bad path: expected error")
	}

	// Key-only wallet rejects custom paths.
	kw, err := FromPrivateKeyBytes([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}, Secp256k1)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer kw.Destroy()
	if _, err := kw.AddressPath(ETH, "m/44'/60'/0'/0/0"); !errors.Is(err, ErrKeyOnlyWallet) {
		t.Fatalf("key-only AddressPath error = %v, want ErrKeyOnlyWallet", err)
	}
}
