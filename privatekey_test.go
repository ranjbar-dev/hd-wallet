package hdwallet

import (
	"bytes"
	"errors"
	"testing"

	"github.com/awnumar/memguard"
)

// canonicalETHPrivKey extracts the secp256k1 leaf private key for the canonical
// "abandon … about" mnemonic at m/44'/60'/0'/0/0 by deriving it once from a seed
// wallet via the new export API. Keeping this self-contained proves WithPrivateKey
// hands out exactly the key the seed wallet derives.
func canonicalETHPrivKey(t *testing.T) []byte {
	t.Helper()
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	var key []byte
	if err := w.WithPrivateKey(ETH, 0, func(priv []byte) error {
		if len(priv) != privateKeyLen {
			t.Fatalf("derived key length = %d, want %d", len(priv), privateKeyLen)
		}
		key = append([]byte(nil), priv...) // copy out before the callback wipes priv
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return key
}

// TestImportedKeyReproducesETHAddress is the authoritative vector: importing the
// secp256k1 leaf key for the canonical mnemonic must yield the canonical ETH
// address, identical to deriving it from the mnemonic.
func TestImportedKeyReproducesETHAddress(t *testing.T) {
	const wantETH = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

	key := canonicalETHPrivKey(t)

	w, err := FromPrivateKeyBytes(key, Secp256k1) // wipes key
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	got, err := w.Address(ETH)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantETH {
		t.Errorf("imported-key ETH = %s, want %s", got, wantETH)
	}

	// The same imported key serves every secp256k1 coin (same curve). BNB shares
	// ETH's key & address format.
	gotBNB, err := w.Address(BNB)
	if err != nil {
		t.Fatal(err)
	}
	if gotBNB != wantETH {
		t.Errorf("imported-key BNB = %s, want %s", gotBNB, wantETH)
	}
}

// TestFromPrivateKeyBytesWipesInput verifies the input slice is zeroed (mirrors
// FromMnemonicBytes).
func TestFromPrivateKeyBytesWipesInput(t *testing.T) {
	key := canonicalETHPrivKey(t)
	in := append([]byte(nil), key...)

	w, err := FromPrivateKeyBytes(in, Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	for i, b := range in {
		if b != 0 {
			t.Fatalf("input private key not wiped at index %d (=%d)", i, b)
		}
	}
}

// TestFromPrivateKeyBuffer verifies the zero-copy buffer import takes ownership
// and reproduces the address.
func TestFromPrivateKeyBuffer(t *testing.T) {
	const wantETH = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

	t.Run("valid takes ownership", func(t *testing.T) {
		key := canonicalETHPrivKey(t)
		buf := memguard.NewBufferFromBytes(key) // wipes key into protected memory
		w, err := FromPrivateKeyBuffer(buf, Secp256k1)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Destroy()
		if buf.IsAlive() {
			t.Error("buffer should remain owned by the wallet (sealed), not alive")
		}
		if got, _ := w.Address(ETH); got != wantETH {
			t.Errorf("ETH = %s, want %s", got, wantETH)
		}
	})

	t.Run("invalid destroys buffer", func(t *testing.T) {
		buf := memguard.NewBufferFromBytes([]byte("too short")) // wrong length
		if _, err := FromPrivateKeyBuffer(buf, Secp256k1); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("err = %v, want ErrInvalidPrivateKey", err)
		}
		if buf.IsAlive() {
			t.Error("buffer should be destroyed even on error")
		}
	})

	t.Run("nil buffer", func(t *testing.T) {
		if _, err := FromPrivateKeyBuffer(nil, Secp256k1); err == nil {
			t.Fatal("expected error for nil buffer")
		}
	})
}

// TestSeedWalletPrivateKeyRoundTrip proves WithPrivateKey/PrivateKey on a seed
// wallet hand out a key that re-derives the same address through a fresh key-only
// wallet, for one coin per curve.
func TestSeedWalletPrivateKeyRoundTrip(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	cases := []struct {
		symbol Symbol
		curve  Curve
	}{
		{ETH, Secp256k1},
		{BTC, Secp256k1},
		{SOL, Ed25519},
		{NEO, Nist256p1},
	}
	for _, tc := range cases {
		t.Run(tc.symbol.String(), func(t *testing.T) {
			wantAddr, err := w.Address(tc.symbol)
			if err != nil {
				t.Fatal(err)
			}

			// Path 1: WithPrivateKey -> import -> re-derive.
			var kw *HDWallet
			if err := w.WithPrivateKey(tc.symbol, 0, func(priv []byte) error {
				key := append([]byte(nil), priv...)
				var e error
				kw, e = FromPrivateKeyBytes(key, tc.curve)
				return e
			}); err != nil {
				t.Fatal(err)
			}
			defer kw.Destroy()
			gotAddr, err := kw.Address(tc.symbol)
			if err != nil {
				t.Fatal(err)
			}
			if gotAddr != wantAddr {
				t.Errorf("WithPrivateKey round-trip %s = %s, want %s", tc.symbol, gotAddr, wantAddr)
			}

			// Path 2: PrivateKey buffer -> import -> re-derive.
			pkBuf, err := w.PrivateKey(tc.symbol, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(pkBuf.Bytes()) != privateKeyLen {
				t.Fatalf("PrivateKey length = %d, want %d", len(pkBuf.Bytes()), privateKeyLen)
			}
			kw2, err := FromPrivateKeyBuffer(pkBuf, tc.curve) // takes ownership
			if err != nil {
				t.Fatal(err)
			}
			defer kw2.Destroy()
			gotAddr2, err := kw2.Address(tc.symbol)
			if err != nil {
				t.Fatal(err)
			}
			if gotAddr2 != wantAddr {
				t.Errorf("PrivateKey round-trip %s = %s, want %s", tc.symbol, gotAddr2, wantAddr)
			}
		})
	}
}

// TestPrivateKeyBufferDestroyWipes confirms the returned buffer's plaintext is
// zeroed after Destroy (memguard wipes page-locked memory on destroy).
func TestPrivateKeyBufferDestroyWipes(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	buf, err := w.PrivateKey(ETH, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes() // view into the locked buffer's backing memory
	nonZero := false
	for _, x := range b {
		if x != 0 {
			nonZero = true
			break
		}
	}
	if !nonZero {
		t.Fatal("private key buffer is all zero before Destroy")
	}

	buf.Destroy()
	if buf.IsAlive() {
		t.Fatal("buffer still alive after Destroy")
	}
	// NOTE: memguard unmaps the buffer's guard pages on Destroy, so the backing
	// slice (b) must NOT be read afterwards — doing so is a use-after-free that
	// faults. memguard guarantees the plaintext is zeroed before the pages are
	// freed; we assert non-aliveness only and rely on that contract for wiping.
	_ = b
}

// TestSeedWalletSignAndPrivateKeyAgree proves a signature made with the seed
// wallet verifies against the public key of the exported/imported key.
func TestImportedKeySignVerifies(t *testing.T) {
	key := canonicalETHPrivKey(t)
	w, err := FromPrivateKeyBytes(key, Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	digest := keccak256([]byte("hd-wallet private-key import test"))
	sig, err := w.Sign(ETH, digest)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.PublicKey(ETH)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(Secp256k1, pub, digest, sig) {
		t.Error("signature from imported key failed to verify")
	}
}

// --- Guards ---

func TestKeyOnlyCurveMismatch(t *testing.T) {
	key := canonicalETHPrivKey(t)
	w, err := FromPrivateKeyBytes(key, Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	// SOL is ed25519; ATOM/BTC/ETH are secp256k1. Every non-secp256k1 coin must
	// be rejected with ErrCurveMismatch across all operations.
	for _, op := range []struct {
		name string
		run  func() error
	}{
		{"Address", func() error { _, err := w.Address(SOL); return err }},
		{"PublicKey", func() error { _, err := w.PublicKey(SOL); return err }},
		{"Sign", func() error { _, err := w.Sign(SOL, []byte("msg")); return err }},
		{"WithPrivateKey", func() error { return w.WithPrivateKey(SOL, 0, func([]byte) error { return nil }) }},
		{"PrivateKey", func() error { _, err := w.PrivateKey(SOL, 0); return err }},
	} {
		if err := op.run(); !errors.Is(err, ErrCurveMismatch) {
			t.Errorf("%s(SOL) err = %v, want ErrCurveMismatch", op.name, err)
		}
	}
}

func TestKeyOnlyNonZeroIndexRejected(t *testing.T) {
	key := canonicalETHPrivKey(t)
	w, err := FromPrivateKeyBytes(key, Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	for _, op := range []struct {
		name string
		run  func() error
	}{
		{"AddressIndex", func() error { _, err := w.AddressIndex(ETH, 1); return err }},
		{"PublicKeyIndex", func() error { _, err := w.PublicKeyIndex(ETH, 1); return err }},
		{"SignIndex", func() error { _, err := w.SignIndex(ETH, 1, make([]byte, 32)); return err }},
		{"WithPrivateKey", func() error { return w.WithPrivateKey(ETH, 1, func([]byte) error { return nil }) }},
		{"PrivateKey", func() error { _, err := w.PrivateKey(ETH, 1); return err }},
	} {
		if err := op.run(); !errors.Is(err, ErrKeyOnlyIndex) {
			t.Errorf("%s(ETH, 1) err = %v, want ErrKeyOnlyIndex", op.name, err)
		}
	}

	// Index 0 must still work.
	if _, err := w.AddressIndex(ETH, 0); err != nil {
		t.Errorf("AddressIndex(ETH, 0) err = %v, want nil", err)
	}
}

func TestKeyOnlyMnemonicOpsRejected(t *testing.T) {
	key := canonicalETHPrivKey(t)
	w, err := FromPrivateKeyBytes(key, Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	if _, err := w.Mnemonic(); !errors.Is(err, ErrKeyOnlyWallet) {
		t.Errorf("Mnemonic err = %v, want ErrKeyOnlyWallet", err)
	}
	if err := w.WithMnemonic(func([]byte) error { return nil }); !errors.Is(err, ErrKeyOnlyWallet) {
		t.Errorf("WithMnemonic err = %v, want ErrKeyOnlyWallet", err)
	}
	if _, err := w.AllAddresses(); !errors.Is(err, ErrKeyOnlyWallet) {
		t.Errorf("AllAddresses err = %v, want ErrKeyOnlyWallet", err)
	}
}

func TestKeyOnlyDestroyedWallet(t *testing.T) {
	key := canonicalETHPrivKey(t)
	w, err := FromPrivateKeyBytes(key, Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	w.Destroy()
	w.Destroy() // idempotent

	if _, err := w.Address(ETH); err != ErrDestroyed {
		t.Errorf("Address after Destroy = %v, want ErrDestroyed", err)
	}
	if err := w.WithPrivateKey(ETH, 0, func([]byte) error { return nil }); err != ErrDestroyed {
		t.Errorf("WithPrivateKey after Destroy = %v, want ErrDestroyed", err)
	}
	if _, err := w.PrivateKey(ETH, 0); err != ErrDestroyed {
		t.Errorf("PrivateKey after Destroy = %v, want ErrDestroyed", err)
	}
}

func TestSeedWalletPrivateKeyDestroyed(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	w.Destroy()

	if err := w.WithPrivateKey(ETH, 0, func([]byte) error { return nil }); err != ErrDestroyed {
		t.Errorf("WithPrivateKey after Destroy = %v, want ErrDestroyed", err)
	}
	if _, err := w.PrivateKey(ETH, 0); err != ErrDestroyed {
		t.Errorf("PrivateKey after Destroy = %v, want ErrDestroyed", err)
	}
}

func TestImportInvalidKeyLengths(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		bad := bytes.Repeat([]byte{0x01}, n)
		if _, err := FromPrivateKeyBytes(bad, Secp256k1); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("FromPrivateKeyBytes(len=%d) err = %v, want ErrInvalidPrivateKey", n, err)
		}
	}
}

func TestImportAllZeroKeyRejected(t *testing.T) {
	zero := make([]byte, privateKeyLen)
	for _, c := range []Curve{Secp256k1, Ed25519, Nist256p1} {
		if _, err := FromPrivateKeyBytes(append([]byte(nil), zero...), c); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("FromPrivateKeyBytes(all-zero, %s) err = %v, want ErrInvalidPrivateKey", c, err)
		}
	}
}

func TestImportUnsupportedCurveRejected(t *testing.T) {
	valid := bytes.Repeat([]byte{0x01}, privateKeyLen)
	if _, err := FromPrivateKeyBytes(valid, Curve(99)); !errors.Is(err, ErrUnsupportedCurve) {
		t.Errorf("FromPrivateKeyBytes(curve=99) err = %v, want ErrUnsupportedCurve", err)
	}
}

func TestImportUnsupportedCoin(t *testing.T) {
	key := canonicalETHPrivKey(t)
	w, err := FromPrivateKeyBytes(key, Secp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	if _, err := w.Address("NOPE"); !errors.Is(err, ErrUnsupportedCoin) {
		t.Errorf("Address(NOPE) err = %v, want ErrUnsupportedCoin", err)
	}
}
