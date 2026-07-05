package hdwallet

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// TestVerifySignaturePerCurve signs with a derived key and checks the
// Chain-keyed VerifySignature wrapper accepts the genuine signature for one
// chain per registered curve.
func TestVerifySignaturePerCurve(t *testing.T) {
	w := signTestWallet(t)
	defer w.Destroy()

	digest := sha256.Sum256([]byte("verifysignature per-curve test"))
	msg := []byte("an arbitrary-length ed25519 message, not a 32-byte digest")

	cases := []struct {
		sym  Chain
		data []byte
	}{
		{BTC, digest[:]}, // secp256k1
		{ETH, digest[:]}, // secp256k1 (keccak chain)
		{SOL, msg},       // ed25519
	}
	for _, tc := range cases {
		sig, err := w.SignIndex(tc.sym, 0, tc.data)
		if err != nil {
			t.Fatalf("%s: SignIndex: %v", tc.sym, err)
		}
		pub, err := w.PublicKeyIndex(tc.sym, 0)
		if err != nil {
			t.Fatalf("%s: PublicKeyIndex: %v", tc.sym, err)
		}
		ok, err := VerifySignature(tc.sym, pub, tc.data, sig)
		if err != nil {
			t.Fatalf("%s: VerifySignature: %v", tc.sym, err)
		}
		if !ok {
			t.Errorf("%s: VerifySignature returned false for a genuine signature", tc.sym)
		}
	}
}

// TestVerifySignatureRejectsWrongKeyAndTampered confirms VerifySignature returns
// false for a different public key and for tampered data.
func TestVerifySignatureRejectsWrongKeyAndTampered(t *testing.T) {
	w := signTestWallet(t)
	defer w.Destroy()

	digest := sha256.Sum256([]byte("verifysignature tamper test"))
	sig, err := w.SignIndex(BTC, 0, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := w.PublicKeyIndex(BTC, 0)

	// Wrong key: a different index's public key must not verify.
	wrongPub, _ := w.PublicKeyIndex(BTC, 1)
	if ok, err := VerifySignature(BTC, wrongPub, digest[:], sig); err != nil || ok {
		t.Errorf("VerifySignature(wrong key) = (%v, %v), want (false, nil)", ok, err)
	}

	// Tampered digest must not verify under the genuine key.
	bad := digest
	bad[0] ^= 0xff
	if ok, err := VerifySignature(BTC, pub, bad[:], sig); err != nil || ok {
		t.Errorf("VerifySignature(tampered digest) = (%v, %v), want (false, nil)", ok, err)
	}

	// Tampered ed25519 message must not verify.
	msg := []byte("solana off-chain message")
	solSig, _ := w.SignIndex(SOL, 0, msg)
	solPub, _ := w.PublicKeyIndex(SOL, 0)
	if ok, err := VerifySignature(SOL, solPub, append(msg, '!'), solSig); err != nil || ok {
		t.Errorf("VerifySignature(tampered message) = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestVerifySignatureUnsupportedCoin returns a wrapped ErrUnsupportedCoin for a
// chain not in the registry.
func TestVerifySignatureUnsupportedCoin(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	ok, err := VerifySignature(Chain("NOPE"), make([]byte, 33), digest[:], &Signature{})
	if ok {
		t.Error("VerifySignature(unknown coin) returned true")
	}
	if !errors.Is(err, ErrUnsupportedCoin) {
		t.Errorf("VerifySignature(unknown coin) err = %v, want ErrUnsupportedCoin", err)
	}
}

// TestVerifySignatureInvalidDigest rejects non-32-byte input for ECDSA chains
// with a wrapped ErrInvalidDigest, mirroring SignIndex, while ed25519 accepts
// any-length messages.
func TestVerifySignatureInvalidDigest(t *testing.T) {
	w := signTestWallet(t)
	defer w.Destroy()

	for _, sym := range []Chain{BTC, ETH} {
		pub, _ := w.PublicKeyIndex(sym, 0)
		ok, err := VerifySignature(sym, pub, []byte("too short"), &Signature{})
		if ok {
			t.Errorf("%s: VerifySignature(non-32-byte) returned true", sym)
		}
		if !errors.Is(err, ErrInvalidDigest) {
			t.Errorf("%s: VerifySignature(non-32-byte) err = %v, want ErrInvalidDigest", sym, err)
		}
	}

	// ed25519 accepts a short message: no ErrInvalidDigest, verifies genuinely.
	msg := []byte("short")
	sig, _ := w.SignIndex(SOL, 0, msg)
	pub, _ := w.PublicKeyIndex(SOL, 0)
	if ok, err := VerifySignature(SOL, pub, msg, sig); err != nil || !ok {
		t.Errorf("VerifySignature(SOL, short message) = (%v, %v), want (true, nil)", ok, err)
	}
}
