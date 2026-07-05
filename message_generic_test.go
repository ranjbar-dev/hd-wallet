package hdwallet

import (
	"bytes"
	"errors"
	"testing"
)

// TestSignRawMessageSecp256k1 verifies that SignRawMessage correctly signs a
// 32-byte digest for a secp256k1 coin and returns a verifiable Signature.
// It cross-checks against SignIndex to confirm the two are identical.
func TestSignRawMessageSecp256k1(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	digest := keccak256([]byte("hello world for generic signing"))

	sig1, err := w.SignRawMessage(ETH, 0, digest)
	if err != nil {
		t.Fatalf("SignRawMessage: %v", err)
	}
	sig2, err := w.SignIndex(ETH, 0, digest)
	if err != nil {
		t.Fatalf("SignIndex: %v", err)
	}
	if !bytes.Equal(sig1.Bytes(), sig2.Bytes()) {
		t.Error("SignRawMessage and SignIndex disagree")
	}

	pub, err := w.PublicKey(ETH)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyRawMessage(ETH, pub, digest, sig1)
	if err != nil {
		t.Fatalf("VerifyRawMessage error: %v", err)
	}
	if !ok {
		t.Error("VerifyRawMessage rejected a valid signature")
	}
}

// TestSignRawMessageEd25519 verifies that SignRawMessage accepts an arbitrary
// message (not a 32-byte digest) for an ed25519 coin and the signature verifies.
func TestSignRawMessageEd25519(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	message := []byte("arbitrary ed25519 message — any length is fine")

	sig, err := w.SignRawMessage(SOL, 0, message)
	if err != nil {
		t.Fatalf("SignRawMessage(SOL): %v", err)
	}

	pub, err := w.PublicKey(SOL)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyRawMessage(SOL, pub, message, sig)
	if err != nil {
		t.Fatalf("VerifyRawMessage(SOL): %v", err)
	}
	if !ok {
		t.Error("VerifyRawMessage(SOL) rejected a valid signature")
	}

	// Wrong message must not verify.
	ok2, _ := VerifyRawMessage(SOL, pub, []byte("wrong"), sig)
	if ok2 {
		t.Error("VerifyRawMessage(SOL) accepted a wrong message")
	}
}

// TestSignRawMessageRejectsNonDigestECDSA verifies that a non-32-byte input for
// a secp256k1 coin returns a wrapped ErrInvalidDigest.
func TestSignRawMessageRejectsNonDigestECDSA(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	_, err = w.SignRawMessage(ETH, 0, []byte("not 32 bytes"))
	if err == nil {
		t.Fatal("expected ErrInvalidDigest, got nil")
	}
	if !errors.Is(err, ErrInvalidDigest) {
		t.Errorf("expected ErrInvalidDigest, got %v", err)
	}
}

// TestSignRawMessageUnknownChain verifies that an unknown chain returns
// ErrUnsupportedCoin.
func TestSignRawMessageUnknownChain(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	digest := make([]byte, 32)
	_, err = w.SignRawMessage(Chain("NOPE"), 0, digest)
	if !errors.Is(err, ErrUnsupportedCoin) {
		t.Errorf("expected ErrUnsupportedCoin, got %v", err)
	}
}

// TestVerifyRawMessageUnknownChain verifies that VerifyRawMessage returns
// ErrUnsupportedCoin for an unknown chain.
func TestVerifyRawMessageUnknownChain(t *testing.T) {
	_, err := VerifyRawMessage(Chain("NOPE"), nil, make([]byte, 32), &Signature{Curve: Secp256k1})
	if !errors.Is(err, ErrUnsupportedCoin) {
		t.Errorf("expected ErrUnsupportedCoin, got %v", err)
	}
}

// TestVerifyRawMessageInvalidDigestECDSA verifies that VerifyRawMessage returns
// ErrInvalidDigest for a non-32-byte message on a secp256k1 coin.
func TestVerifyRawMessageInvalidDigestECDSA(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	pub, err := w.PublicKey(ETH)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyRawMessage(ETH, pub, []byte("not 32 bytes"), &Signature{Curve: Secp256k1})
	if !errors.Is(err, ErrInvalidDigest) {
		t.Errorf("expected ErrInvalidDigest, got %v", err)
	}
}
