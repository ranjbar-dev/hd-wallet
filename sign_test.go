package hdwallet

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func signTestWallet(t *testing.T) *HDWallet {
	t.Helper()
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// recoverSecp rebuilds the btcec compact form [27+recid || R || S] and recovers
// the signing public key from a recoverable signature.
func recoverSecp(t *testing.T, sig *Signature, digest []byte) *btcec.PublicKey {
	t.Helper()
	compact := make([]byte, 65)
	compact[0] = 27 + sig.RecoveryID
	copy(compact[1:33], sig.R)
	copy(compact[33:65], sig.S)
	pub, _, err := btcecdsa.RecoverCompact(compact, digest)
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	return pub
}

// TestSignSecp256k1 covers sign/verify, RFC 6979 determinism, and public-key
// recovery for a secp256k1 chain.
func TestSignSecp256k1(t *testing.T) {
	w := signTestWallet(t)
	defer w.Destroy()

	digest := sha256.Sum256([]byte("hd-wallet signing test"))
	sig, err := w.Sign(BTC, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.PublicKey(BTC)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(Secp256k1, pub, digest[:], sig) {
		t.Fatal("signature did not verify")
	}
	// Tampered digest must not verify.
	bad := digest
	bad[0] ^= 0xff
	if Verify(Secp256k1, pub, bad[:], sig) {
		t.Error("signature verified against a tampered digest")
	}
	// RFC 6979: signing the same digest twice is deterministic.
	sig2, _ := w.Sign(BTC, digest[:])
	if !bytes.Equal(sig.Bytes(), sig2.Bytes()) {
		t.Error("secp256k1 signing is not deterministic (RFC 6979 expected)")
	}
	// Recovery: the recoverable signature recovers the signing public key.
	if rec := recoverSecp(t, sig, digest[:]).SerializeCompressed(); !bytes.Equal(rec, pub) {
		t.Errorf("recovered pubkey %x != signing pubkey %x", rec, pub)
	}
	if len(sig.Recoverable()) != 65 {
		t.Errorf("Recoverable() len = %d, want 65", len(sig.Recoverable()))
	}
}

// TestSignEthereumEcrecover is the strong independent anchor: sign a keccak256
// digest, ecrecover the address from the 65-byte signature, and assert it equals
// the known Ethereum address for the canonical mnemonic. This proves secp256k1
// signing + recovery end-to-end against a value derived from Trust Wallet.
func TestSignEthereumEcrecover(t *testing.T) {
	w := signTestWallet(t)
	defer w.Destroy()

	const wantAddr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
	digest := keccak256([]byte("some ethereum transaction hash input"))
	sig, err := w.Sign(ETH, digest)
	if err != nil {
		t.Fatal(err)
	}

	// Address from the recovered key: uncompressed (drop 0x04), keccak, last 20.
	uncompressed := recoverSecp(t, sig, digest).SerializeUncompressed()
	addr := eip55(keccak256(uncompressed[1:])[12:])
	if addr != wantAddr {
		t.Errorf("ecrecovered address = %s, want %s", addr, wantAddr)
	}
}

// TestSignEd25519 covers sign/verify for an ed25519 chain, including that the
// message (not a 32-byte digest) is signed directly.
func TestSignEd25519(t *testing.T) {
	w := signTestWallet(t)
	defer w.Destroy()

	msg := []byte("an arbitrary-length solana message, not a 32-byte digest")
	sig, err := w.Sign(SOL, msg)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := w.PublicKey(SOL)
	if !Verify(Ed25519, pub, msg, sig) {
		t.Fatal("ed25519 signature did not verify")
	}
	if Verify(Ed25519, pub, append(msg, '!'), sig) {
		t.Error("ed25519 signature verified against a tampered message")
	}
	if len(sig.Bytes()) != 64 {
		t.Errorf("ed25519 sig len = %d, want 64", len(sig.Bytes()))
	}
	if sig.Recoverable() != nil || sig.DER() != nil {
		t.Error("ed25519 signature must not expose Recoverable/DER")
	}
}

// TestSignDigestValidation ensures ECDSA chains require a 32-byte digest while
// ed25519 accepts any-length messages.
func TestSignDigestValidation(t *testing.T) {
	w := signTestWallet(t)
	defer w.Destroy()

	for _, sym := range []Chain{BTC, ETH} {
		if _, err := w.Sign(sym, []byte("too short")); !errors.Is(err, ErrInvalidDigest) {
			t.Errorf("%s: Sign(non-32-byte) error = %v, want ErrInvalidDigest", sym, err)
		}
	}
	if _, err := w.Sign(SOL, []byte("short message is fine for ed25519")); err != nil {
		t.Errorf("ed25519 Sign(message) unexpected error: %v", err)
	}
}

// TestSignIndexVariesKey checks that different address indices sign with
// different keys (distinct signatures for the same digest).
func TestSignIndexVariesKey(t *testing.T) {
	w := signTestWallet(t)
	defer w.Destroy()

	digest := sha256.Sum256([]byte("index test"))
	s0, _ := w.SignIndex(BTC, 0, digest[:])
	s1, _ := w.SignIndex(BTC, 1, digest[:])
	if bytes.Equal(s0.Bytes(), s1.Bytes()) {
		t.Error("SignIndex(0) and SignIndex(1) produced identical signatures")
	}
	// Each must verify under its own public key.
	p0, _ := w.PublicKeyIndex(BTC, 0)
	p1, _ := w.PublicKeyIndex(BTC, 1)
	if !Verify(Secp256k1, p0, digest[:], s0) || !Verify(Secp256k1, p1, digest[:], s1) {
		t.Error("per-index signature/pubkey mismatch")
	}
}

// TestPublicKeyMatchesAddress ties PublicKey back to address derivation: the
// returned key must encode to the same address Address() produces.
func TestPublicKeyMatchesAddress(t *testing.T) {
	w := signTestWallet(t)
	defer w.Destroy()

	for _, sym := range []Chain{BTC, ETH, SOL, ATOM} {
		pub, err := w.PublicKey(sym)
		if err != nil {
			t.Fatalf("%s: %v", sym, err)
		}
		coin, _ := CoinInfo(sym)
		want, _ := coin.Encode(pub)
		got, _ := w.Address(sym)
		if got != want {
			t.Errorf("%s: encode(PublicKey) = %s, Address = %s", sym, want, got)
		}
	}
}

// TestSignErrors covers destroyed wallet and unknown coin.
func TestSignErrors(t *testing.T) {
	w := signTestWallet(t)
	digest := sha256.Sum256([]byte("x"))

	if _, err := w.Sign("NOPE", digest[:]); !errors.Is(err, ErrUnsupportedCoin) {
		t.Errorf("unknown coin error = %v, want ErrUnsupportedCoin", err)
	}
	w.Destroy()
	if _, err := w.Sign(BTC, digest[:]); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Sign after Destroy = %v, want ErrDestroyed", err)
	}
	if _, err := w.PublicKey(BTC); !errors.Is(err, ErrDestroyed) {
		t.Errorf("PublicKey after Destroy = %v, want ErrDestroyed", err)
	}
}
