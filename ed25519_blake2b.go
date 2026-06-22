package hdwallet

import (
	"crypto/subtle"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"
)

// ed25519-blake2b (Nano) is the standard EdDSA construction with the internal
// 512-bit hash replaced by BLAKE2b-512. The leaf private key (a 32-byte seed) is
// produced by SLIP-0010 ed25519 derivation; everything below operates on that
// seed exactly as RFC 8032 does for ed25519, but hashing with BLAKE2b.

// blake2bExpand expands a 32-byte ed25519 seed into the clamped scalar and the
// 32-byte nonce prefix, using BLAKE2b-512 instead of SHA-512. Mirrors the
// reference Nano/ed25519-blake2b key expansion. The returned scalar and prefix
// are caller-owned; h is wiped here.
func blake2bExpand(seed []byte) (*edwards25519.Scalar, []byte, error) {
	h := blake2b.Sum512(seed)
	defer wipe(h[:])

	// SetBytesWithClamping applies the RFC 8032 clamping (clear low 3 bits, set
	// bit 254, clear bit 255) to the low 32 bytes and reduces mod L.
	scalar, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		return nil, nil, err
	}
	prefix := make([]byte, 32)
	copy(prefix, h[32:])
	return scalar, prefix, nil
}

// blake2bPublicKey computes the 32-byte ed25519-blake2b public key for a seed.
func blake2bPublicKey(seed []byte) ([]byte, error) {
	scalar, prefix, err := blake2bExpand(seed)
	if err != nil {
		return nil, err
	}
	wipe(prefix)
	a := new(edwards25519.Point).ScalarBaseMult(scalar)
	return a.Bytes(), nil
}

// blake2b512 hashes the concatenation of parts with BLAKE2b-512 (64-byte out).
func blake2b512Concat(parts ...[]byte) [64]byte {
	h, _ := blake2b.New512(nil)
	for _, p := range parts {
		h.Write(p)
	}
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

// signMessageEd25519Blake2b produces a 64-byte EdDSA signature over message
// using BLAKE2b-512 as the internal hash (the Nano scheme). priv is the 32-byte
// seed; it is owned and wiped by the caller.
func signMessageEd25519Blake2b(priv, message []byte) (*Signature, error) {
	scalar, prefix, err := blake2bExpand(priv)
	if err != nil {
		return nil, err
	}
	defer wipe(prefix)

	// A = a*B
	a := new(edwards25519.Point).ScalarBaseMult(scalar)
	aBytes := a.Bytes()

	// r = H(prefix || message); R = r*B
	rHash := blake2b512Concat(prefix, message)
	defer wipe(rHash[:])
	rScalar, err := edwards25519.NewScalar().SetUniformBytes(rHash[:])
	if err != nil {
		return nil, err
	}
	R := new(edwards25519.Point).ScalarBaseMult(rScalar)
	rBytes := R.Bytes()

	// k = H(R || A || message)
	kHash := blake2b512Concat(rBytes, aBytes, message)
	defer wipe(kHash[:])
	kScalar, err := edwards25519.NewScalar().SetUniformBytes(kHash[:])
	if err != nil {
		return nil, err
	}

	// s = r + k*a  (mod L)
	s := edwards25519.NewScalar().MultiplyAdd(kScalar, scalar, rScalar)

	sig := make([]byte, 64)
	copy(sig[:32], rBytes)
	copy(sig[32:], s.Bytes())
	return &Signature{Curve: Ed25519Blake2bNano, raw: sig}, nil
}

// verifyEd25519Blake2b verifies a 64-byte ed25519-blake2b signature. pub is the
// 32-byte public key, message is the signed message.
func verifyEd25519Blake2b(pub, message []byte, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}
	A, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return false
	}
	// k = H(R || A || message)
	kHash := blake2b512Concat(sig[:32], pub, message)
	kScalar, err := edwards25519.NewScalar().SetUniformBytes(kHash[:])
	if err != nil {
		return false
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}
	// Recompute R' = s*B - k*A and compare to R.
	minusA := new(edwards25519.Point).Negate(A)
	Rprime := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(kScalar, minusA, s)
	return subtle.ConstantTimeCompare(Rprime.Bytes(), sig[:32]) == 1
}
