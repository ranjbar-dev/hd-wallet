package hdwallet

import (
	"crypto/ed25519"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// Curve25519 is the public-key and signing scheme Waves uses. The leaf 32-byte
// private key is derived via SLIP-0010 ed25519 (see derive.go). The public key
// used for the address is the X25519 (Montgomery) point. Signing is a standard
// ed25519 signature (the private key is the ed25519 seed) with the ed25519
// public key's sign bit folded into S[63] — the "curve25519_sign" construction
// from axlsign / trezor-crypto that Trust Wallet Core uses for Waves.

// curve25519PublicKey returns the 32-byte curve25519 (Montgomery) public key for
// a private key, matching Trust Wallet Core: compute the ed25519 public key A
// from the seed (SHA-512 expansion) and convert the Edwards point to its
// Montgomery u-coordinate via u = (1+y)/(1-y). This is identical to TWC's
// ed25519_pk_to_curve25519(ed25519_publickey(priv)).
func curve25519PublicKey(priv []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errInvalidKeyLen("curve25519", len(priv), 32)
	}
	ed := ed25519PublicKeyFromSeed(priv)
	u, ok := edwardsToMontgomery(ed)
	if !ok {
		return nil, errInvalidKeyLen("curve25519", len(priv), 32)
	}
	return u, nil
}

// edwardsToMontgomery converts a 32-byte compressed ed25519 public key to its
// Montgomery u-coordinate: u = (1 + y) / (1 - y)  (mod p), where y is the low 255
// bits of the encoding. Returns false if 1-y is zero.
func edwardsToMontgomery(ed []byte) ([]byte, bool) {
	yBytes := make([]byte, 32)
	copy(yBytes, ed)
	yBytes[31] &= 0x7f // strip the x sign bit to get y
	y, err := new(field.Element).SetBytes(yBytes)
	if err != nil {
		return nil, false
	}
	one := new(field.Element).One()
	num := new(field.Element).Add(one, y)      // 1 + y
	den := new(field.Element).Subtract(one, y) // 1 - y
	if den.Equal(new(field.Element).Zero()) == 1 {
		return nil, false
	}
	den.Invert(den)
	u := new(field.Element).Multiply(num, den)
	return u.Bytes(), true
}

// ed25519PublicKeyFromSeed returns the 32-byte ed25519 public key A for a seed.
func ed25519PublicKeyFromSeed(seed []byte) []byte {
	return ed25519PubFromSeed(append([]byte(nil), seed...))
}

// signMessageCurve25519 signs message with the Waves curve25519 scheme: a
// standard ed25519 signature over the message using priv as the seed, then the
// ed25519 public key's high bit is copied into the signature's last byte.
func signMessageCurve25519(priv, message []byte) (*Signature, error) {
	if len(priv) != ed25519.SeedSize {
		return nil, errInvalidKeyLen("curve25519", len(priv), ed25519.SeedSize)
	}
	key := ed25519.NewKeyFromSeed(priv)
	defer wipe(key)

	sig := ed25519.Sign(key, message)
	a := ed25519PublicKeyFromSeed(priv)

	// Fold the ed25519 public-key sign bit into S[63]; this lets a verifier
	// recover the ed25519 point from the X25519 (Montgomery) public key.
	sig[63] = (sig[63] & 0x7f) | (a[31] & 0x80)
	return &Signature{Curve: Curve25519, raw: sig}, nil
}

// verifyCurve25519 verifies a Waves curve25519 signature given the 32-byte
// X25519 public key. The ed25519 point is reconstructed from the Montgomery
// u-coordinate plus the sign bit carried in S[63].
func verifyCurve25519(pub, message, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}
	// Convert the Montgomery u-coordinate to the Edwards y-coordinate:
	//   y = (u - 1) / (u + 1)  (mod p)
	// and take the sign bit (x parity) from S[63] bit 7.
	edPub, ok := montgomeryToEdwards(pub, sig[63]&0x80)
	if !ok {
		return false
	}
	// Re-create a clean signature with the original sign bit cleared from S[63]
	// before standard ed25519 verification (the bit is not part of S).
	clean := make([]byte, 64)
	copy(clean, sig)
	clean[63] &= 0x7f
	return ed25519.Verify(ed25519.PublicKey(edPub), message, clean)
}

// montgomeryToEdwards converts an X25519 (Montgomery u) public key to the
// equivalent ed25519 (Edwards) compressed public key, applying signBit (0x80 or
// 0) as the x sign. Returns false if the point is invalid.
func montgomeryToEdwards(u []byte, signBit byte) ([]byte, bool) {
	// edwards25519 exposes SetMontgomeryBytes-style conversion via the y
	// coordinate. We compute y = (u-1)/(u+1) over the field using big-arithmetic
	// through the edwards25519 Point API by constructing the compressed encoding
	// directly: the low 255 bits are y, the top bit is the x sign.
	fy, ok := montgomeryUToEdwardsY(u)
	if !ok {
		return nil, false
	}
	fy[31] |= signBit
	// Validate by decoding as an ed25519 point.
	if _, err := new(edwards25519.Point).SetBytes(fy); err != nil {
		return nil, false
	}
	return fy, true
}

// montgomeryUToEdwardsY computes the Edwards y-coordinate (32-byte little-endian
// encoding, top bit cleared) from a Montgomery u-coordinate using the birational
// map y = (u - 1) / (u + 1) over GF(2^255-19). Returns false if u+1 is zero.
func montgomeryUToEdwardsY(u []byte) ([]byte, bool) {
	fu, err := new(field.Element).SetBytes(u)
	if err != nil {
		return nil, false
	}
	one := new(field.Element).One()
	num := new(field.Element).Subtract(fu, one) // u - 1
	den := new(field.Element).Add(fu, one)      // u + 1
	if den.Equal(new(field.Element).Zero()) == 1 {
		return nil, false
	}
	den.Invert(den)
	y := new(field.Element).Multiply(num, den)
	out := y.Bytes() // 32-byte little-endian, bit 255 already 0
	return out, true
}
