package hdwallet

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math/big"

	starkcurve "github.com/consensys/gnark-crypto/ecc/stark-curve"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/fr"
)

// starkex implements the STARK curve (StarkNet/StarkEx). Signing is ECDSA over
// the STARK curve with a deterministic nonce produced by the RFC-6979 HMAC-DRBG
// (SHA-256) variant StarkNet uses (`generate_k_shifted`: each 256-bit candidate
// is right-shifted by 4 bits to fit the 252-bit field, then range-checked). The
// public key is the x-coordinate of d*G as 32 big-endian bytes; the signature is
// r||s, 32 bytes each.
//
// Matches Trust Wallet Core's TWCurveStarkex / starknet-rs.

// starkOrder is the order of the STARK curve group (== fr modulus).
var starkOrder = fr.Modulus()

// starkUpperBound is StarkNet's ELEMENT_UPPER_BOUND = 2^251 + 17*2^192 + 1,
// rounded: starknet enforces r, s, z < 2^251. We use 2^251 as the bound, which
// is the value starknet-rs checks (0x0800...0000).
var starkUpperBound = new(big.Int).Lsh(big.NewInt(1), 251)

var (
	errStarkInvalidScalar = errors.New("hdwallet: starkex: scalar out of range")
	errStarkSign          = errors.New("hdwallet: starkex: could not produce a valid signature")
)

// starkexPublicKey returns the 32-byte big-endian x-coordinate of d*G.
func starkexPublicKey(priv []byte) ([]byte, error) {
	d := new(big.Int).SetBytes(priv)
	if d.Sign() == 0 || d.Cmp(starkOrder) >= 0 {
		return nil, errStarkInvalidScalar
	}
	var p starkcurve.G1Affine
	p.ScalarMultiplicationBase(d)
	var x big.Int
	p.X.BigInt(&x)
	return leftPad(x.Bytes(), 32), nil
}

// signDigestStarkex signs a field-element message hash with deterministic ECDSA
// over the STARK curve. data is the message hash (≤ 32 bytes, big-endian).
func signDigestStarkex(priv, data []byte) (*Signature, error) {
	if len(data) > 32 {
		return nil, ErrInvalidDigest
	}
	d := new(big.Int).SetBytes(priv)
	if d.Sign() == 0 || d.Cmp(starkOrder) >= 0 {
		return nil, errStarkInvalidScalar
	}
	z := new(big.Int).SetBytes(data)

	// Seed-retry loop (ported from cairo-lang via starknet-rs): bump the RFC-6979
	// extra entropy until a usable (r, s) pair is found.
	for seed := 0; seed < 64; seed++ {
		k := starkGenerateK(data, priv, seed)
		if k == nil {
			continue
		}
		sig, ok := starkSignWithK(d, z, k)
		if ok {
			return sig, nil
		}
	}
	return nil, errStarkSign
}

// starkSignWithK computes (r, s) for a fixed nonce k; returns ok=false if the
// candidate must be rejected (r==0, s==0, or out of the StarkNet bound).
func starkSignWithK(d, z, k *big.Int) (*Signature, bool) {
	var R starkcurve.G1Affine
	R.ScalarMultiplicationBase(k)
	var rx big.Int
	R.X.BigInt(&rx)
	r := new(big.Int).Mod(&rx, starkOrder)
	if r.Sign() == 0 || r.Cmp(starkUpperBound) >= 0 {
		return nil, false
	}

	// s = (z + r*d) / k  mod N
	kInv := new(big.Int).ModInverse(k, starkOrder)
	if kInv == nil {
		return nil, false
	}
	s := new(big.Int).Mul(r, d)
	s.Add(s, z)
	s.Mul(s, kInv)
	s.Mod(s, starkOrder)
	if s.Sign() == 0 {
		return nil, false
	}
	// starknet-rs also rejects s outside the bound (it checks s_inv there, but the
	// canonical low form has s < N which is always < 2^252; the upper-bound check
	// mirrors the r check).
	if s.Cmp(starkUpperBound) >= 0 {
		return nil, false
	}

	raw := make([]byte, 64)
	copy(raw[:32], leftPad(r.Bytes(), 32))
	copy(raw[32:], leftPad(s.Bytes(), 32))
	return &Signature{
		Curve: Starkex,
		R:     append([]byte(nil), raw[:32]...),
		S:     append([]byte(nil), raw[32:]...),
		raw:   raw,
	}, true
}

// verifyStarkex verifies a STARK-curve ECDSA signature. pub is the 32-byte
// big-endian x-coordinate of the public key; data is the message hash. Because
// only the x-coordinate is stored, both candidate y values are tried.
func verifyStarkex(pub, data []byte, sig *Signature) bool {
	if len(pub) != 32 || sig == nil || len(sig.R) != 32 || len(sig.S) != 32 {
		return false
	}
	r := new(big.Int).SetBytes(sig.R)
	s := new(big.Int).SetBytes(sig.S)
	if r.Sign() == 0 || r.Cmp(starkUpperBound) >= 0 {
		return false
	}
	if s.Sign() == 0 || s.Cmp(starkOrder) >= 0 {
		return false
	}
	z := new(big.Int).SetBytes(data)

	// w = s^-1 mod N; u1 = z*w; u2 = r*w; R' = u1*G + u2*Q; check R'.x == r.
	w := new(big.Int).ModInverse(s, starkOrder)
	if w == nil {
		return false
	}
	u1 := new(big.Int).Mul(z, w)
	u1.Mod(u1, starkOrder)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, starkOrder)

	for _, q := range starkPubCandidates(pub) {
		var p1, p2, sum starkcurve.G1Affine
		p1.ScalarMultiplicationBase(u1)
		p2.ScalarMultiplication(&q, u2)
		sum.Add(&p1, &p2)
		if sum.IsInfinity() {
			continue
		}
		var x big.Int
		sum.X.BigInt(&x)
		x.Mod(&x, starkOrder)
		if x.Cmp(r) == 0 {
			return true
		}
	}
	return false
}

// starkPubCandidates reconstructs the two possible public-key points from the
// stored x-coordinate.
func starkPubCandidates(xBytes []byte) []starkcurve.G1Affine {
	x := new(big.Int).SetBytes(xBytes)
	// Build the uncompressed encodings for both y parities and decode whichever
	// lands on the curve. gnark's SetBytes(compressed) handles the parity, so try
	// both compressed flag bytes.
	out := make([]starkcurve.G1Affine, 0, 2)
	xb := leftPad(x.Bytes(), 32)
	for _, flag := range []byte{0x80, 0xa0} { // compressed, y even / y odd masks
		buf := make([]byte, 32)
		copy(buf, xb)
		buf[0] |= flag
		var p starkcurve.G1Affine
		if _, err := p.SetBytes(buf); err == nil && p.IsOnCurve() {
			out = append(out, p)
		}
	}
	return out
}

// starkGenerateK implements StarkNet's RFC-6979 HMAC-DRBG(SHA-256) nonce
// generation with the 4-bit right shift (`generate_k_shifted`). seed is the
// extra-entropy counter; it is encoded big-endian with leading zero bytes
// stripped, matching starknet-rs.
func starkGenerateK(msgHash, priv []byte, seed int) *big.Int {
	holen := sha256.Size

	x := leftPad(priv, 32)     // private key, 32 bytes big-endian
	h1 := leftPad(msgHash, 32) // message hash, 32 bytes big-endian

	// Extra entropy: the seed as big-endian bytes with leading zeros stripped
	// (matches starknet-rs, which strips to the first non-zero byte).
	var extra []byte
	if seed > 0 {
		extra = stripLeadingZeros(big.NewInt(int64(seed)).Bytes())
	}

	// RFC 6979 §3.2 HMAC-DRBG initialisation with SHA-256.
	k := make([]byte, holen) // all zero
	v := make([]byte, holen)
	for i := range v {
		v[i] = 0x01
	}
	k = hmacSHA256(k, concat(v, []byte{0x00}, x, h1, extra))
	v = hmacSHA256(k, v)
	k = hmacSHA256(k, concat(v, []byte{0x01}, x, h1, extra))
	v = hmacSHA256(k, v)

	// StarkNet `generate_k_shifted`: draw exactly 32 bytes, interpret big-endian,
	// then right-shift by 4 bits to land in the 252-bit field. Reject and reseed
	// if out of [1, n).
	for {
		v = hmacSHA256(k, v)
		cand := new(big.Int).SetBytes(v) // 256-bit candidate
		cand.Rsh(cand, 4)
		if cand.Sign() != 0 && cand.Cmp(starkOrder) < 0 {
			return cand
		}
		k = hmacSHA256(k, append(append([]byte(nil), v...), 0x00))
		v = hmacSHA256(k, v)
	}
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func stripLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return b[i:]
}

// withStarkexPrivateKey derives a STARK private key from the seed using EIP-2645
// grinding over the secp256k1 leaf key. NOTE: provisional — see starkex_test.go.
func withStarkexPrivateKey(seed []byte, path []uint32, fn func(priv []byte) error) error {
	return withSecp256k1PrivateKey(seed, path, func(leaf []byte) error {
		ground := starkGrindKey(leaf)
		defer wipe(ground)
		return fn(ground)
	})
}

// starkGrindKey implements the StarkNet EIP-2645 key-grinding: repeatedly hash
// (key || i) with SHA-256 until the result is below the largest multiple of the
// STARK order that fits in 256 bits, then reduce mod the order.
func starkGrindKey(key []byte) []byte {
	const sha256Bits = 256
	n := starkOrder
	// limit = floor(2^256 / n) * n
	twoPow256 := new(big.Int).Lsh(big.NewInt(1), sha256Bits)
	limit := new(big.Int).Div(twoPow256, n)
	limit.Mul(limit, n)

	key32 := leftPad(key, 32)
	for i := 0; i < 100000; i++ {
		h := sha256.Sum256(append(append([]byte(nil), key32...), byte(i)))
		cand := new(big.Int).SetBytes(h[:])
		if cand.Cmp(limit) < 0 {
			cand.Mod(cand, n)
			return leftPad(cand.Bytes(), 32)
		}
	}
	// Astronomically unlikely; fall back to a plain reduction.
	cand := new(big.Int).SetBytes(key32)
	cand.Mod(cand, n)
	return leftPad(cand.Bytes(), 32)
}
