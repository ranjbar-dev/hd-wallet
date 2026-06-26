package hdwallet

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"golang.org/x/crypto/pbkdf2"
)

// Cardano uses BIP32-Ed25519 (CIP-1852) with 64-byte extended private keys. The
// master secret is produced by the Icarus scheme: PBKDF2-HMAC-SHA512 over the
// BIP-39 entropy (NOT the BIP-39 seed) with an empty passphrase, 4096 iterations,
// 96-byte output (kL || kR || chainCode), then kL is clamped. Child keys use the
// Khovratovich/BIP32-Ed25519 derivation (hardened and soft).
//
// A Cardano extended private key here is 96 bytes: kL(32) || kR(32) || chain(32).
// The public key handed to the encoder is the 64-byte point||chain.
//
// Matches Trust Wallet Core's TWCurveED25519ExtendedCardano (Icarus V2).

const cardanoExtendedLen = 96 // kL || kR || chainCode

var (
	errCardanoKeyLen       = errors.New("hdwallet: cardano: invalid extended key length")
	errCardanoNeedsEntropy = errors.New("hdwallet: cardano: derivation requires BIP-39 entropy, not the seed (use withCardanoPrivateKey)")
)

// cardanoNode is a BIP32-Ed25519 node: a 96-byte extended secret (kL||kR||chain).
type cardanoNode struct {
	kL    []byte // 32-byte left scalar (clamped)
	kR    []byte // 32-byte right half
	chain []byte // 32-byte chain code
}

func (n *cardanoNode) wipe() {
	wipe(n.kL)
	wipe(n.kR)
	wipe(n.chain)
}

// cardanoMasterFromEntropy builds the Icarus master node from BIP-39 entropy.
func cardanoMasterFromEntropy(entropy []byte) *cardanoNode {
	// Icarus (CIP-3): PBKDF2(password=passphrase (empty), salt=entropy,
	// iter=4096, dkLen=96, HMAC-SHA512).
	secret := pbkdf2.Key([]byte{}, entropy, 4096, cardanoExtendedLen, sha512.New)
	// Clamp kL per ed25519 (and the BIP32-Ed25519 extra "third-highest bit"
	// constraint: clear bit 5 of byte 31, i.e. byte[31] &= 0x1F before setting
	// 0x40, matching trezor-crypto's hdnode_from_secret_cardano).
	secret[0] &= 0xF8
	secret[31] &= 0x1F
	secret[31] |= 0x40

	n := &cardanoNode{
		kL:    append([]byte(nil), secret[0:32]...),
		kR:    append([]byte(nil), secret[32:64]...),
		chain: append([]byte(nil), secret[64:96]...),
	}
	wipe(secret)
	return n
}

// cardanoScalarFromKL parses kL as a little-endian integer and reduces it mod L
// to obtain the ed25519 secret scalar. kL is ALREADY clamped during master/child
// derivation, so it must NOT be re-clamped here (BIP32-Ed25519 multiplies the
// raw kL by the basepoint, reducing only mod the group order).
func cardanoScalarFromKL(kL []byte) (*edwards25519.Scalar, error) {
	// Reduce the 256-bit little-endian kL modulo L by feeding it as the low half
	// of a 64-byte wide value (high half zero) to SetUniformBytes, which performs
	// the canonical mod-L reduction.
	wide := make([]byte, 64)
	copy(wide[:32], kL)
	defer wipe(wide)
	return edwards25519.NewScalar().SetUniformBytes(wide)
}

// cardanoPoint returns the 32-byte compressed Edwards public key A = kL*B.
func cardanoPoint(kL []byte) ([]byte, error) {
	s, err := cardanoScalarFromKL(kL)
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Point).ScalarBaseMult(s).Bytes(), nil
}

// le32 returns the 4-byte little-endian encoding of an index.
func le32(i uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return b
}

// cardanoDeriveChild performs one BIP32-Ed25519 child derivation step.
func cardanoDeriveChild(n *cardanoNode, index uint32) (*cardanoNode, error) {
	hardened := index >= hardenedOffset
	aPub, err := cardanoPoint(n.kL)
	if err != nil {
		return nil, err
	}

	var zMsg, cMsg []byte
	if hardened {
		// Z = HMAC-SHA512(chain, 0x00 || kL || kR || LE(index))
		zMsg = concat([]byte{0x00}, n.kL, n.kR, le32(index))
		cMsg = concat([]byte{0x01}, n.kL, n.kR, le32(index))
	} else {
		// Z = HMAC-SHA512(chain, 0x02 || A || LE(index))
		zMsg = concat([]byte{0x02}, aPub, le32(index))
		cMsg = concat([]byte{0x03}, aPub, le32(index))
	}

	z := hmacSHA512(n.chain, zMsg)
	defer wipe(z)
	c := hmacSHA512(n.chain, cMsg)
	defer wipe(c)

	// kL_child = (8 * zL[0:28]) + kL  (as little-endian integers, no mod)
	zL := new(big.Int).SetBytes(reverse(z[0:28]))
	zL.Mul(zL, big.NewInt(8))
	parentL := new(big.Int).SetBytes(reverse(n.kL))
	childL := new(big.Int).Add(zL, parentL)
	kLChild := leToFixed(childL, 32)

	// kR_child = (zR + kR) mod 2^256, where zR = z[32:64]
	zR := new(big.Int).SetBytes(reverse(z[32:64]))
	parentR := new(big.Int).SetBytes(reverse(n.kR))
	childR := new(big.Int).Add(zR, parentR)
	childR.Mod(childR, new(big.Int).Lsh(big.NewInt(1), 256))
	kRChild := leToFixed(childR, 32)

	// chain code child = right half of c.
	chainChild := append([]byte(nil), c[32:64]...)

	wipe(zMsg)
	wipe(cMsg)
	return &cardanoNode{kL: kLChild, kR: kRChild, chain: chainChild}, nil
}

// withCardanoPrivateKey derives the Cardano leaf node for the path and hands the
// 96-byte extended key (kL||kR||chain) to fn, wiping it afterwards. The seed
// argument here is the BIP-39 entropy (see secret.go wiring), NOT the BIP-39
// seed, because Icarus derives from entropy.
func withCardanoPrivateKey(entropy []byte, path []uint32, fn func(priv []byte) error) error {
	node := cardanoMasterFromEntropy(entropy)
	// Wipe whatever node is current at return time. A closure (not `defer
	// node.wipe()`) is required because node is reassigned in the loop: a bare
	// method-value defer would bind to the master node and leak the leaf key.
	defer func() { node.wipe() }()
	for _, idx := range path {
		child, err := cardanoDeriveChild(node, idx)
		if err != nil {
			return err
		}
		node.wipe()
		node = child
	}
	ext := make([]byte, cardanoExtendedLen)
	copy(ext[0:32], node.kL)
	copy(ext[32:64], node.kR)
	copy(ext[64:96], node.chain)
	defer wipe(ext)
	return fn(ext)
}

// cardanoStakingPath returns the staking derivation path for a Cardano payment
// path: a CIP-1852 5-element path (m/1852'/1815'/account'/role/index) with the
// role element forced to 2 (the staking role) and the address element forced to
// 0, matching Trust Wallet Core's HDWallet.cpp stakingPath construction. The
// payment path must have exactly 5 elements.
func cardanoStakingPath(payment []uint32) ([]uint32, error) {
	if len(payment) != 5 {
		return nil, errors.New("hdwallet: cardano: path must have 5 elements (m/1852'/1815'/account'/role/index)")
	}
	staking := append([]uint32(nil), payment...)
	staking[3] = 2 // role = 2 (staking), non-hardened
	staking[4] = 0 // address index = 0
	return staking, nil
}

// cardanoPublicKey returns the 64-byte public key (A(32) || chainCode(32)) from a
// 96-byte extended private key.
func cardanoPublicKey(priv []byte) ([]byte, error) {
	if len(priv) != cardanoExtendedLen {
		return nil, errCardanoKeyLen
	}
	a, err := cardanoPoint(priv[0:32])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	copy(out[0:32], a)
	copy(out[32:64], priv[64:96])
	return out, nil
}

const (
	// cardanoCombinedPubLen is the length of the TWC ED25519Cardano public key:
	// paymentPoint(32)||paymentChain(32)||stakingPoint(32)||stakingChain(32).
	cardanoCombinedPubLen = 128
	// cardanoKeyHashLen is the BLAKE2b digest size (224 bits) for a Cardano
	// payment/staking credential.
	cardanoKeyHashLen = 28
	// cardanoBaseHeader is the header byte of a mainnet base address:
	// (Kind_Base(0) << 4) | Network_Production(1) == 0x01.
	cardanoBaseHeader = 0x01
	// cardanoHRP is the bech32 human-readable part of a mainnet payment address.
	cardanoHRP = "addr"
)

// cardanoCombinedPublicKey derives the payment node (paymentIdx) and the staking
// node (stakingIdx) from entropy and assembles the 128-byte ED25519Cardano public
// key Trust Wallet Core's address encoder expects:
// paymentPoint(32)||paymentChain(32)||stakingPoint(32)||stakingChain(32). Each
// 96-byte extended private key is wiped on return by withCardanoPrivateKey.
func cardanoCombinedPublicKey(entropy []byte, paymentIdx, stakingIdx []uint32) ([]byte, error) {
	var paymentPub, stakingPub []byte
	if err := withCardanoPrivateKey(entropy, paymentIdx, func(priv []byte) error {
		p, e := cardanoPublicKey(priv) // 64-byte A||chain
		paymentPub = p
		return e
	}); err != nil {
		return nil, err
	}
	if err := withCardanoPrivateKey(entropy, stakingIdx, func(priv []byte) error {
		p, e := cardanoPublicKey(priv) // 64-byte A||chain
		stakingPub = p
		return e
	}); err != nil {
		return nil, err
	}
	combined := make([]byte, 0, cardanoCombinedPubLen)
	combined = append(combined, paymentPub...) // A(32) || chain(32)
	combined = append(combined, stakingPub...) // A(32) || chain(32)
	return combined, nil
}

// encodeCardano builds a Cardano mainnet base (addr1...) address from the
// 128-byte ED25519Cardano public key (payment A||chain || staking A||chain). It
// hashes the payment point (bytes 0:32) and the staking point (bytes 64:96) with
// BLAKE2b-224 to 28-byte credentials, lays them out as
// header(0x01) || paymentKeyHash(28) || stakingKeyHash(28), and bech32-encodes
// the 57-byte payload with HRP "addr". Matches Trust Wallet Core's
// Cardano::AddressV3 base-address construction.
func encodeCardano(pub []byte) (string, error) {
	if len(pub) != cardanoCombinedPubLen {
		return "", errors.New("hdwallet: cardano: address requires a 128-byte ED25519Cardano public key")
	}
	paymentHash := blake2bSize(cardanoKeyHashLen, pub[0:32])
	stakingHash := blake2bSize(cardanoKeyHashLen, pub[64:96])

	payload := make([]byte, 0, 1+2*cardanoKeyHashLen)
	payload = append(payload, cardanoBaseHeader)
	payload = append(payload, paymentHash...)
	payload = append(payload, stakingHash...)

	conv, err := bech32.ConvertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(cardanoHRP, conv)
}

// signMessageCardano signs message with the BIP32-Ed25519 extended key. priv is
// the 96-byte kL||kR||chain; the signature is the standard ed25519-with-extended
// -key form: r = H(kR || M), R = r*B, k = H(R || A || M), s = r + k*kL.
func signMessageCardano(priv, message []byte) (*Signature, error) {
	if len(priv) != cardanoExtendedLen {
		return nil, errCardanoKeyLen
	}
	kL := priv[0:32]
	kR := priv[32:64]

	scalar, err := cardanoScalarFromKL(kL)
	if err != nil {
		return nil, err
	}
	aBytes := new(edwards25519.Point).ScalarBaseMult(scalar).Bytes()

	// r = H(kR || M)
	rHash := sha512Concat(kR, message)
	defer wipe(rHash[:])
	rScalar, err := edwards25519.NewScalar().SetUniformBytes(rHash[:])
	if err != nil {
		return nil, err
	}
	R := new(edwards25519.Point).ScalarBaseMult(rScalar)
	rBytes := R.Bytes()

	// k = H(R || A || M)
	kHash := sha512Concat(rBytes, aBytes, message)
	defer wipe(kHash[:])
	kScalar, err := edwards25519.NewScalar().SetUniformBytes(kHash[:])
	if err != nil {
		return nil, err
	}

	// s = r + k*a
	s := edwards25519.NewScalar().MultiplyAdd(kScalar, scalar, rScalar)

	sig := make([]byte, 64)
	copy(sig[:32], rBytes)
	copy(sig[32:], s.Bytes())
	return &Signature{Curve: Ed25519ExtendedCardano, raw: sig}, nil
}

// verifyCardano verifies a Cardano extended-key signature. pub is the 64-byte
// A||chain (only A is used); message is the signed message.
func verifyCardano(pub, message, sig []byte) bool {
	if len(pub) < 32 || len(sig) != 64 {
		return false
	}
	A, err := new(edwards25519.Point).SetBytes(pub[:32])
	if err != nil {
		return false
	}
	kHash := sha512Concat(sig[:32], pub[:32], message)
	kScalar, err := edwards25519.NewScalar().SetUniformBytes(kHash[:])
	if err != nil {
		return false
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}
	minusA := new(edwards25519.Point).Negate(A)
	Rprime := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(kScalar, minusA, s)
	return constantTimeEqual(Rprime.Bytes(), sig[:32])
}

// sha512Concat hashes the concatenation of parts with SHA-512 (64-byte out).
func sha512Concat(parts ...[]byte) [64]byte {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

// reverse returns a reversed copy of b (big-endian <-> little-endian).
func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// leToFixed encodes a big.Int as size little-endian bytes (truncating/padding).
func leToFixed(n *big.Int, size int) []byte {
	be := n.Bytes()
	le := reverse(be)
	out := make([]byte, size)
	copy(out, le)
	return out
}

// constantTimeEqual reports byte-equality in constant time.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
