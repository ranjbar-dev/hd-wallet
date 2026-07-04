package hdwallet

import (
	"crypto/ed25519"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Signature is the result of signing with a derived key.
//
// For the ECDSA curve (secp256k1), R and S are the signature scalars and the
// value is available as a 64-byte R||S string, an ASN.1 DER encoding, and a
// 65-byte recoverable form. For ed25519, R and S are nil and the 64-byte
// signature is available via Bytes.
type Signature struct {
	Curve      Curve
	R, S       []byte // ECDSA signature scalars (nil for ed25519)
	RecoveryID byte   // secp256k1 public-key recovery id (0 or 1)
	raw        []byte // ed25519: 64-byte signature; ECDSA: 64-byte R||S
}

// Bytes returns the 64-byte signature: R||S for ECDSA curves, or the raw
// 64-byte signature for ed25519. Cosmos and Solana use this form.
func (s *Signature) Bytes() []byte {
	out := make([]byte, len(s.raw))
	copy(out, s.raw)
	return out
}

// Recoverable returns the 65-byte [R||S||V] signature, where V is the recovery
// id (0 or 1), used by Ethereum/EVM chains and Tron. Callers add the chain's V
// offset (e.g. 27, or 35+2*chainID for EIP-155) as needed. It is only valid for
// secp256k1; for other curves it returns nil.
func (s *Signature) Recoverable() []byte {
	if s.Curve != Secp256k1 {
		return nil
	}
	out := make([]byte, 65)
	copy(out[:64], s.raw)
	out[64] = s.RecoveryID
	return out
}

// DER returns the ASN.1 DER encoding (SEQUENCE of two INTEGERs) used by
// Bitcoin-family chains. It is valid for ECDSA curves; for ed25519 it returns
// nil.
func (s *Signature) DER() []byte {
	if s.R == nil || s.S == nil {
		return nil
	}
	b, err := asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(s.R),
		new(big.Int).SetBytes(s.S),
	})
	if err != nil {
		return nil
	}
	return b
}

// signDigest signs a 32-byte digest (ECDSA curves) or a message (ed25519) with a
// raw private key on the given curve. The private key is not wiped here — the
// caller (withPrivateKey) owns and wipes it.
func signDigest(curve Curve, priv, data []byte) (*Signature, error) {
	switch curve {
	case Secp256k1:
		return signDigestSecp256k1(priv, data)
	case Ed25519:
		return signMessageEd25519(priv, data)
	default:
		return nil, fmt.Errorf("unsupported curve: %d", curve)
	}
}

// signDigestSecp256k1 produces a recoverable, RFC 6979 deterministic, canonical
// low-S ECDSA signature over a 32-byte digest.
func signDigestSecp256k1(priv, digest []byte) (*Signature, error) {
	if len(digest) != 32 {
		return nil, ErrInvalidDigest
	}
	key, _ := btcec.PrivKeyFromBytes(priv)
	defer key.Zero()

	// SignCompact returns [27+recid(+4 if compressed)] || R(32) || S(32) with a
	// deterministic nonce (RFC 6979) and canonical low-S.
	compact, err := btcecdsa.SignCompact(key, digest, true)
	if err != nil {
		return nil, err
	}
	recid := compact[0] - 27 - 4 // strip the 27 base and the compressed-key +4

	raw := make([]byte, 64)
	copy(raw, compact[1:65])
	return &Signature{
		Curve:      Secp256k1,
		R:          append([]byte(nil), compact[1:33]...),
		S:          append([]byte(nil), compact[33:65]...),
		RecoveryID: recid,
		raw:        raw,
	}, nil
}

// signMessageEd25519 signs the message directly (the EdDSA scheme hashes
// internally; there is no pre-hash).
func signMessageEd25519(priv, message []byte) (*Signature, error) {
	if len(priv) != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519: invalid seed length %d", len(priv))
	}
	key := ed25519.NewKeyFromSeed(priv)
	defer wipe(key)
	return &Signature{Curve: Ed25519, raw: ed25519.Sign(key, message)}, nil
}

// verifySignature checks a signature against a public key and data. Used by
// tests; exported behaviour is provided by Verify.
func verifySignature(curve Curve, pub, data []byte, sig *Signature) bool {
	switch curve {
	case Secp256k1:
		pk, err := btcec.ParsePubKey(pub)
		if err != nil {
			return false
		}
		parsed, err := btcecdsa.ParseDERSignature(sig.DER())
		if err != nil {
			return false
		}
		return parsed.Verify(data, pk)
	case Ed25519:
		if len(pub) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(pub), data, sig.raw)
	default:
		return false
	}
}

// Verify reports whether sig is a valid signature of data by the public key pub
// on the given curve. For ECDSA curves data is the 32-byte digest that was
// signed; for ed25519 it is the message.
func Verify(curve Curve, pub, data []byte, sig *Signature) bool {
	return verifySignature(curve, pub, data, sig)
}

// VerifySignature reports whether sig is a valid signature of data by the public
// key pub for the coin chain. It is the Chain-keyed counterpart to Sign: the
// curve is resolved from the registry rather than supplied directly.
//
// As with Sign/SignIndex, data is the 32-byte digest for ECDSA chains
// (secp256k1) and the raw message for ed25519 chains. A non-32-byte input for
// an ECDSA chain returns a wrapped ErrInvalidDigest, mirroring SignIndex; an
// unknown chain returns a wrapped ErrUnsupportedCoin.
//
// It needs no secret and so is a free function, not a wallet method.
func VerifySignature(chain Chain, pub, data []byte, sig *Signature) (bool, error) {
	coin, ok := coins[chain]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrUnsupportedCoin, chain)
	}
	switch coin.Curve {
	case Secp256k1:
		if len(data) != 32 {
			return false, fmt.Errorf("hdwallet: %s: %w", chain, ErrInvalidDigest)
		}
	}
	return Verify(coin.Curve, pub, data, sig), nil
}
