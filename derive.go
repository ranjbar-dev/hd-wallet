package hdwallet

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// parsePath parses a BIP-32 path such as "m/44'/60'/0'/0/0" into child indices,
// applying the hardened offset to elements suffixed with ' (or h/H).
func parsePath(path string) ([]uint32, error) {
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] != "m" {
		return nil, fmt.Errorf("invalid derivation path: %q", path)
	}
	out := make([]uint32, 0, len(parts)-1)
	for _, p := range parts[1:] {
		hardened := false
		if strings.HasSuffix(p, "'") || strings.HasSuffix(p, "h") || strings.HasSuffix(p, "H") {
			hardened = true
			p = p[:len(p)-1]
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid path element %q: %w", p, err)
		}
		if n >= uint64(hardenedOffset) {
			return nil, fmt.Errorf("path element out of range: %q", p)
		}
		idx := uint32(n)
		if hardened {
			idx += hardenedOffset
		}
		out = append(out, idx)
	}
	return out, nil
}

// withIndex returns path with its final element's numeric value replaced by
// index, preserving that element's hardened flag (a trailing "'"). For BIP-44/
// BIP-84 paths ending in "/0/0" this varies the receive address index (the
// non-hardened last element); for account-based paths ending in a hardened
// element such as "/0'" it varies that final hardened element. index must be
// below hardenedOffset (2^31); a hardened element's offset is re-applied here.
func withIndex(path string, index uint32) (string, error) {
	if index >= hardenedOffset {
		return "", fmt.Errorf("address index out of range: %d (must be < %d)", index, hardenedOffset)
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] != "m" {
		return "", fmt.Errorf("invalid derivation path: %q", path)
	}
	last := parts[len(parts)-1]
	hardened := ""
	if strings.HasSuffix(last, "'") || strings.HasSuffix(last, "h") || strings.HasSuffix(last, "H") {
		hardened = "'"
	}
	parts[len(parts)-1] = strconv.FormatUint(uint64(index), 10) + hardened
	return strings.Join(parts, "/"), nil
}

// withPrivateKey derives the leaf private key for the coin's curve and path,
// passes the raw 32-byte key to fn, and wipes it before returning. It is the
// single place that materialises a private key in this package; both public-key
// derivation and signing go through it. It is unexported on purpose — private
// keys must never escape the package (see the security model in the docs).
func withPrivateKey(seed []byte, c Coin, fn func(priv []byte) error) error {
	path, err := parsePath(c.Path)
	if err != nil {
		return err
	}

	switch c.Curve {
	case Secp256k1:
		return withSecp256k1PrivateKey(seed, path, fn)
	case Ed25519, Ed25519Blake2bNano, Curve25519, Sr25519:
		// All three use SLIP-0010 ed25519 derivation for the leaf 32-byte key;
		// they differ only in how that key is expanded into a signing key.
		node, err := deriveEd25519(seed, path)
		if err != nil {
			return err
		}
		defer wipe(node.key)
		return fn(node.key)
	case Ed25519ExtendedCardano:
		// Cardano's Icarus master secret is derived from the BIP-39 ENTROPY, not
		// the BIP-39 seed that this function receives. The seed is the wrong input
		// here, so the seed-based path is deliberately closed: the public Address/
		// Sign APIs route Cardano through the entropy enclave instead
		// (HDWallet.withLeafPrivateKey / withCardanoCombinedPublicKey, which call
		// withCardanoPrivateKey(entropy, ...) in cardano.go). Reaching this branch
		// means a Cardano coin was fed the seed directly, which would silently
		// produce a wrong key, so it errors.
		return errCardanoNeedsEntropy
	case Starkex:
		return withStarkexPrivateKey(seed, path, fn)
	case Nist256p1:
		node, err := deriveNist256p1(seed, path)
		if err != nil {
			return err
		}
		defer wipe(node.key)
		return fn(node.key)
	default:
		return fmt.Errorf("unsupported curve: %d", c.Curve)
	}
}

// withSecp256k1PrivateKey walks the BIP-32 path and hands the leaf private key's
// 32-byte serialization to fn. BIP-32 EC math is network-independent, so
// MainNetParams works for every secp256k1 coin. The raw key, the btcec key, and
// every intermediate extended key are zeroed before returning.
func withSecp256k1PrivateKey(seed []byte, path []uint32, fn func(priv []byte) error) error {
	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return err
	}
	for _, childNum := range path {
		child, err := key.Derive(childNum)
		if err != nil {
			key.Zero()
			return err
		}
		key.Zero() // parent no longer needed; wipe before moving to the child
		key = child
	}
	defer key.Zero() // wipe the leaf extended key on return
	priv, err := key.ECPrivKey()
	if err != nil {
		return err
	}
	raw := priv.Serialize()
	priv.Zero()
	defer wipe(raw)
	return fn(raw)
}

// derivePublicKey walks the coin's path on its curve and returns the public key
// bytes the encoder expects (compressed for secp256k1/nist256p1, the raw 32-byte
// key for ed25519). Private key material is wiped before returning.
func derivePublicKey(seed []byte, c Coin) ([]byte, error) {
	var pub []byte
	err := withPrivateKey(seed, c, func(priv []byte) error {
		p, err := publicKeyFromPriv(c.Curve, priv)
		if err != nil {
			return err
		}
		pub = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func ed25519PubFromSeed(seed []byte) []byte {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := make([]byte, ed25519.PublicKeySize)
	copy(pub, priv[ed25519.SeedSize:])
	wipe(priv)
	return pub
}

// publicKeyFromPriv computes the public key for a raw private key on a given
// curve, without HD derivation. Used to verify encoders against fixed-key test
// vectors (see the Trust Wallet CoinAddressDerivation vectors).
func publicKeyFromPriv(curve Curve, priv []byte) ([]byte, error) {
	switch curve {
	case Secp256k1:
		_, pub := btcec.PrivKeyFromBytes(priv)
		return pub.SerializeCompressed(), nil
	case Ed25519:
		seed := make([]byte, ed25519.SeedSize)
		copy(seed, priv)
		return ed25519PubFromSeed(seed), nil
	case Ed25519Blake2bNano:
		return blake2bPublicKey(priv)
	case Curve25519:
		return curve25519PublicKey(priv)
	case Sr25519:
		return sr25519PublicKey(priv)
	case Ed25519ExtendedCardano:
		return cardanoPublicKey(priv)
	case Starkex:
		return starkexPublicKey(priv)
	case Nist256p1:
		return compressP256(priv), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %d", curve)
	}
}
