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

// derivePublicKey walks the coin's path on its curve and returns the public key
// bytes the encoder expects (compressed for secp256k1/nist256p1, the raw 32-byte
// key for ed25519). Private key material is wiped before returning.
func derivePublicKey(seed []byte, c Coin) ([]byte, error) {
	path, err := parsePath(c.Path)
	if err != nil {
		return nil, err
	}

	switch c.Curve {
	case Secp256k1:
		return deriveSecp256k1Pub(seed, path)
	case Ed25519:
		node, err := deriveEd25519(seed, path)
		if err != nil {
			return nil, err
		}
		defer wipe(node.key)
		return ed25519PubFromSeed(node.key), nil
	case Nist256p1:
		node, err := deriveNist256p1(seed, path)
		if err != nil {
			return nil, err
		}
		defer wipe(node.key)
		return compressP256(node.key), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %d", c.Curve)
	}
}

// deriveSecp256k1Pub derives a BIP-32 leaf key and returns its compressed
// public key. BIP-32 EC math is network-independent, so MainNetParams works for
// every secp256k1 coin. The leaf private key is zeroed before returning.
func deriveSecp256k1Pub(seed []byte, path []uint32) ([]byte, error) {
	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	for _, childNum := range path {
		key, err = key.Derive(childNum)
		if err != nil {
			return nil, err
		}
	}
	priv, err := key.ECPrivKey()
	if err != nil {
		return nil, err
	}
	pub := priv.PubKey().SerializeCompressed()
	priv.Zero()
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
	case Nist256p1:
		return compressP256(priv), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %d", curve)
	}
}
