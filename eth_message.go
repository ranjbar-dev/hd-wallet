package hdwallet

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// EthereumMessageSigner-style API: EIP-191 personal_sign and EIP-712 typed-data
// signing, plus ecrecover-based verification. These are methods on *HDWallet but
// live entirely in this file (hdwallet.go is not modified); they reuse the
// existing signer via SignIndex and never expose private key material.
//
// Both signers return a 65-byte r||s||v signature where v is the Ethereum
// convention 27/28 (recovery id + 27). To sign, the digest is computed here and
// handed to the secp256k1 signer; the 0/1 recovery id from Recoverable() is
// offset by 27.

// Ethereum message errors.
var (
	// ErrEthSignature is returned when an Ethereum signature is malformed.
	ErrEthSignature = errors.New("hdwallet: invalid ethereum signature")
)

// SignMessage signs message with EIP-191 personal_sign using the key for chain
// at the given address index, returning a 65-byte r||s||v signature (v = 27/28).
// chain must be a secp256k1/EVM coin (e.g. ETH); other curves return an error.
func (w *HDWallet) SignMessage(chain Chain, index uint32, message []byte) ([]byte, error) {
	digest := EthereumPersonalMessageHash(message)
	return w.signEthDigest(chain, index, digest)
}

// SignTypedData signs the EIP-712 digest of MetaMask-shape typed-data JSON using
// the key for chain at the given address index, returning a 65-byte r||s||v
// signature (v = 27/28).
func (w *HDWallet) SignTypedData(chain Chain, index uint32, typedDataJSON []byte) ([]byte, error) {
	digest, err := EIP712Hash(typedDataJSON)
	if err != nil {
		return nil, err
	}
	return w.signEthDigest(chain, index, digest)
}

// signEthDigest signs a 32-byte digest with the secp256k1 signer and returns the
// 65-byte r||s||v form with v in {27, 28}.
func (w *HDWallet) signEthDigest(chain Chain, index uint32, digest []byte) ([]byte, error) {
	sig, err := w.SignIndex(chain, index, digest)
	if err != nil {
		return nil, err
	}
	rec := sig.Recoverable() // 65 bytes r||s||v with v in {0,1}
	if rec == nil {
		return nil, fmt.Errorf("%w: %s is not a recoverable (secp256k1) coin", ErrEthSignature, chain)
	}
	out := make([]byte, 65)
	copy(out, rec)
	out[64] = rec[64] + 27
	return out, nil
}

// VerifyEthereumMessage reports whether sig (65-byte r||s||v, v in {27,28} or
// {0,1}) is a valid EIP-191 personal_sign signature of message by the signer
// identified by addressOrPubKey. addressOrPubKey may be a 0x-hex Ethereum address
// (20 bytes), or a hex/raw secp256k1 public key (33-byte compressed or 65-byte
// uncompressed). It ecrecovers the signer and compares.
func VerifyEthereumMessage(addressOrPubKey string, message, sig []byte) bool {
	digest := EthereumPersonalMessageHash(message)
	return verifyEthDigest(addressOrPubKey, digest, sig)
}

// VerifyEthereumTypedData is the EIP-712 counterpart of VerifyEthereumMessage.
func VerifyEthereumTypedData(addressOrPubKey string, typedDataJSON, sig []byte) bool {
	digest, err := EIP712Hash(typedDataJSON)
	if err != nil {
		return false
	}
	return verifyEthDigest(addressOrPubKey, digest, sig)
}

// verifyEthDigest ecrecovers the public key from a 65-byte signature over digest
// and checks it matches the expected address/public key.
func verifyEthDigest(addressOrPubKey string, digest, sig []byte) bool {
	pub, err := recoverEthPubKey(digest, sig)
	if err != nil {
		return false
	}
	return ethPubKeyMatches(addressOrPubKey, pub)
}

// recoverEthPubKey recovers the signing public key from a 65-byte r||s||v
// signature over digest. v may be 27/28 or 0/1.
func recoverEthPubKey(digest, sig []byte) (*btcec.PublicKey, error) {
	if len(sig) != 65 {
		return nil, ErrEthSignature
	}
	v := sig[64]
	switch v {
	case 27, 28:
		v -= 27
	case 0, 1:
		// already a recovery id
	default:
		return nil, fmt.Errorf("%w: bad recovery byte %d", ErrEthSignature, sig[64])
	}
	// btcec compact form: [27+recid] || R || S.
	compact := make([]byte, 65)
	compact[0] = 27 + v
	copy(compact[1:], sig[:64])
	pub, _, err := btcecdsa.RecoverCompact(compact, digest)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// ethPubKeyMatches checks a recovered key against an expected address or public
// key string (any of: 0x-address, hex/compressed/uncompressed public key).
func ethPubKeyMatches(expected string, pub *btcec.PublicKey) bool {
	exp := strings.TrimSpace(expected)
	expBytes, err := hexToBytes(exp)
	if err != nil {
		return false
	}
	switch len(expBytes) {
	case 20: // Ethereum address
		got := ethAddressFromPubKey(pub)
		return bytes.Equal(got, expBytes)
	case 33: // compressed public key
		return bytes.Equal(pub.SerializeCompressed(), expBytes)
	case 65: // uncompressed public key
		return bytes.Equal(pub.SerializeUncompressed(), expBytes)
	default:
		return false
	}
}

// ethAddressFromPubKey computes the 20-byte Ethereum address (keccak256 of the
// uncompressed key without the 0x04 prefix, last 20 bytes).
func ethAddressFromPubKey(pub *btcec.PublicKey) []byte {
	return keccak256(pub.SerializeUncompressed()[1:])[12:]
}

// RecoverEthereumAddress recovers the EIP-55 checksummed Ethereum address that
// produced sig over message under EIP-191 personal_sign. It is a convenience for
// callers that want the signer's address rather than a boolean match.
func RecoverEthereumAddress(message, sig []byte) (string, error) {
	digest := EthereumPersonalMessageHash(message)
	pub, err := recoverEthPubKey(digest, sig)
	if err != nil {
		return "", err
	}
	return eip55(ethAddressFromPubKey(pub)), nil
}
