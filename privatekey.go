package hdwallet

import (
	"github.com/awnumar/memguard"
)

// FromPrivateKeyBytes builds a key-only wallet from a raw private key held in a
// byte slice. The slice is wiped before this function returns; callers must not
// reuse it (mirrors FromMnemonicBytes).
//
// curve identifies the elliptic curve the key belongs to (Secp256k1, Ed25519, or
// Nist256p1). The resulting wallet can derive addresses, public keys, sign, and
// export the key for any registered coin whose curve matches; mismatched-curve
// coins return ErrCurveMismatch. A key-only wallet has no HD path — the imported
// key is the leaf — so only index 0 is valid and there is no mnemonic to read
// (Mnemonic/WithMnemonic/AllAddresses return ErrKeyOnlyWallet).
//
// The key must be exactly 32 bytes and non-zero, or ErrInvalidPrivateKey is
// returned.
func FromPrivateKeyBytes(priv []byte, curve Curve) (*HDWallet, error) {
	s, err := newSecretFromPrivateKey(priv, curve)
	if err != nil {
		return nil, err
	}
	return &HDWallet{secret: s}, nil
}

// FromPrivateKeyBuffer builds a key-only wallet from a raw private key held in a
// memguard LockedBuffer. This is the most secure key-import entry point: the key
// stays in page-locked, encrypted-at-rest memory from your code all the way into
// the wallet's sealed enclave, with no intermediate plaintext copy on the Go heap
// (mirrors FromMnemonicBuffer).
//
// The wallet takes ownership of buf and destroys it; do not use buf afterwards.
// See FromPrivateKeyBytes for the semantics of a key-only wallet.
func FromPrivateKeyBuffer(buf *memguard.LockedBuffer, curve Curve) (*HDWallet, error) {
	s, err := newSecretFromPrivateKeyBuffer(buf, curve)
	if err != nil {
		return nil, err
	}
	return &HDWallet{secret: s}, nil
}

// WithPrivateKey runs fn with the raw leaf private key for symbol at the given
// address index and wipes the key as soon as fn returns. This is the safe export
// primitive — the key never escapes into a value the caller must remember to
// clear (mirrors WithMnemonic). The slice passed to fn must not escape fn.
//
// It works for both wallet modes: seed wallets derive the key for symbol/index;
// key-only wallets return their imported key (curve must match symbol's curve,
// and index must be 0). The key is the 32-byte scalar/seed for the coin's curve.
//
// For ECDSA chains this is the signing scalar; for ed25519 it is the 32-byte
// seed (not the 64-byte expanded key).
func (w *HDWallet) WithPrivateKey(symbol Symbol, index uint32, fn func(priv []byte) error) error {
	return w.withLeafPrivateKey(symbol, index, func(priv []byte, _ Coin) error {
		return fn(priv)
	})
}

// PrivateKey returns the raw leaf private key for symbol at the given address
// index in a page-locked, encrypted-at-rest memguard buffer. This is a
// lower-level accessor: the caller MUST call Destroy on the returned buffer when
// finished, or the decrypted key lingers in memory. Prefer WithPrivateKey, which
// wipes the key automatically when its callback returns (mirrors Mnemonic).
//
// The returned buffer holds a copy taken inside the wallet's protected
// derivation window; the wallet's own working copy is wiped before this returns.
// See WithPrivateKey for the seed/key-only semantics and the key encoding.
func (w *HDWallet) PrivateKey(symbol Symbol, index uint32) (*memguard.LockedBuffer, error) {
	var out *memguard.LockedBuffer
	err := w.withLeafPrivateKey(symbol, index, func(priv []byte, _ Coin) error {
		// Copy the raw key into a fresh locked buffer while it is live; the
		// source slice is wiped by withLeafPrivateKey when this callback returns.
		buf := memguard.NewBuffer(len(priv))
		buf.Copy(priv)
		out = buf
		return nil
	})
	if err != nil {
		if out != nil {
			out.Destroy()
		}
		return nil, err
	}
	return out, nil
}
