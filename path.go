package hdwallet

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/awnumar/memguard"
)

// Custom-derivation API.
//
// AddressIndex only varies the final element of a coin's path. The *Path methods
// here take a complete absolute BIP-32 path so callers can select any account,
// change branch, or address index (e.g. "m/44'/60'/3'/0/7"). The *At helpers are
// a guided convenience that build a standard 5-element BIP-44/84 path from an
// account/change/index triple.
//
// All of these are seed-only: a key-only wallet (imported from a single private
// key) has one leaf and no HD path, so they return ErrKeyOnlyWallet. The path is
// validated before any derivation, and the derived key is wiped on return — it
// never leaves the package, exactly as with the index-based methods.

// AddressPath returns the address for symbol derived at the given absolute BIP-32
// path (e.g. "m/44'/60'/1'/0/5"). The path's curve scheme is the coin's; only the
// child indices are taken from path. An invalid path or unknown symbol returns an
// error; a key-only wallet returns ErrKeyOnlyWallet.
func (w *HDWallet) AddressPath(symbol Symbol, path string) (string, error) {
	var addr string
	err := w.withLeafPublicKeyPath(symbol, path, func(pub []byte, coin Coin) error {
		a, err := coin.Encode(pub)
		if err != nil {
			return fmt.Errorf("hdwallet: %s: %w", symbol, err)
		}
		addr = a
		return nil
	})
	if err != nil {
		return "", err
	}
	return addr, nil
}

// PublicKeyPath returns the public key for symbol derived at the given absolute
// BIP-32 path: the 33-byte compressed key for secp256k1/nist256p1, or the 32-byte
// key for ed25519-family curves.
func (w *HDWallet) PublicKeyPath(symbol Symbol, path string) ([]byte, error) {
	var pub []byte
	err := w.withLeafPublicKeyPath(symbol, path, func(p []byte, _ Coin) error {
		pub = append([]byte(nil), p...) // copy out before the lock is released
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// SignPath signs data with the key for symbol derived at the given absolute
// BIP-32 path. The ECDSA-vs-ed25519 input rule is identical to SignIndex (ECDSA
// curves want the 32-byte digest; ed25519 wants the message).
func (w *HDWallet) SignPath(symbol Symbol, path string, data []byte) (*Signature, error) {
	var sig *Signature
	err := w.withLeafPrivateKeyPath(symbol, path, func(priv []byte, coin Coin) error {
		s, err := signDigest(coin.Curve, priv, data)
		if err != nil {
			return fmt.Errorf("hdwallet: %s: %w", symbol, err)
		}
		sig = s
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// WithPrivateKeyPath runs fn with the raw leaf private key for symbol derived at
// the given absolute BIP-32 path and wipes the key as soon as fn returns (mirrors
// WithPrivateKey). The slice passed to fn must not escape fn.
func (w *HDWallet) WithPrivateKeyPath(symbol Symbol, path string, fn func(priv []byte) error) error {
	return w.withLeafPrivateKeyPath(symbol, path, func(priv []byte, _ Coin) error {
		return fn(priv)
	})
}

// PrivateKeyPath returns the raw leaf private key for symbol derived at the given
// absolute BIP-32 path in a page-locked memguard buffer; the caller MUST Destroy
// it (mirrors PrivateKey). Prefer WithPrivateKeyPath, which wipes automatically.
func (w *HDWallet) PrivateKeyPath(symbol Symbol, path string) (*memguard.LockedBuffer, error) {
	var out *memguard.LockedBuffer
	err := w.withLeafPrivateKeyPath(symbol, path, func(priv []byte, _ Coin) error {
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

// AddressAt returns the address for symbol at the given BIP-44 account, change
// branch, and address index, building the path "m/purpose'/coin'/account'/change/
// index" from the coin's template. It requires a standard 5-element path; coins
// whose template has a different shape (e.g. SOL's "m/44'/501'/0'") return
// ErrPathArity — use AddressPath for those.
func (w *HDWallet) AddressAt(symbol Symbol, account, change, index uint32) (string, error) {
	path, err := w.accountPath(symbol, account, change, index)
	if err != nil {
		return "", err
	}
	return w.AddressPath(symbol, path)
}

// PublicKeyAt is the account/change/index counterpart of PublicKeyPath.
func (w *HDWallet) PublicKeyAt(symbol Symbol, account, change, index uint32) ([]byte, error) {
	path, err := w.accountPath(symbol, account, change, index)
	if err != nil {
		return nil, err
	}
	return w.PublicKeyPath(symbol, path)
}

// SignAt is the account/change/index counterpart of SignPath.
func (w *HDWallet) SignAt(symbol Symbol, account, change, index uint32, data []byte) (*Signature, error) {
	path, err := w.accountPath(symbol, account, change, index)
	if err != nil {
		return nil, err
	}
	return w.SignPath(symbol, path, data)
}

// accountPath builds a 5-element BIP-44/84 path from the coin's template by
// replacing the account (hardened), change, and index elements. It returns
// ErrUnsupportedCoin for an unknown symbol and ErrPathArity when the template is
// not a 5-element path. account/change/index must each be below 2^31.
func (w *HDWallet) accountPath(symbol Symbol, account, change, index uint32) (string, error) {
	coin, ok := coins[symbol]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	// parts: ["m", purpose', coin', account', change, index] — 6 entries.
	parts := strings.Split(coin.Path, "/")
	if len(parts) != 6 || parts[0] != "m" {
		return "", fmt.Errorf("%w: %s (%s)", ErrPathArity, symbol, coin.Path)
	}
	if account >= hardenedOffset || change >= hardenedOffset || index >= hardenedOffset {
		return "", fmt.Errorf("hdwallet: %s: account/change/index must each be < %d", symbol, uint32(hardenedOffset))
	}
	parts[3] = strconv.FormatUint(uint64(account), 10) + "'" // account is hardened
	parts[4] = strconv.FormatUint(uint64(change), 10)
	parts[5] = strconv.FormatUint(uint64(index), 10)
	return strings.Join(parts, "/"), nil
}
