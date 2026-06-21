// Package hdwallet is a Trust Wallet-compatible hierarchical-deterministic
// wallet for Go.
//
// It generates a BIP-39 mnemonic (or imports one) and derives receive addresses
// for many networks using the same derivation paths and address formats Trust
// Wallet uses by default, so seeds are interchangeable between the two.
//
// Secrets (the mnemonic and the derived seed) are never held as plain Go
// strings or long-lived byte slices. They are stored in encrypted, page-locked
// memguard enclaves and decrypted only for the duration of a single derivation.
// Always call (*HDWallet).Destroy when finished, and consider
// memguard.Purge on program exit.
package hdwallet

import (
	"errors"
	"fmt"
	"sort"

	"github.com/awnumar/memguard"
	bip39 "github.com/tyler-smith/go-bip39"
)

// errDestroyed is returned by operations on a wallet whose secrets were wiped.
var errDestroyed = errors.New("hdwallet: wallet has been destroyed")

// HDWallet is an HD wallet derived from a BIP-39 mnemonic. Its sensitive
// material is protected in memory; see the package documentation.
type HDWallet struct {
	secret *secret
}

// NewHDWallet creates a wallet with a fresh 12-word (128-bit) mnemonic.
func NewHDWallet() (*HDWallet, error) {
	mnemonic, err := generateMnemonicBytes()
	if err != nil {
		return nil, err
	}
	return FromMnemonicBytes(mnemonic) // consumes/wipes mnemonic
}

// FromMnemonic builds a wallet from an existing 12/24-word mnemonic string.
//
// Prefer FromMnemonicBytes where possible: a Go string cannot be wiped from
// memory, so any mnemonic held as a string lingers until garbage-collected.
func FromMnemonic(mnemonic string) (*HDWallet, error) {
	return FromMnemonicBytes([]byte(mnemonic))
}

// FromMnemonicBytes builds a wallet from a mnemonic held in a byte slice. The
// slice is wiped before the function returns; callers must not reuse it.
func FromMnemonicBytes(mnemonic []byte) (*HDWallet, error) {
	s, err := newSecret(mnemonic)
	if err != nil {
		return nil, err
	}
	return &HDWallet{secret: s}, nil
}

// GenerateMnemonic returns a fresh 12-word BIP-39 mnemonic as a string.
//
// The returned string cannot be securely wiped; for sensitive use derive a
// wallet with NewHDWallet (which keeps the mnemonic in protected memory) and
// read it back via Mnemonic or WithMnemonic only when required.
func GenerateMnemonic() (string, error) {
	mn, err := generateMnemonicBytes()
	if err != nil {
		return "", err
	}
	defer wipe(mn)
	return string(mn), nil
}

func generateMnemonicBytes() ([]byte, error) {
	entropy, err := bip39.NewEntropy(128) // 128 bits -> 12 words
	if err != nil {
		return nil, err
	}
	defer wipe(entropy)
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, err
	}
	return []byte(mnemonic), nil
}

// Address returns the first receive address (index 0) for a coin symbol,
// e.g. "BTC", "ETH", "SOL", "ATOM". Use SupportedCoins to list every symbol.
func (w *HDWallet) Address(symbol string) (string, error) {
	if w.secret == nil {
		return "", errDestroyed
	}
	coin, ok := coins[symbol]
	if !ok {
		return "", fmt.Errorf("hdwallet: unsupported coin: %s", symbol)
	}

	var addr string
	err := w.secret.withSeed(func(seed []byte) error {
		pub, err := derivePublicKey(seed, coin)
		if err != nil {
			return err
		}
		addr, err = coin.Encode(pub)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	return addr, nil
}

// AllAddresses derives the first address for every supported coin.
func (w *HDWallet) AllAddresses() (map[string]string, error) {
	if w.secret == nil {
		return nil, errDestroyed
	}
	out := make(map[string]string, len(coins))
	for _, symbol := range SupportedCoins() {
		addr, err := w.Address(symbol)
		if err != nil {
			return nil, err
		}
		out[symbol] = addr
	}
	return out, nil
}

// Mnemonic returns the wallet's mnemonic in a page-locked buffer. The caller
// MUST call Destroy on the returned buffer when finished with it.
func (w *HDWallet) Mnemonic() (*memguard.LockedBuffer, error) {
	if w.secret == nil {
		return nil, errDestroyed
	}
	return w.secret.openMnemonic()
}

// WithMnemonic runs fn with the plaintext mnemonic bytes and wipes the decrypted
// copy as soon as fn returns. The slice passed to fn must not escape fn.
func (w *HDWallet) WithMnemonic(fn func(mnemonic []byte) error) error {
	if w.secret == nil {
		return errDestroyed
	}
	buf, err := w.secret.openMnemonic()
	if err != nil {
		return err
	}
	defer buf.Destroy()
	return fn(buf.Bytes())
}

// Destroy wipes the wallet's secret material from memory. The wallet is unusable
// afterwards. It is safe to call multiple times.
func (w *HDWallet) Destroy() {
	if w.secret != nil {
		w.secret.destroy()
		w.secret = nil
	}
}

// SupportedCoins lists the registered coin symbols in sorted order.
func SupportedCoins() []string {
	out := make([]string, 0, len(coins))
	for s := range coins {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// CoinInfo returns the static registry entry for a symbol.
func CoinInfo(symbol string) (Coin, bool) {
	c, ok := coins[symbol]
	return c, ok
}
