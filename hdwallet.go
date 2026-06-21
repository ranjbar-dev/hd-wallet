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
	"slices"
	"sync"

	"github.com/awnumar/memguard"
	bip39 "github.com/tyler-smith/go-bip39"
)

// Exported sentinel errors. Consumers can match them with errors.Is; errors that
// add context (e.g. the offending symbol) wrap these with %w.
var (
	// ErrInvalidMnemonic is returned when a mnemonic fails BIP-39 validation.
	ErrInvalidMnemonic = errors.New("hdwallet: invalid mnemonic")
	// ErrUnsupportedCoin is returned for a symbol not in the registry.
	ErrUnsupportedCoin = errors.New("hdwallet: unsupported coin")
	// ErrDestroyed is returned by operations on a wallet whose secrets were wiped.
	ErrDestroyed = errors.New("hdwallet: wallet has been destroyed")
)

// HDWallet is an HD wallet derived from a BIP-39 mnemonic. Its sensitive
// material is protected in memory; see the package documentation. All methods
// are safe for concurrent use.
type HDWallet struct {
	mu     sync.RWMutex
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

// FromMnemonicBuffer builds a wallet from a mnemonic held in a memguard
// LockedBuffer. This is the most secure entry point: the mnemonic stays in
// page-locked, encrypted-at-rest memory from your code all the way into the
// wallet's sealed enclave, with no intermediate plaintext copy on the Go heap.
//
// The wallet takes ownership of buf and destroys it; do not use buf afterwards.
// Surrounding whitespace in the buffer is trimmed before use.
func FromMnemonicBuffer(buf *memguard.LockedBuffer) (*HDWallet, error) {
	s, err := newSecretFromBuffer(buf)
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
//
// It is exactly equivalent to AddressIndex(symbol, 0).
func (w *HDWallet) Address(symbol Symbol) (string, error) {
	return w.AddressIndex(symbol, 0)
}

// AddressIndex returns the address for a coin symbol derived with the final
// element of the coin's BIP-32 path replaced by index, preserving that
// element's hardened flag (a trailing "'").
//
// For BIP-44/BIP-84 chains whose path ends in "/0/0" (change/address_index),
// this varies the non-hardened receive address index — e.g. for BTC
// (m/84'/0'/0'/0/0), index 1 derives m/84'/0'/0'/0/1. For account-based chains
// whose path ends in a hardened element such as "/0'" (e.g. SOL,
// m/44'/501'/0'), this varies that final hardened element — index 1 derives
// m/44'/501'/1'.
//
// index must be below 2^31 (0x80000000); a larger value returns an error, as
// does an unknown symbol (wrapping ErrUnsupportedCoin) or a destroyed wallet.
func (w *HDWallet) AddressIndex(symbol Symbol, index uint32) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return "", ErrDestroyed
	}
	coin, ok := coins[symbol]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	path, err := withIndex(coin.Path, index)
	if err != nil {
		return "", fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	coin.Path = path // local copy; the registry entry is unchanged

	var addr string
	err = w.secret.withSeed(func(seed []byte) error {
		a, err := addressFromSeed(seed, symbol, coin)
		addr = a
		return err
	})
	if err != nil {
		return "", err
	}
	return addr, nil
}

// AllAddresses derives the first address for every supported coin. The seed
// enclave is opened exactly once and every coin is derived inside that single
// decryption window.
func (w *HDWallet) AllAddresses() (map[Symbol]string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return nil, ErrDestroyed
	}
	out := make(map[Symbol]string, len(coins))
	err := w.secret.withSeed(func(seed []byte) error {
		for _, symbol := range SupportedCoins() {
			addr, err := addressFromSeed(seed, symbol, coins[symbol])
			if err != nil {
				return err
			}
			out[symbol] = addr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// addressFromSeed derives and encodes a single coin's address from an already
// open seed. Errors are wrapped with the symbol for context. It performs no
// locking and assumes the caller holds w.mu and the seed buffer is live.
func addressFromSeed(seed []byte, symbol Symbol, coin Coin) (string, error) {
	pub, err := derivePublicKey(seed, coin)
	if err != nil {
		return "", fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	addr, err := coin.Encode(pub)
	if err != nil {
		return "", fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	return addr, nil
}

// Mnemonic returns the wallet's mnemonic in a page-locked buffer. This is a
// lower-level accessor: the caller MUST call Destroy on the returned buffer when
// finished with it, or the decrypted phrase lingers in memory. Prefer
// WithMnemonic, which wipes the decrypted copy automatically when its callback
// returns.
func (w *HDWallet) Mnemonic() (*memguard.LockedBuffer, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return nil, ErrDestroyed
	}
	return w.secret.openMnemonic()
}

// WithMnemonic runs fn with the plaintext mnemonic bytes and wipes the decrypted
// copy as soon as fn returns. The slice passed to fn must not escape fn.
func (w *HDWallet) WithMnemonic(fn func(mnemonic []byte) error) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return ErrDestroyed
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
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.secret != nil {
		w.secret.destroy()
		w.secret = nil
	}
}

// SupportedCoins lists the registered coin symbols in sorted order.
func SupportedCoins() []Symbol {
	out := make([]Symbol, 0, len(coins))
	for s := range coins {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// CoinInfo returns the static registry entry for a symbol.
func CoinInfo(symbol Symbol) (Coin, bool) {
	c, ok := coins[symbol]
	return c, ok
}
