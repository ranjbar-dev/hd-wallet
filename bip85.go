package hdwallet

import (
	"fmt"
	"strconv"

	bip39 "github.com/tyler-smith/go-bip39"
)

// BIP-85 deterministic child entropy derived from a master HD key.
//
// BIP-85 lets a single root seed produce unlimited sub-wallets without extra
// backup burden: each child mnemonic / raw-entropy blob is fully reproducible
// from the root. The derivation uses secp256k1 BIP-32 at a dedicated namespace
// (m/83696968') regardless of which curves the child entropy will be used with.

// BIP85Entropy derives entropy bytes via BIP-85 (non-EC-multiply mode only).
//
// appPath is the application-specific suffix after m/83696968', without a
// leading or trailing slash. Common values:
//
//	"39'/0'/12'"  →  first 16 bytes → 12-word BIP-39 English mnemonic
//	"39'/0'/24'"  →  first 32 bytes → 24-word BIP-39 English mnemonic
//	"32'"         →  first 32 bytes → raw 256-bit entropy
//
// index is the BIP-85 child index (hardened automatically).
// length is the number of entropy bytes (1–64) passed to fn; fn is called
// with the slice and it is wiped before BIP85Entropy returns.
func (w *HDWallet) BIP85Entropy(appPath string, index uint32, length int, fn func([]byte)) error {
	if length < 1 || length > 64 {
		return fmt.Errorf("hdwallet: BIP-85 entropy length must be 1-64, got %d", length)
	}
	fullPath := "m/83696968'/" + appPath + "/" + strconv.FormatUint(uint64(index), 10) + "'"

	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return ErrDestroyed
	}
	if w.secret.isKeyOnly() {
		return fmt.Errorf("%w: BIP-85", ErrKeyOnlyWallet)
	}
	return w.secret.withSeed(func(seed []byte) error {
		path, err := parsePath(fullPath)
		if err != nil {
			return fmt.Errorf("hdwallet: BIP-85 invalid path %q: %w", fullPath, err)
		}
		return withSecp256k1PrivateKey(seed, path, func(priv []byte) error {
			raw := hmacSHA512([]byte("bip-entropy-from-k"), priv)
			defer wipe(raw)
			out := make([]byte, length)
			copy(out, raw[:length])
			defer wipe(out)
			fn(out)
			return nil
		})
	})
}

// BIP85Mnemonic derives a child BIP-39 mnemonic at the given index via BIP-85.
//
// wordCount must be 12, 18, or 24. fn receives the space-separated mnemonic as
// a byte slice; the slice is wiped before BIP85Mnemonic returns.
func (w *HDWallet) BIP85Mnemonic(wordCount int, index uint32, fn func([]byte)) error {
	var length int
	switch wordCount {
	case 12:
		length = 16
	case 18:
		length = 24
	case 24:
		length = 32
	default:
		return fmt.Errorf("%w: %d (BIP-85 supports 12, 18, or 24)", ErrInvalidWordCount, wordCount)
	}
	appPath := "39'/0'/" + strconv.Itoa(wordCount) + "'"
	var innerErr error
	err := w.BIP85Entropy(appPath, index, length, func(entropy []byte) {
		mnemonic, merr := bip39.NewMnemonic(entropy)
		if merr != nil {
			innerErr = fmt.Errorf("hdwallet: BIP-85 mnemonic generation: %w", merr)
			return
		}
		b := []byte(mnemonic)
		defer wipe(b)
		fn(b)
	})
	if err != nil {
		return err
	}
	return innerErr
}
