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
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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
	// ErrInvalidDigest is returned when an ECDSA signing input is not 32 bytes.
	ErrInvalidDigest = errors.New("hdwallet: digest must be 32 bytes")
	// ErrInvalidPrivateKey is returned when an imported private key has the wrong
	// length or is otherwise invalid for its curve.
	ErrInvalidPrivateKey = errors.New("hdwallet: invalid private key")
	// ErrUnsupportedCurve is returned when a curve is not one of the supported
	// elliptic curves.
	ErrUnsupportedCurve = errors.New("hdwallet: unsupported curve")
	// ErrCurveMismatch is returned when an operation targets a coin whose curve
	// differs from the curve of a key-only wallet's imported private key.
	ErrCurveMismatch = errors.New("hdwallet: coin curve does not match imported key curve")
	// ErrKeyOnlyWallet is returned by mnemonic/seed-only operations (Mnemonic,
	// WithMnemonic, AllAddresses) on a wallet imported from a raw private key.
	ErrKeyOnlyWallet = errors.New("hdwallet: operation not available on a private-key-only wallet")
	// ErrKeyOnlyIndex is returned when a non-zero address/sign index is requested
	// on a key-only wallet, which has a single leaf key and no HD path.
	ErrKeyOnlyIndex = errors.New("hdwallet: private-key-only wallet supports only index 0")
	// ErrPathArity is returned by the structured account/change/index helpers
	// (AddressAt, SignAt, PublicKeyAt) when a coin's path template is not a
	// 5-element BIP-44/BIP-84 path; use the AddressPath/SignPath primitives instead.
	ErrPathArity = errors.New("hdwallet: coin path is not a 5-element BIP-44/84 path; use the *Path methods")
	// ErrExtKeyUnsupportedCurve is returned by the extended-key (xprv/xpub) and
	// watch-only APIs for a non-secp256k1 coin: BIP-32 extended keys and public
	// (non-hardened) child derivation apply only to secp256k1; the SLIP-0010
	// ed25519/nist256p1 schemes support hardened derivation only.
	ErrExtKeyUnsupportedCurve = errors.New("hdwallet: extended keys / watch-only require a secp256k1 coin")
	// ErrInvalidWordCount is returned when a requested mnemonic length is not a
	// valid BIP-39 word count (12, 15, 18, 21, or 24) or entropy size in bits
	// (128, 160, 192, 224, or 256).
	ErrInvalidWordCount = errors.New("hdwallet: invalid mnemonic word count")
	// ErrNoEntropy is returned by Cardano (ADA) operations on a wallet that has no
	// BIP-39 entropy to derive from. Cardano's Icarus master key is built from the
	// mnemonic entropy, not the seed, so a wallet imported from a raw private key,
	// WIF, or extended public key (which carry no mnemonic) cannot derive Cardano
	// addresses or signatures.
	ErrNoEntropy = errors.New("hdwallet: Cardano requires a mnemonic-derived wallet (no BIP-39 entropy available)")
)

// HDWallet is an HD wallet derived from a BIP-39 mnemonic. Its sensitive
// material is protected in memory; see the package documentation. All methods
// are safe for concurrent use.
type HDWallet struct {
	mu     sync.RWMutex
	secret *secret
}

// NewHDWallet creates a wallet with a fresh 12-word (128-bit) mnemonic. It is a
// convenience wrapper over NewHDWalletWithWordCount(12).
func NewHDWallet() (*HDWallet, error) {
	return NewHDWalletWithWordCount(12)
}

// NewHDWalletWithWordCount creates a wallet with a fresh mnemonic of the given
// length in words. words must be one of 12, 15, 18, 21, or 24; any other value
// returns an error wrapping ErrInvalidWordCount.
func NewHDWalletWithWordCount(words int) (*HDWallet, error) {
	bits, err := wordCountToEntropyBits(words)
	if err != nil {
		return nil, err
	}
	return NewHDWalletWithEntropy(bits)
}

// NewHDWalletWithEntropy creates a wallet with a fresh mnemonic generated from
// bits of BIP-39 entropy. bits must be one of 128, 160, 192, 224, or 256
// (yielding 12, 15, 18, 21, or 24 words); any other value returns an error
// wrapping ErrInvalidWordCount.
func NewHDWalletWithEntropy(bits int) (*HDWallet, error) {
	mnemonic, err := generateMnemonicBytes(bits)
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
//
// It uses the empty BIP-39 passphrase (Trust Wallet's default). For a
// passphrase-protected ("hidden") wallet, use FromMnemonicWithPassphrase.
func FromMnemonicBytes(mnemonic []byte) (*HDWallet, error) {
	s, err := newSecret(mnemonic, nil)
	if err != nil {
		return nil, err
	}
	return &HDWallet{secret: s}, nil
}

// FromMnemonicWithPassphrase builds a wallet from a mnemonic and an optional
// BIP-39 passphrase (the "25th word"), both held in byte slices. A different
// passphrase derives a completely different set of addresses from the same
// mnemonic; the empty passphrase (nil or empty slice) matches FromMnemonicBytes
// and Trust Wallet's default.
//
// Both slices are wiped before the function returns; callers must not reuse
// them. Like the mnemonic, the passphrase is briefly converted to a Go string
// internally for BIP-39 seed derivation (see the package secret-handling notes).
func FromMnemonicWithPassphrase(mnemonic, passphrase []byte) (*HDWallet, error) {
	s, err := newSecret(mnemonic, passphrase)
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
//
// It uses the empty BIP-39 passphrase (Trust Wallet's default). For a
// passphrase-protected wallet, use FromMnemonicBufferWithPassphrase.
func FromMnemonicBuffer(buf *memguard.LockedBuffer) (*HDWallet, error) {
	s, err := newSecretFromBuffer(buf, nil)
	if err != nil {
		return nil, err
	}
	return &HDWallet{secret: s}, nil
}

// FromMnemonicBufferWithPassphrase is the most secure passphrase entry point:
// both the mnemonic and the BIP-39 passphrase are supplied in page-locked,
// encrypted-at-rest memguard buffers and used without an intermediate plaintext
// heap copy (aside from the unavoidable transient BIP-39 string conversion).
//
// The wallet takes ownership of both buffers and destroys them; do not use
// either afterwards. passphrase may be nil for the empty passphrase. Surrounding
// whitespace in the mnemonic buffer is trimmed; the passphrase is used verbatim.
func FromMnemonicBufferWithPassphrase(buf, passphrase *memguard.LockedBuffer) (*HDWallet, error) {
	var pass []byte
	if passphrase != nil {
		if !passphrase.IsAlive() {
			return nil, fmt.Errorf("%w: passphrase buffer is destroyed", ErrDestroyed)
		}
		pass = passphrase.Bytes() // used transiently; destroyed below
		defer passphrase.Destroy()
	}
	s, err := newSecretFromBuffer(buf, pass)
	if err != nil {
		return nil, err
	}
	return &HDWallet{secret: s}, nil
}

// GenerateMnemonic returns a fresh 12-word BIP-39 mnemonic as a Go string.
//
// Security note: Go strings are GC-managed and cannot be reliably wiped from
// memory. For security-sensitive applications (hardware wallets, HSMs) prefer
// [GenerateMnemonicBuffer], which returns the phrase in a page-locked enclave
// that is wiped on Destroy. If you use this function, call [FromMnemonicBytes]
// immediately and discard the string rather than storing it.
func GenerateMnemonic() (string, error) {
	return GenerateMnemonicWithWordCount(12)
}

// GenerateMnemonicBuffer returns a fresh 12-word BIP-39 mnemonic in a
// page-locked, encrypted-at-rest memguard buffer. The caller must call Destroy
// on the returned buffer when finished. This is the secure alternative to
// [GenerateMnemonic] for applications where the phrase must not linger on the
// Go heap.
func GenerateMnemonicBuffer() (*memguard.LockedBuffer, error) {
	return GenerateMnemonicBufferWithWordCount(12)
}

// GenerateMnemonicBufferWithWordCount returns a fresh BIP-39 mnemonic of the
// given length (12, 15, 18, 21, or 24 words) in a page-locked memguard buffer.
// An unsupported word count returns ErrInvalidWordCount.
func GenerateMnemonicBufferWithWordCount(words int) (*memguard.LockedBuffer, error) {
	bits, err := wordCountToEntropyBits(words)
	if err != nil {
		return nil, err
	}
	mn, err := generateMnemonicBytes(bits)
	if err != nil {
		return nil, err
	}
	return memguard.NewBufferFromBytes(mn), nil // NewBufferFromBytes wipes mn
}

// GenerateMnemonicWithWordCount returns a fresh BIP-39 mnemonic of the given
// length in words (12, 15, 18, 21, or 24) as a string. Like GenerateMnemonic,
// the returned string cannot be securely wiped; prefer NewHDWalletWithWordCount
// for sensitive use. An unsupported word count returns an error wrapping
// ErrInvalidWordCount.
func GenerateMnemonicWithWordCount(words int) (string, error) {
	bits, err := wordCountToEntropyBits(words)
	if err != nil {
		return "", err
	}
	mn, err := generateMnemonicBytes(bits)
	if err != nil {
		return "", err
	}
	defer wipe(mn)
	return string(mn), nil
}

// ValidateMnemonic reports whether mnemonic is a valid BIP-39 seed phrase. It
// returns nil if the phrase is valid and ErrInvalidMnemonic otherwise, applying
// the same wordlist, word-count, and checksum checks FromMnemonic does — but
// without constructing a wallet or retaining the phrase, so an import UI can
// validate user input before building anything. Surrounding whitespace is
// trimmed first, exactly as the constructors do.
func ValidateMnemonic(mnemonic string) error {
	if !bip39.IsMnemonicValid(strings.TrimSpace(mnemonic)) {
		return ErrInvalidMnemonic
	}
	return nil
}

// ValidateMnemonicBytes is ValidateMnemonic for a mnemonic held in a byte slice,
// mirroring the FromMnemonic/FromMnemonicBytes string/bytes pairing. Unlike the
// constructors it neither wipes nor modifies the slice: this is a read-only
// validity check, not a wallet entry point.
func ValidateMnemonicBytes(mnemonic []byte) error {
	return ValidateMnemonic(string(mnemonic))
}

// wordCountToEntropyBits maps a BIP-39 word count to its entropy size in bits.
// Valid counts are 12, 15, 18, 21, and 24 (→ 128, 160, 192, 224, 256 bits).
func wordCountToEntropyBits(words int) (int, error) {
	switch words {
	case 12, 15, 18, 21, 24:
		// BIP-39: entropy_bits = words/3 * 32.
		return words / 3 * 32, nil
	default:
		return 0, fmt.Errorf("%w: %d words (want 12, 15, 18, 21, or 24)", ErrInvalidWordCount, words)
	}
}

// generateMnemonicBytes generates a fresh BIP-39 mnemonic with bits of entropy.
// bits must be one of 128, 160, 192, 224, or 256.
func generateMnemonicBytes(bits int) ([]byte, error) {
	switch bits {
	case 128, 160, 192, 224, 256:
	default:
		return nil, fmt.Errorf("%w: %d bits (want 128, 160, 192, 224, or 256)", ErrInvalidWordCount, bits)
	}
	entropy, err := bip39.NewEntropy(bits)
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
// Privacy note: calling Address repeatedly returns the same address. For
// privacy-sensitive applications (receiving from multiple sources) use
// [AddressIndex] with incrementing indices or [AddressRange] for gap-limit
// discovery.
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
	var addr string
	err := w.withLeafPublicKey(symbol, index, func(pub []byte, coin Coin) error {
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

// AllAddresses derives the first address (index 0) for every supported coin. It
// is exactly equivalent to AllAddressesAt(0).
func (w *HDWallet) AllAddresses() (map[Symbol]string, error) {
	return w.AllAddressesAt(0)
}

// AllAddressesAt derives the address at the given index for every supported
// coin, varying the final element of each coin's BIP-32 path (preserving its
// hardened flag) exactly as AddressIndex does. The seed enclave is opened
// exactly once and every coin is derived inside that single decryption window.
//
// index must be below 2^31 (0x80000000); a larger value returns an error. It is
// only available on seed-based wallets; a key-only wallet (imported from a
// single private key) has no seed to enumerate over and returns ErrKeyOnlyWallet.
func (w *HDWallet) AllAddressesAt(index uint32) (map[Symbol]string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return nil, ErrDestroyed
	}
	if w.secret.isKeyOnly() {
		return nil, ErrKeyOnlyWallet
	}
	out := make(map[Symbol]string, len(coins))
	err := w.secret.withSeed(func(seed []byte) error {
		for _, symbol := range SupportedCoins() {
			coin := coins[symbol] // copy; safe to rewrite its Path
			if coin.Curve == Ed25519ExtendedCardano {
				// Cardano derives from the BIP-39 entropy, not this seed; derive it
				// in the same lock window via the entropy enclave so AllAddresses
				// stays complete (see withCardanoAddressAt).
				addr, aerr := w.cardanoAddressAt(symbol, index)
				if aerr != nil {
					return aerr
				}
				out[symbol] = addr
				continue
			}
			path, err := withIndex(coin.Path, index)
			if err != nil {
				return fmt.Errorf("hdwallet: %s: %w", symbol, err)
			}
			coin.Path = path
			addr, err := addressFromSeed(seed, symbol, coin)
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

// AllAddressesCtx is like AllAddresses but respects the context's cancellation.
// Returns partial results and ctx.Err() if cancelled.
func (w *HDWallet) AllAddressesCtx(ctx context.Context) (map[Symbol]string, error) {
	return w.AllAddressesAtCtx(ctx, 0)
}

// AllAddressesAtCtx is like AllAddressesAt but respects cancellation.
// Returns partial results and ctx.Err() if cancelled.
func (w *HDWallet) AllAddressesAtCtx(ctx context.Context, index uint32) (map[Symbol]string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return nil, ErrDestroyed
	}
	if w.secret.isKeyOnly() {
		return nil, ErrKeyOnlyWallet
	}
	out := make(map[Symbol]string, len(coins))
	var ctxErr error
	err := w.secret.withSeed(func(seed []byte) error {
		for _, symbol := range SupportedCoins() {
			if err := ctx.Err(); err != nil {
				ctxErr = err
				return nil
			}
			coin := coins[symbol]
			if coin.Curve == Ed25519ExtendedCardano {
				addr, aerr := w.cardanoAddressAt(symbol, index)
				if aerr != nil {
					return aerr
				}
				out[symbol] = addr
				continue
			}
			path, err := withIndex(coin.Path, index)
			if err != nil {
				return fmt.Errorf("hdwallet: %s: %w", symbol, err)
			}
			coin.Path = path
			addr, err := addressFromSeed(seed, symbol, coin)
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
	return out, ctxErr
}

// AddressResult is the result of deriving one coin address.
type AddressResult struct {
	Address string
	Err     error
}

// AllAddressResults derives all coins at index and returns per-coin results.
// Does not stop on error — all coins are attempted.
func (w *HDWallet) AllAddressResults(index uint32) map[Symbol]AddressResult {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make(map[Symbol]AddressResult, len(coins))
	if w.secret == nil {
		for _, s := range SupportedCoins() {
			out[s] = AddressResult{Err: ErrDestroyed}
		}
		return out
	}
	if w.secret.isKeyOnly() {
		_ = w.secret.withImportedKey(func(priv []byte) error {
			for _, symbol := range SupportedCoins() {
				coin := coins[symbol]
				if coin.Curve == Ed25519ExtendedCardano {
					// cardanoAddressAt→withEntropy returns ErrNoEntropy for key-only wallets.
					_, aerr := w.cardanoAddressAt(symbol, index)
					out[symbol] = AddressResult{Err: aerr}
					continue
				}
				if coin.Curve != w.secret.curve {
					out[symbol] = AddressResult{Err: fmt.Errorf("%w: coin %s is %s, key is %s", ErrCurveMismatch, symbol, coin.Curve, w.secret.curve)}
					continue
				}
				if index != 0 {
					out[symbol] = AddressResult{Err: fmt.Errorf("%w: %s index %d", ErrKeyOnlyIndex, symbol, index)}
					continue
				}
				pub, perr := publicKeyFromPriv(coin.Curve, priv)
				if perr != nil {
					out[symbol] = AddressResult{Err: fmt.Errorf("hdwallet: %s: %w", symbol, perr)}
					continue
				}
				addr, aerr := coin.Encode(pub)
				out[symbol] = AddressResult{Address: addr, Err: aerr}
			}
			return nil
		})
		return out
	}
	_ = w.secret.withSeed(func(seed []byte) error {
		for _, symbol := range SupportedCoins() {
			coin := coins[symbol]
			if coin.Curve == Ed25519ExtendedCardano {
				addr, aerr := w.cardanoAddressAt(symbol, index)
				out[symbol] = AddressResult{Address: addr, Err: aerr}
				continue
			}
			path, perr := withIndex(coin.Path, index)
			if perr != nil {
				out[symbol] = AddressResult{Err: fmt.Errorf("hdwallet: %s: %w", symbol, perr)}
				continue
			}
			coin.Path = path
			addr, aerr := addressFromSeed(seed, symbol, coin)
			out[symbol] = AddressResult{Address: addr, Err: aerr}
		}
		return nil
	})
	return out
}

// cardanoAddressAt derives and encodes the Cardano address for symbol at index
// from the BIP-39 entropy enclave (Cardano's Icarus master comes from entropy,
// not the seed). It assumes the caller already holds w.mu and has verified the
// wallet is alive and seed-based; it opens only the entropy enclave (not the
// seed). The combined payment+staking public key is wiped inside
// withCardanoCombinedPublicKey.
func (w *HDWallet) cardanoAddressAt(symbol Symbol, index uint32) (string, error) {
	coin, ok := coins[symbol]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	paymentPath, err := withIndex(coin.Path, index)
	if err != nil {
		return "", fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	paymentIdx, err := parsePath(paymentPath)
	if err != nil {
		return "", fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	stakingIdx, err := cardanoStakingPath(paymentIdx)
	if err != nil {
		return "", fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	var addr string
	err = w.secret.withEntropy(func(entropy []byte) error {
		pub, perr := cardanoCombinedPublicKey(entropy, paymentIdx, stakingIdx)
		if perr != nil {
			return fmt.Errorf("hdwallet: %s: %w", symbol, perr)
		}
		a, aerr := coin.Encode(pub)
		if aerr != nil {
			return fmt.Errorf("hdwallet: %s: %w", symbol, aerr)
		}
		addr = a
		return nil
	})
	if err != nil {
		return "", err
	}
	return addr, nil
}

// AddressRange derives count consecutive addresses for a single coin symbol
// starting at index start, varying the final element of the coin's BIP-32 path
// (preserving its hardened flag) exactly as AddressIndex does. The returned
// slice is in ascending index order: element i is the address at start+i. A
// count of 0 returns an empty, non-nil slice.
//
// The seed enclave is opened exactly once and every address is derived inside
// that single decryption window. start+count must not exceed 2^31 (0x80000000);
// a larger range returns an out-of-range error, as does an unknown symbol
// (wrapping ErrUnsupportedCoin). It is only available on seed-based wallets; a
// key-only wallet (imported from a single private key) returns ErrKeyOnlyWallet.
func (w *HDWallet) AddressRange(symbol Symbol, start, count uint32) ([]string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return nil, ErrDestroyed
	}
	if w.secret.isKeyOnly() {
		return nil, ErrKeyOnlyWallet
	}
	coin, ok := coins[symbol]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	if uint64(start)+uint64(count) > uint64(hardenedOffset) {
		return nil, fmt.Errorf("address range out of range: start %d + count %d (must end <= %d)", start, count, hardenedOffset)
	}
	out := make([]string, 0, count)
	if coin.Curve == Ed25519ExtendedCardano {
		// Cardano derives from the BIP-39 entropy, not the seed; derive each address
		// from the entropy enclave (cardanoAddressAt opens it per call).
		for i := start; i < start+count; i++ {
			addr, err := w.cardanoAddressAt(symbol, i)
			if err != nil {
				return nil, err
			}
			out = append(out, addr)
		}
		return out, nil
	}
	err := w.secret.withSeed(func(seed []byte) error {
		for i := start; i < start+count; i++ {
			coinCopy := coin // copy; safe to rewrite its Path
			path, err := withIndex(coin.Path, i)
			if err != nil {
				return fmt.Errorf("hdwallet: %s: %w", symbol, err)
			}
			coinCopy.Path = path
			addr, err := addressFromSeed(seed, symbol, coinCopy)
			if err != nil {
				return err
			}
			out = append(out, addr)
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

// withLeafPrivateKey is the single entry point that materialises the leaf private
// key for symbol at index in BOTH wallet modes, passes the raw key plus the
// resolved coin to fn, and guarantees the key is wiped before returning.
//
//   - Seed wallets: derive the key from the seed via withPrivateKey (which wipes
//     the derived key on return).
//   - Key-only wallets: the imported key is the leaf. The coin's curve must equal
//     the imported curve (else ErrCurveMismatch) and index must be 0 (else
//     ErrKeyOnlyIndex); the key is opened and the decrypted copy destroyed on
//     return by withImportedKey.
//
// It holds the read lock and rejects a destroyed wallet. The registry entry is
// never mutated (coin is a copy).
func (w *HDWallet) withLeafPrivateKey(symbol Symbol, index uint32, fn func(priv []byte, coin Coin) error) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return ErrDestroyed
	}
	coin, ok := coins[symbol]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}

	if w.secret.isKeyOnly() {
		if coin.Curve != w.secret.curve {
			return fmt.Errorf("%w: coin %s is %s, key is %s", ErrCurveMismatch, symbol, coin.Curve, w.secret.curve)
		}
		if index != 0 {
			return fmt.Errorf("%w: %s index %d", ErrKeyOnlyIndex, symbol, index)
		}
		return w.secret.withImportedKey(func(priv []byte) error { return fn(priv, coin) })
	}

	path, err := withIndex(coin.Path, index)
	if err != nil {
		return fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	if coin.Curve == Ed25519ExtendedCardano {
		// Cardano derives from the BIP-39 entropy, not the seed. The leaf key handed
		// to fn is the 96-byte payment extended key (the signing key); the address
		// path uses withCardanoCombinedPublicKey, which also derives the staking key.
		coin.Path = path
		return w.secret.withEntropy(func(entropy []byte) error {
			pathIdx, perr := parsePath(coin.Path)
			if perr != nil {
				return fmt.Errorf("hdwallet: %s: %w", symbol, perr)
			}
			return withCardanoPrivateKey(entropy, pathIdx, func(priv []byte) error { return fn(priv, coin) })
		})
	}
	return w.deriveLeafSeedMode(coin, path, fn)
}

// deriveLeafSeedMode derives the leaf private key for coin at the resolved
// absolute path, opening the seed once and handing the wiped-on-return key plus
// the resolved coin to fn. The caller MUST hold w.mu and have verified the
// wallet is in seed mode (secret != nil, not key-only). coin is a copy, so
// overwriting its Path is safe.
func (w *HDWallet) deriveLeafSeedMode(coin Coin, path string, fn func(priv []byte, coin Coin) error) error {
	coin.Path = path
	return w.secret.withSeed(func(seed []byte) error {
		return withPrivateKey(seed, coin, func(priv []byte) error { return fn(priv, coin) })
	})
}

// withLeafPrivateKeyPath is the custom-path counterpart of withLeafPrivateKey: it
// materialises the leaf key for symbol at an arbitrary absolute BIP-32 path
// instead of the coin's template-derived index. It is seed-only — a key-only
// wallet has a single leaf and no HD path, so it returns ErrKeyOnlyWallet. The
// path is validated with parsePath before any derivation.
func (w *HDWallet) withLeafPrivateKeyPath(symbol Symbol, path string, fn func(priv []byte, coin Coin) error) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return ErrDestroyed
	}
	coin, ok := coins[symbol]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	if w.secret.isKeyOnly() {
		return fmt.Errorf("%w: %s custom path", ErrKeyOnlyWallet, symbol)
	}
	if _, err := parsePath(path); err != nil {
		return fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	return w.deriveLeafSeedMode(coin, path, fn)
}

// withLeafPublicKey materialises the leaf private key (both modes), derives its
// public key, and runs fn with the public key bytes and resolved coin. The
// private key is wiped before fn runs (it is consumed inside withLeafPrivateKey).
func (w *HDWallet) withLeafPublicKey(symbol Symbol, index uint32, fn func(pub []byte, coin Coin) error) error {
	if c, ok := coins[symbol]; ok && c.Curve == Ed25519ExtendedCardano {
		// A Cardano base address is built from two keys — the payment key at the
		// coin's role-0 path and the staking key at the role-2 path — so the encoder
		// receives the 128-byte ED25519Cardano public key (payment point||chain ||
		// staking point||chain), not the single-key form publicKeyFromPriv yields.
		return w.withCardanoCombinedPublicKey(symbol, index, fn)
	}
	return w.withLeafPrivateKey(symbol, index, func(priv []byte, coin Coin) error {
		pub, err := publicKeyFromPriv(coin.Curve, priv)
		if err != nil {
			return fmt.Errorf("hdwallet: %s: %w", symbol, err)
		}
		return fn(pub, coin)
	})
}

// withCardanoCombinedPublicKey derives the Cardano payment key (role 0) and
// staking key (role 2) for symbol at index, assembles the 128-byte
// ED25519Cardano public key Trust Wallet Core's address encoder expects
// (paymentPoint(32)||paymentChain(32)||stakingPoint(32)||stakingChain(32)), and
// runs fn with it. Both extended private keys are wiped on return by
// withCardanoPrivateKey. It is seed-mode only (Cardano needs BIP-39 entropy);
// a wallet without entropy returns ErrNoEntropy via withEntropy.
func (w *HDWallet) withCardanoCombinedPublicKey(symbol Symbol, index uint32, fn func(pub []byte, coin Coin) error) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return ErrDestroyed
	}
	coin, ok := coins[symbol]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	paymentPath, err := withIndex(coin.Path, index)
	if err != nil {
		return fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	paymentIdx, err := parsePath(paymentPath)
	if err != nil {
		return fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	// The staking path is the payment path with the role element (index 3) forced
	// to 2 and the address element (index 4) forced to 0 — matching TWC's
	// HDWallet.cpp stakingPath construction.
	stakingIdx, err := cardanoStakingPath(paymentIdx)
	if err != nil {
		return fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	return w.secret.withEntropy(func(entropy []byte) error {
		pub, perr := cardanoCombinedPublicKey(entropy, paymentIdx, stakingIdx)
		if perr != nil {
			return fmt.Errorf("hdwallet: %s: %w", symbol, perr)
		}
		return fn(pub, coin)
	})
}

// withLeafPublicKeyPath is the custom-path counterpart of withLeafPublicKey.
func (w *HDWallet) withLeafPublicKeyPath(symbol Symbol, path string, fn func(pub []byte, coin Coin) error) error {
	return w.withLeafPrivateKeyPath(symbol, path, func(priv []byte, coin Coin) error {
		pub, err := publicKeyFromPriv(coin.Curve, priv)
		if err != nil {
			return fmt.Errorf("hdwallet: %s: %w", symbol, err)
		}
		return fn(pub, coin)
	})
}

// Sign signs data with the key for symbol at address index 0. See SignIndex.
func (w *HDWallet) Sign(symbol Symbol, data []byte) (*Signature, error) {
	return w.SignIndex(symbol, 0, data)
}

// SignIndex signs data with the private key derived for symbol at the given
// address index and returns the signature.
//
// For ECDSA chains (secp256k1, nist256p1 — e.g. BTC, ETH, ATOM, NEO) data must
// be the 32-byte digest the chain signs; pre-hash the message with the chain's
// hash function (keccak256 for Ethereum/Tron, double-SHA256 for Bitcoin, SHA-256
// for Cosmos, …). For ed25519 chains (e.g. SOL, XLM, DOT) data is the message
// itself; the EdDSA scheme hashes internally.
//
// The derived private key is wiped immediately after signing and never leaves
// the package.
func (w *HDWallet) SignIndex(symbol Symbol, index uint32, data []byte) (*Signature, error) {
	if data == nil {
		return nil, fmt.Errorf("%w: nil data", ErrInvalidDigest)
	}
	var sig *Signature
	err := w.withLeafPrivateKey(symbol, index, func(priv []byte, coin Coin) error {
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

// PublicKey returns the public key for symbol at address index 0. See
// PublicKeyIndex.
func (w *HDWallet) PublicKey(symbol Symbol) ([]byte, error) {
	return w.PublicKeyIndex(symbol, 0)
}

// PublicKeyIndex returns the public key derived for symbol at the given address
// index: the 33-byte compressed key for secp256k1/nist256p1, or the 32-byte key
// for ed25519. Signing callers need this to build or verify transactions.
func (w *HDWallet) PublicKeyIndex(symbol Symbol, index uint32) ([]byte, error) {
	var pub []byte
	err := w.withLeafPublicKey(symbol, index, func(p []byte, _ Coin) error {
		pub = append([]byte(nil), p...) // copy out before the lock is released
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pub, nil
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
	if w.secret.isKeyOnly() {
		return nil, ErrKeyOnlyWallet
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
	if w.secret.isKeyOnly() {
		return ErrKeyOnlyWallet
	}
	buf, err := w.secret.openMnemonic()
	if err != nil {
		return err
	}
	defer buf.Destroy()
	return fn(buf.Bytes())
}

// Destroy wipes the wallet's secret material from memory. After Destroy
// returns, all methods that require secret material return [ErrDestroyed]. Safe
// to call multiple times; subsequent calls are no-ops.
//
// Destroy does not wait for in-flight Sign or Address operations to complete.
// If concurrent goroutines may be using the wallet, callers must coordinate
// shutdown before calling Destroy.
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
