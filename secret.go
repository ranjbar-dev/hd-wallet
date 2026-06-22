package hdwallet

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/awnumar/memguard"
	bip39 "github.com/tyler-smith/go-bip39"
)

// secret holds the wallet's sensitive material inside memguard enclaves.
// Enclaves keep the data encrypted in RAM, in pages locked against swapping to
// disk; they are decrypted into a short-lived LockedBuffer only for the duration
// of a single operation and destroyed immediately afterwards. The plaintext is
// never stored on the Go heap for longer than one derivation.
//
// A secret is in one of two modes:
//
//   - Seed mode (the default, from a BIP-39 mnemonic): seed and mnemonic are set
//     and privKey is nil. Keys are derived on demand from the seed.
//   - Key-only mode (from an imported private key): privKey and curve are set and
//     seed/mnemonic are nil. The imported key IS the leaf — there is no HD path,
//     so only address index 0 is meaningful and there is no mnemonic to read.
type secret struct {
	seed     *memguard.Enclave
	mnemonic *memguard.Enclave

	// Key-only mode: a single imported leaf private key and its curve. When
	// privKey is non-nil the secret is key-only and seed/mnemonic are nil.
	privKey *memguard.Enclave
	curve   Curve
}

// isKeyOnly reports whether the secret was built from an imported private key
// (no seed, no mnemonic, no HD path).
func (s *secret) isKeyOnly() bool { return s.privKey != nil }

// newSecret validates the mnemonic, derives the seed, and seals both into
// enclaves. Surrounding ASCII whitespace is trimmed first, matching
// FromMnemonicBuffer, so a trailing newline is not mistaken for an invalid
// phrase. The input mnemonic slice is wiped — callers must pass a slice they are
// willing to surrender ownership of.
func newSecret(mnemonic []byte) (*secret, error) {
	defer wipe(mnemonic) // always wipe the caller's untrimmed copy

	trimmed := bytes.TrimSpace(mnemonic) // sub-slice; sealed via a copy below

	seedEnclave, err := deriveSeedEnclave(trimmed)
	if err != nil {
		return nil, err
	}

	// Seal a copy of the trimmed phrase so the surrounding whitespace in the
	// caller's backing array is still wiped by the deferred wipe above.
	mnBuf := memguard.NewBufferFromBytes(trimmed)
	return &secret{
		seed:     seedEnclave,
		mnemonic: mnBuf.Seal(),
	}, nil
}

// newSecretFromBuffer is the strongest entry point: the mnemonic is supplied in
// a memguard LockedBuffer and is sealed into an enclave without ever being
// copied into an unprotected heap slice. The wallet takes ownership of buf and
// destroys it. Surrounding whitespace is trimmed before use.
func newSecretFromBuffer(buf *memguard.LockedBuffer) (*secret, error) {
	if buf == nil || !buf.IsAlive() {
		return nil, errors.New("hdwallet: mnemonic buffer is nil or destroyed")
	}

	raw := buf.Bytes()
	trimmed := bytes.TrimSpace(raw) // sub-slice of protected memory; no copy

	seedEnclave, err := deriveSeedEnclave(trimmed)
	if err != nil {
		buf.Destroy()
		return nil, err
	}

	var mnemonic *memguard.Enclave
	if len(trimmed) == len(raw) {
		// No trimming needed: seal the caller's buffer directly (zero copy).
		mnemonic = buf.Seal()
	} else {
		// Copy the trimmed phrase protected-memory -> protected-memory, then seal.
		norm := memguard.NewBuffer(len(trimmed))
		norm.Copy(trimmed)
		mnemonic = norm.Seal()
		buf.Destroy()
	}

	return &secret{seed: seedEnclave, mnemonic: mnemonic}, nil
}

// privateKeyLen is the raw private-key length for every supported curve: 32
// bytes (secp256k1 scalar, ed25519 seed, NIST P-256 scalar).
const privateKeyLen = 32

// newSecretFromPrivateKey seals an imported raw private key into a key-only
// secret. The input slice is wiped — callers must surrender ownership of it
// (mirrors newSecret). The key is validated for the curve before sealing.
func newSecretFromPrivateKey(priv []byte, curve Curve) (*secret, error) {
	defer wipe(priv)

	if err := validatePrivateKey(priv, curve); err != nil {
		return nil, err
	}

	// Seal a copy so the caller's backing array is still wiped by the deferred
	// wipe above.
	buf := memguard.NewBufferFromBytes(priv) // wipes priv into protected memory
	return &secret{privKey: buf.Seal(), curve: curve}, nil
}

// newSecretFromPrivateKeyBuffer is the strongest key-import entry point: the
// private key is supplied in a memguard LockedBuffer and sealed into an enclave
// without ever being copied onto an unprotected heap slice. The wallet takes
// ownership of buf and destroys it (mirrors newSecretFromBuffer).
func newSecretFromPrivateKeyBuffer(buf *memguard.LockedBuffer, curve Curve) (*secret, error) {
	if buf == nil || !buf.IsAlive() {
		return nil, errors.New("hdwallet: private-key buffer is nil or destroyed")
	}

	if err := validatePrivateKey(buf.Bytes(), curve); err != nil {
		buf.Destroy()
		return nil, err
	}

	// Zero-copy: seal the caller's protected buffer directly.
	return &secret{privKey: buf.Seal(), curve: curve}, nil
}

// validatePrivateKey checks that priv is a plausible private key for curve: the
// correct length and not the all-zero scalar (which is not a valid key on any of
// the supported curves and would derive a point at infinity).
func validatePrivateKey(priv []byte, curve Curve) error {
	switch curve {
	case Secp256k1, Ed25519, Nist256p1:
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedCurve, curve)
	}
	if len(priv) != privateKeyLen {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidPrivateKey, len(priv), privateKeyLen)
	}
	allZero := true
	for _, b := range priv {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%w: key is all zero", ErrInvalidPrivateKey)
	}
	return nil
}

// withImportedKey opens the key-only private-key enclave, copies the plaintext
// into a transient slice, runs fn with it, and wipes that copy before returning.
// The decrypted LockedBuffer is destroyed regardless of fn's outcome. It must
// only be called on a key-only secret (privKey != nil).
func (s *secret) withImportedKey(fn func(priv []byte) error) error {
	buf, err := s.privKey.Open()
	if err != nil {
		return err
	}
	defer buf.Destroy()
	return fn(buf.Bytes())
}

// deriveSeedEnclave validates a mnemonic and returns its BIP-39 seed sealed in
// an enclave. It does not take ownership of mnemonic (the caller wipes/seals it).
//
// bip39 only accepts strings, so a single transient string conversion is made
// here for validation and seed derivation; it cannot be wiped and is bounded by
// GC. This is the one residual plaintext exposure in the secret path.
func deriveSeedEnclave(mnemonic []byte) (*memguard.Enclave, error) {
	phrase := string(mnemonic)
	if !bip39.IsMnemonicValid(phrase) {
		return nil, ErrInvalidMnemonic
	}
	seed := bip39.NewSeed(phrase, "")                    // empty passphrase == Trust Wallet default
	return memguard.NewBufferFromBytes(seed).Seal(), nil // wipes seed
}

// withSeed opens the seed enclave, runs fn with the plaintext seed, and destroys
// the decrypted buffer before returning.
func (s *secret) withSeed(fn func(seed []byte) error) error {
	buf, err := s.seed.Open()
	if err != nil {
		return err
	}
	defer buf.Destroy()
	return fn(buf.Bytes())
}

// openMnemonic decrypts the mnemonic into a LockedBuffer. The caller must call
// Destroy on the returned buffer.
func (s *secret) openMnemonic() (*memguard.LockedBuffer, error) {
	return s.mnemonic.Open()
}

// destroy drops the enclave references so their encrypted contents become
// unreachable and eligible for collection. For a hard, immediate wipe of all
// memguard-protected memory in the process, call memguard.Purge.
func (s *secret) destroy() {
	s.seed = nil
	s.mnemonic = nil
	s.privKey = nil
}
