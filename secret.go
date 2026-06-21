package hdwallet

import (
	"bytes"
	"errors"

	"github.com/awnumar/memguard"
	bip39 "github.com/tyler-smith/go-bip39"
)

// secret holds the wallet's sensitive material — the BIP-39 mnemonic and the
// derived seed — inside memguard enclaves. Enclaves keep the data encrypted in
// RAM, in pages locked against swapping to disk; they are decrypted into a
// short-lived LockedBuffer only for the duration of a single operation and
// destroyed immediately afterwards. The plaintext is never stored on the Go
// heap for longer than one derivation.
type secret struct {
	seed     *memguard.Enclave
	mnemonic *memguard.Enclave
}

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
}
