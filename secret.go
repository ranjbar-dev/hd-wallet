package hdwallet

import (
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
// enclaves. The input mnemonic slice is wiped — callers must pass a slice they
// are willing to surrender ownership of.
func newSecret(mnemonic []byte) (*secret, error) {
	// bip39 only accepts strings; this transient copy cannot be wiped and is
	// the one unavoidable plaintext exposure, bounded by GC. We minimise it to
	// a single conversion used for validation and seed derivation.
	phrase := string(mnemonic)
	if !bip39.IsMnemonicValid(phrase) {
		wipe(mnemonic)
		return nil, errors.New("invalid mnemonic")
	}

	seed := bip39.NewSeed(phrase, "") // empty passphrase == Trust Wallet default

	return &secret{
		seed:     memguard.NewBufferFromBytes(seed).Seal(),     // wipes seed
		mnemonic: memguard.NewBufferFromBytes(mnemonic).Seal(), // wipes mnemonic
	}, nil
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
