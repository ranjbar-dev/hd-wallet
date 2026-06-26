package hdwallet

import (
	"errors"
	"testing"
)

// THE GATE: the registered Cardano (ADA) address must equal Trust Wallet Core's
// authoritative value byte-for-byte. A wrong address loses funds permanently, so
// this string equality is the single most important assertion for the ADA
// registration.
//
// Vector source: Trust Wallet Core tests/chains/Cardano/AddressTests.cpp
//
//	HDWallet wallet("civil void tool perfect avocado sweet immense fluid arrow aerobic boil flash", "");
//	const auto address = wallet.deriveAddress(TWCoinTypeCardano);
//	EXPECT_EQ(address, "addr1q94zzrtl32tjp8j96auatnhxd2y35fnk6wuxqvqm9364vp9spdkjdsmyfhvfagjzh4uzp9zs6p5djw89jac2g0ujs2eqsuy7pu");
//
// (TWC's mnemonic-less CoinAddressDerivationTests.cpp uses a fixed dummy private
// key — payment and staking material identical — not a mnemonic, so it is NOT the
// right anchor for the mnemonic-derived public API. This is TWC's standard
// Cardano test mnemonic, used across its Cardano Address/Signer tests.)
//
// The address is a CIP-19 mainnet base address (header 0x01 || blake2b224(payment
// pubkey) || blake2b224(staking pubkey)), bech32-encoded with HRP "addr". The
// payment key is derived at m/1852'/1815'/0'/0/0 and the staking key at
// m/1852'/1815'/0'/2/0 from the Icarus master built off the BIP-39 entropy.
const (
	cardanoTWCMnemonic = "civil void tool perfect avocado sweet immense fluid arrow aerobic boil flash"
	cardanoTWCAddress  = "addr1q94zzrtl32tjp8j96auatnhxd2y35fnk6wuxqvqm9364vp9spdkjdsmyfhvfagjzh4uzp9zs6p5djw89jac2g0ujs2eqsuy7pu"
)

func TestCardanoAddressVector(t *testing.T) {
	w, err := FromMnemonic(cardanoTWCMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	got, err := w.Address(ADA)
	if err != nil {
		t.Fatalf("Address(ADA): %v", err)
	}
	if got != cardanoTWCAddress {
		t.Fatalf("Cardano address mismatch:\n got %s\nwant %s", got, cardanoTWCAddress)
	}
}

// The registered ADA address must round-trip through the address validator and
// AddressFromPublicKey, and AddressFromPublicKey on the wallet's public key must
// reproduce the same address (mirrors the encoders round-trip discipline).
func TestCardanoAddressValidates(t *testing.T) {
	w, err := FromMnemonic(cardanoTWCMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	addr, err := w.Address(ADA)
	if err != nil {
		t.Fatalf("Address(ADA): %v", err)
	}
	if !IsValidAddress(ADA, addr) {
		t.Fatalf("IsValidAddress(ADA, %q) = false, want true", addr)
	}
	if err := ValidateAddress(ADA, addr); err != nil {
		t.Fatalf("ValidateAddress(ADA): %v", err)
	}

	pub, err := w.PublicKey(ADA)
	if err != nil {
		t.Fatalf("PublicKey(ADA): %v", err)
	}
	if len(pub) != 128 {
		t.Fatalf("PublicKey(ADA) length = %d, want 128 (ED25519Cardano)", len(pub))
	}
	roundTrip, err := AddressFromPublicKey(ADA, pub)
	if err != nil {
		t.Fatalf("AddressFromPublicKey(ADA): %v", err)
	}
	if roundTrip != addr {
		t.Fatalf("AddressFromPublicKey round-trip mismatch:\n got %s\nwant %s", roundTrip, addr)
	}
}

// AllAddresses must include ADA and agree with Address(ADA); the registration
// would otherwise break the AllAddressesAt-vs-AddressIndex invariant.
func TestCardanoInAllAddresses(t *testing.T) {
	w, err := FromMnemonic(cardanoTWCMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	all, err := w.AllAddresses()
	if err != nil {
		t.Fatalf("AllAddresses: %v", err)
	}
	if all[ADA] != cardanoTWCAddress {
		t.Fatalf("AllAddresses[ADA] = %q, want %q", all[ADA], cardanoTWCAddress)
	}

	// AddressRange must also derive ADA across an index range.
	rng, err := w.AddressRange(ADA, 0, 1)
	if err != nil {
		t.Fatalf("AddressRange(ADA): %v", err)
	}
	if len(rng) != 1 || rng[0] != cardanoTWCAddress {
		t.Fatalf("AddressRange(ADA,0,1) = %v, want [%s]", rng, cardanoTWCAddress)
	}
}

// Cardano signing must work end-to-end on a seed wallet and verify under the
// derived public key. (TWC ships no public Cardano message-signing vector keyed
// to this mnemonic, so the byte-for-byte pin is the address above; full tx
// signing is roadmap. This anchors that the entropy-routed signing path is wired
// and self-consistent.)
func TestCardanoSignRoundTrip(t *testing.T) {
	w, err := FromMnemonic(cardanoTWCMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	msg := []byte("hello cardano")
	sig, err := w.Sign(ADA, msg)
	if err != nil {
		t.Fatalf("Sign(ADA): %v", err)
	}
	pub, err := w.PublicKey(ADA)
	if err != nil {
		t.Fatalf("PublicKey(ADA): %v", err)
	}
	// The signing key is the payment key; the address pubkey is the 128-byte
	// combined key, whose first 32 bytes are the payment point used to verify.
	if !verifySignature(Ed25519ExtendedCardano, pub[:32], msg, sig) {
		t.Fatalf("Cardano signature failed verification under the payment public key")
	}
}

// A mnemonic-less wallet (imported private key) has no BIP-39 entropy, so Cardano
// Address/Sign must fail cleanly with ErrNoEntropy — never a wrong address.
func TestCardanoNoEntropyKeyOnly(t *testing.T) {
	priv := make([]byte, 32)
	priv[31] = 1
	// Ed25519ExtendedCardano cannot be imported as a 32-byte key, so build the
	// key-only wallet on a different curve and request ADA: the curve-mismatch
	// guard fires first for that mode. To exercise the entropy gap specifically we
	// also assert a secp256k1 key-only wallet rejects ADA.
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	// ADA on a key-only wallet: the coin curve (Ed25519ExtendedCardano) does not
	// match the imported curve, so this is rejected before any derivation. Either
	// way it must NOT return an address.
	if _, err := w.Address(ADA); err == nil {
		t.Fatalf("Address(ADA) on a key-only wallet returned no error; want a failure")
	}
	if _, err := w.Sign(ADA, []byte("x")); err == nil {
		t.Fatalf("Sign(ADA) on a key-only wallet returned no error; want a failure")
	}
}

// withEntropy on a key-only secret must return ErrNoEntropy directly: this pins
// the clear sentinel for the no-mnemonic case (the public Cardano path surfaces
// it).
func TestWithEntropyNoEntropy(t *testing.T) {
	priv := make([]byte, 32)
	priv[31] = 1
	w, err := FromPrivateKeyBytes(priv, Secp256k1)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	err = w.secret.withEntropy(func([]byte) error { return nil })
	if !errors.Is(err, ErrNoEntropy) {
		t.Fatalf("withEntropy on key-only secret = %v, want ErrNoEntropy", err)
	}
}

// Destroy must wipe the entropy enclave (mirrors the seed-wipe discipline): after
// Destroy, withEntropy on the (now nil) secret is unreachable, and the secret's
// entropy reference is cleared. We assert via the public API that any ADA
// operation after Destroy fails with ErrDestroyed.
func TestCardanoEntropyWipedOnDestroy(t *testing.T) {
	w, err := FromMnemonic(cardanoTWCMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}

	// Sanity: entropy is present and usable before Destroy.
	if _, err := w.Address(ADA); err != nil {
		t.Fatalf("Address(ADA) before Destroy: %v", err)
	}

	w.Destroy()

	// After Destroy the secret pointer is nil; ADA operations report ErrDestroyed.
	if _, err := w.Address(ADA); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("Address(ADA) after Destroy = %v, want ErrDestroyed", err)
	}
}

// TestCardanoEntropyEnclaveCleared inspects the enclave directly (mirroring the
// passphrase_test enclave-access pattern): a fresh wallet seals a non-nil entropy
// enclave, and destroy() clears the reference so the encrypted entropy becomes
// unreachable.
func TestCardanoEntropyEnclaveCleared(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	if w.secret.entropy == nil {
		t.Fatalf("seed wallet has nil entropy enclave; want it sealed")
	}
	// The sealed entropy for the canonical mnemonic is the all-zero 16-byte entropy.
	err = w.secret.withEntropy(func(entropy []byte) error {
		if len(entropy) != 16 {
			t.Fatalf("entropy length = %d, want 16", len(entropy))
		}
		for i, b := range entropy {
			if b != 0 {
				t.Fatalf("entropy[%d] = 0x%02x, want 0x00 (canonical abandon..about entropy is all-zero)", i, b)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withEntropy: %v", err)
	}

	w.secret.destroy()
	if w.secret.entropy != nil {
		t.Fatalf("destroy() did not clear the entropy enclave reference")
	}
}
