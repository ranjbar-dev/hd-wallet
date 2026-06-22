package hdwallet

import (
	"encoding/hex"
	"testing"
)

// The canonical all-abandon/about mnemonic is the first BIP-39 official
// (Trezor) test vector. The official vectors.json specifies the seed for the
// "TREZOR" passphrase, giving an authoritative anchor for the passphrase
// plumbing. (The empty-passphrase path is anchored by every existing address
// test in the suite, so it is exercised via TestFromMnemonicWithPassphrase
// rather than a hardcoded seed here.)
const passphraseTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// TestBIP39SeedVector checks deriveSeedEnclave against the official BIP-39 seed
// for the "TREZOR" passphrase.
func TestBIP39SeedVector(t *testing.T) {
	const wantSeed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"

	enc, err := deriveSeedEnclave([]byte(passphraseTestMnemonic), []byte("TREZOR"))
	if err != nil {
		t.Fatalf("deriveSeedEnclave: %v", err)
	}
	buf, err := enc.Open()
	if err != nil {
		t.Fatalf("open seed enclave: %v", err)
	}
	defer buf.Destroy()
	if got := hex.EncodeToString(buf.Bytes()); got != wantSeed {
		t.Fatalf("seed mismatch:\n got %s\nwant %s", got, wantSeed)
	}
}

// TestFromMnemonicWithPassphrase confirms the public constructors thread the
// passphrase: a passphrase wallet derives different addresses from the same
// mnemonic with no passphrase, and the empty-passphrase constructor matches the
// default FromMnemonic.
func TestFromMnemonicWithPassphrase(t *testing.T) {
	plain, err := FromMnemonic(passphraseTestMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer plain.Destroy()

	hidden, err := FromMnemonicWithPassphrase([]byte(passphraseTestMnemonic), []byte("TREZOR"))
	if err != nil {
		t.Fatalf("FromMnemonicWithPassphrase: %v", err)
	}
	defer hidden.Destroy()

	plainETH, err := plain.Address(ETH)
	if err != nil {
		t.Fatalf("plain ETH: %v", err)
	}
	hiddenETH, err := hidden.Address(ETH)
	if err != nil {
		t.Fatalf("hidden ETH: %v", err)
	}
	if plainETH == hiddenETH {
		t.Fatalf("passphrase wallet derived the same ETH address as the no-passphrase wallet (%s); passphrase not applied", plainETH)
	}

	// Empty passphrase must equal the default constructor.
	empty, err := FromMnemonicWithPassphrase([]byte(passphraseTestMnemonic), nil)
	if err != nil {
		t.Fatalf("FromMnemonicWithPassphrase(nil): %v", err)
	}
	defer empty.Destroy()
	emptyETH, err := empty.Address(ETH)
	if err != nil {
		t.Fatalf("empty ETH: %v", err)
	}
	if emptyETH != plainETH {
		t.Fatalf("empty-passphrase address %s != default %s", emptyETH, plainETH)
	}
}
