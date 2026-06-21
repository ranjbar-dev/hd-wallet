package hdwallet_test

import (
	"testing"

	hdwallet "github.com/ranjbar-dev/hd-wallet"
)

// benchMnemonic is the standard BIP-39 test vector mnemonic (holds no funds).
const benchMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// BenchmarkAddressBTC measures secp256k1 (BIP-32) derivation + encoding.
func BenchmarkAddressBTC(b *testing.B) {
	w, err := hdwallet.FromMnemonic(benchMnemonic)
	if err != nil {
		b.Fatal(err)
	}
	defer w.Destroy()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Address("BTC"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAddressSOL measures ed25519 (SLIP-0010) derivation + encoding.
func BenchmarkAddressSOL(b *testing.B) {
	w, err := hdwallet.FromMnemonic(benchMnemonic)
	if err != nil {
		b.Fatal(err)
	}
	defer w.Destroy()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Address("SOL"); err != nil {
			b.Fatal(err)
		}
	}
}
