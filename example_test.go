package hdwallet_test

import (
	"fmt"
	"log"
	"strings"

	"github.com/awnumar/memguard"

	hdwallet "github.com/ranjbar-dev/hd-wallet"
)

// exampleMnemonic is the standard BIP-39 test vector mnemonic. Never hard-code a
// real mnemonic in source; this one holds no funds and is used only for docs.
const exampleMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// ExampleNewHDWallet creates a wallet with a fresh, random mnemonic and derives
// an address. Output is omitted because the mnemonic (and therefore the address)
// is random on every run.
func ExampleNewHDWallet() {
	w, err := hdwallet.NewHDWallet()
	if err != nil {
		log.Fatal(err)
	}
	defer w.Destroy() // wipe the wallet's secrets when finished

	addr, err := w.Address(hdwallet.ETH)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(strings.HasPrefix(addr, "0x"))
	// Output: true
}

// ExampleHDWallet_Address derives the first receive address for several chains
// from a fixed mnemonic, producing deterministic, Trust Wallet-compatible
// addresses.
func ExampleHDWallet_Address() {
	w, err := hdwallet.FromMnemonic(exampleMnemonic)
	if err != nil {
		log.Fatal(err)
	}
	defer w.Destroy()

	btc, _ := w.Address(hdwallet.BTC)
	eth, _ := w.Address(hdwallet.ETH)
	fmt.Println(btc)
	fmt.Println(eth)
	// Output:
	// bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
	// 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
}

// ExampleHDWallet_AddressIndex derives multiple receive addresses for the same
// chain by varying the final path index.
func ExampleHDWallet_AddressIndex() {
	w, err := hdwallet.FromMnemonic(exampleMnemonic)
	if err != nil {
		log.Fatal(err)
	}
	defer w.Destroy()

	first, _ := w.AddressIndex(hdwallet.BTC, 0)
	second, _ := w.AddressIndex(hdwallet.BTC, 1)
	fmt.Println(first)
	fmt.Println(second)
	// Output:
	// bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
	// bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g
}

// ExampleFromMnemonicBuffer shows the most secure way to import a mnemonic: the
// phrase lives in a page-locked, encrypted memguard buffer and is handed to the
// wallet without an intermediate plaintext copy. The wallet takes ownership of
// the buffer and destroys it.
func ExampleFromMnemonicBuffer() {
	// In real code, read the mnemonic straight into protected memory (for
	// example with memguard.NewBufferFromReaderUntil over stdin).
	buf := memguard.NewBufferFromBytes([]byte(exampleMnemonic))

	w, err := hdwallet.FromMnemonicBuffer(buf)
	if err != nil {
		log.Fatal(err)
	}
	defer w.Destroy()

	addr, _ := w.Address(hdwallet.BTC)
	fmt.Println(addr)
	// Output: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
}

// ExampleHDWallet_WithMnemonic shows the safe pattern for reading the mnemonic
// back: the decrypted copy is wiped automatically when the callback returns, and
// the slice must not escape it.
func ExampleHDWallet_WithMnemonic() {
	w, err := hdwallet.FromMnemonic(exampleMnemonic)
	if err != nil {
		log.Fatal(err)
	}
	defer w.Destroy()

	err = w.WithMnemonic(func(mnemonic []byte) error {
		fmt.Println(len(strings.Fields(string(mnemonic))), "words")
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	// Output: 12 words
}
