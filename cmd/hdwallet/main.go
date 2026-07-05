// Command hdwallet is a small demo CLI for the hd-wallet library: it generates
// a fresh BIP-39 mnemonic (or imports one) and prints the receive address for
// every supported network.
//
// WARNING: printing a mnemonic to a terminal defeats in-memory protection. This
// command is for demonstration and local testing only — never paste a real
// mnemonic into a shared machine or capture its output.
package main

import (
	"flag"
	"fmt"
	"log"
	"slices"

	"github.com/awnumar/memguard"

	hdwallet "github.com/ranjbar-dev/hd-wallet"
)

func main() {
	// Terminate safely and wipe all protected memory on interrupt / exit.
	memguard.CatchInterrupt()
	defer memguard.Purge()

	mnemonic := flag.String("mnemonic", "", "import this mnemonic instead of generating one")
	showMnemonic := flag.Bool("show-mnemonic", false, "print the mnemonic (insecure; demo only)")
	flag.Parse()

	w, err := newWallet(*mnemonic)
	if err != nil {
		log.Fatal(err)
	}
	defer w.Destroy()

	if *showMnemonic {
		if err := w.WithMnemonic(func(m []byte) error {
			fmt.Println("Mnemonic (import into Trust Wallet):")
			fmt.Printf("  %s\n\n", m)
			return nil
		}); err != nil {
			log.Fatal(err)
		}
	}

	addrs, err := w.AllAddresses()
	if err != nil {
		log.Fatal(err)
	}

	chains := make([]hdwallet.Chain, 0, len(addrs))
	for s := range addrs {
		chains = append(chains, s)
	}
	slices.Sort(chains)

	fmt.Println("Addresses:")
	for _, s := range chains {
		fmt.Printf("  %-6s %s\n", s, addrs[s])
	}
}

func newWallet(mnemonic string) (*hdwallet.HDWallet, error) {
	if mnemonic != "" {
		return hdwallet.FromMnemonic(mnemonic)
	}
	return hdwallet.NewHDWallet()
}
