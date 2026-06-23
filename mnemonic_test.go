package hdwallet

import (
	"errors"
	"strings"
	"testing"

	bip39 "github.com/tyler-smith/go-bip39"
)

// wordCount returns the number of words in a wallet's mnemonic.
func walletWordCount(t *testing.T, w *HDWallet) int {
	t.Helper()
	var n int
	if err := w.WithMnemonic(func(mn []byte) error {
		n = len(strings.Fields(string(mn)))
		return nil
	}); err != nil {
		t.Fatalf("WithMnemonic: %v", err)
	}
	return n
}

func TestNewHDWalletWithWordCount(t *testing.T) {
	cases := []struct {
		words      int
		entropyLen int // bytes
	}{
		{12, 16}, {15, 20}, {18, 24}, {21, 28}, {24, 32},
	}
	for _, tc := range cases {
		w, err := NewHDWalletWithWordCount(tc.words)
		if err != nil {
			t.Fatalf("%d words: %v", tc.words, err)
		}
		if got := walletWordCount(t, w); got != tc.words {
			t.Errorf("%d words: mnemonic has %d words", tc.words, got)
		}
		if err := w.WithMnemonic(func(mn []byte) error {
			ent, err := bip39.EntropyFromMnemonic(string(mn))
			if err != nil {
				return err
			}
			if len(ent) != tc.entropyLen {
				t.Errorf("%d words: entropy %d bytes, want %d", tc.words, len(ent), tc.entropyLen)
			}
			return nil
		}); err != nil {
			t.Fatalf("%d words entropy: %v", tc.words, err)
		}
		w.Destroy()
	}
}

func TestNewHDWalletDefaultIs12Words(t *testing.T) {
	w, err := NewHDWallet()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	if got := walletWordCount(t, w); got != 12 {
		t.Errorf("NewHDWallet mnemonic has %d words, want 12", got)
	}
}

func TestNewHDWalletWithEntropy(t *testing.T) {
	w, err := NewHDWalletWithEntropy(256)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	if got := walletWordCount(t, w); got != 24 {
		t.Errorf("256-bit entropy gave %d words, want 24", got)
	}
}

func TestInvalidWordCount(t *testing.T) {
	for _, words := range []int{0, 1, 11, 13, 16, 25, 48} {
		if _, err := NewHDWalletWithWordCount(words); !errors.Is(err, ErrInvalidWordCount) {
			t.Errorf("NewHDWalletWithWordCount(%d) err = %v, want ErrInvalidWordCount", words, err)
		}
		if _, err := GenerateMnemonicWithWordCount(words); !errors.Is(err, ErrInvalidWordCount) {
			t.Errorf("GenerateMnemonicWithWordCount(%d) err = %v, want ErrInvalidWordCount", words, err)
		}
	}
}

func TestInvalidEntropyBits(t *testing.T) {
	for _, bits := range []int{0, 64, 127, 129, 255, 257, 512} {
		if _, err := NewHDWalletWithEntropy(bits); !errors.Is(err, ErrInvalidWordCount) {
			t.Errorf("NewHDWalletWithEntropy(%d) err = %v, want ErrInvalidWordCount", bits, err)
		}
	}
}

func TestGenerateMnemonicWithWordCount(t *testing.T) {
	mn, err := GenerateMnemonicWithWordCount(24)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(mn)); got != 24 {
		t.Errorf("got %d words, want 24", got)
	}
	if !bip39.IsMnemonicValid(mn) {
		t.Error("generated mnemonic is not BIP-39 valid")
	}
}
