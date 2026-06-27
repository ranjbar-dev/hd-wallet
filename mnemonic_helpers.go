package hdwallet

// mnemonic_helpers.go — pure-function BIP-39 UI helpers.
//
// These helpers are intended for wallet entry screens: autocomplete, word
// validation, final-word recovery, and entropy-strength display.  They are
// stateless, touch no secrets, and perform no network or file I/O.
//
// SECURITY NOTE: these functions accept and return plain strings/slices.
// They are designed for the UI entry phase — before the wallet object is
// created.  Once [FromMnemonicBuffer] or [FromMnemonicBytes] has been called
// and the wallet is the live secret, do not pass it back through these
// helpers; use the wallet's own secure methods instead.

import (
	"fmt"
	"strings"

	bip39 "github.com/tyler-smith/go-bip39"
)

// wordlistMaxResults is the maximum number of words [WordlistPrefix] returns.
// Eight entries is sufficient for most mobile / desktop autocomplete widgets.
const wordlistMaxResults = 8

// WordlistPrefix returns up to [wordlistMaxResults] BIP-39 English words that
// begin with prefix, in alphabetical (wordlist) order.  It is designed for
// wallet-entry autocomplete: call it on every keystroke and display the results
// as suggestions.
//
// An empty prefix returns the first [wordlistMaxResults] words of the wordlist.
// A prefix with no matches returns a nil slice.
func WordlistPrefix(prefix string) []string {
	var out []string
	for _, w := range bip39.GetWordList() {
		if strings.HasPrefix(w, prefix) {
			out = append(out, w)
			if len(out) == wordlistMaxResults {
				break
			}
		}
	}
	return out
}

// IsValidWord reports whether word is present in the BIP-39 English wordlist.
func IsValidWord(word string) bool {
	_, ok := bip39.GetWordIndex(word)
	return ok
}

// SuggestFinalWords takes a slice of 11, 14, 17, 20, or 23 valid BIP-39 words
// (the first N–1 words of a mnemonic) and returns every word from the English
// wordlist that, when appended, yields a valid BIP-39 checksum.  Results are
// in wordlist (alphabetical) order.
//
// Expected result counts per prefix length:
//
//	11 words → 12-word / 128-bit mnemonic → 128 valid completions
//	14 words → 15-word / 160-bit mnemonic →  64 valid completions
//	17 words → 18-word / 192-bit mnemonic →  32 valid completions
//	20 words → 21-word / 224-bit mnemonic →  16 valid completions
//	23 words → 24-word / 256-bit mnemonic →   8 valid completions
//
// The function returns an error if the prefix length is not one of the values
// above, or if any word in words is not in the BIP-39 English wordlist.
func SuggestFinalWords(words []string) ([]string, error) {
	switch len(words) {
	case 11, 14, 17, 20, 23:
		// valid prefix lengths for 12/15/18/21/24-word mnemonics
	default:
		return nil, fmt.Errorf("hdwallet: SuggestFinalWords: prefix must be 11, 14, 17, 20, or 23 words (got %d)", len(words))
	}
	for i, w := range words {
		if !IsValidWord(w) {
			return nil, fmt.Errorf("hdwallet: SuggestFinalWords: word %d %q is not in the BIP-39 wordlist", i+1, w)
		}
	}
	prefix := strings.Join(words, " ") + " "
	out := make([]string, 0, 128)
	for _, candidate := range bip39.GetWordList() {
		if bip39.IsMnemonicValid(prefix + candidate) {
			out = append(out, candidate)
		}
	}
	return out, nil
}

// MnemonicStrength validates mnemonic and returns its entropy size in bits and
// word count.  It is intended for a "strength indicator" on a wallet-import
// screen, e.g. "128 bits · 12 words".  Surrounding whitespace is trimmed
// before validation, exactly as the wallet constructors do.
//
// Returns [ErrInvalidMnemonic] for an invalid phrase (wrong word count, unknown
// words, or bad checksum).
func MnemonicStrength(mnemonic string) (bits int, words int, err error) {
	trimmed := strings.TrimSpace(mnemonic)
	if !bip39.IsMnemonicValid(trimmed) {
		return 0, 0, ErrInvalidMnemonic
	}
	words = len(strings.Fields(trimmed))
	bits = words / 3 * 32
	return bits, words, nil
}
