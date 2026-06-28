package hdwallet

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	bip39 "github.com/tyler-smith/go-bip39"
)

// canonical12 is the BIP-39 all-abandon test vector (holds no funds).
const canonical12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// abandon11 is the first 11 words of canonical12, used as a known 128-bit prefix.
var abandon11 = strings.Fields(strings.TrimSuffix(canonical12, " about"))

func TestWordlistPrefix(t *testing.T) {
	cases := []struct {
		name      string
		prefix    string
		wantFirst string // first result must equal this (skip check if "")
		allStart  string // every result must start with this (skip if "")
		wantLen   int    // exact length assertion; -1 means skip
		wantMax   int    // result length must be ≤ wantMax; 0 means skip
	}{
		{
			name:      "prefix ab",
			prefix:    "ab",
			wantFirst: "abandon",
			allStart:  "ab",
			wantLen:   -1,
			wantMax:   wordlistMaxResults,
		},
		{
			name:      "empty prefix returns first N words",
			prefix:    "",
			wantFirst: "", // don't assert specific first word
			wantLen:   wordlistMaxResults,
			wantMax:   wordlistMaxResults,
		},
		{
			name:      "full word returns exactly itself",
			prefix:    "abandon",
			wantFirst: "abandon",
			allStart:  "abandon",
			wantLen:   1,
		},
		{
			name:    "no matches returns nil slice",
			prefix:  "zzzzz",
			wantLen: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := WordlistPrefix(tc.prefix)

			if tc.wantLen >= 0 && len(got) != tc.wantLen {
				t.Errorf("WordlistPrefix(%q): len=%d, want %d", tc.prefix, len(got), tc.wantLen)
			}
			if tc.wantMax > 0 && len(got) > tc.wantMax {
				t.Errorf("WordlistPrefix(%q): len=%d exceeds cap %d", tc.prefix, len(got), tc.wantMax)
			}
			if tc.wantFirst != "" && (len(got) == 0 || got[0] != tc.wantFirst) {
				first := ""
				if len(got) > 0 {
					first = got[0]
				}
				t.Errorf("WordlistPrefix(%q): first=%q, want %q", tc.prefix, first, tc.wantFirst)
			}
			for _, w := range got {
				if tc.allStart != "" && !strings.HasPrefix(w, tc.allStart) {
					t.Errorf("WordlistPrefix(%q): result %q does not start with %q", tc.prefix, w, tc.allStart)
				}
				if !IsValidWord(w) {
					t.Errorf("WordlistPrefix(%q): result %q is not a BIP-39 word", tc.prefix, w)
				}
			}
		})
	}
}

func TestIsValidWord(t *testing.T) {
	cases := []struct {
		word string
		want bool
	}{
		{"abandon", true},
		{"about", true},
		{"zoo", true},   // last word in the BIP-39 English list
		{"zoom", false}, // not in the list
		{"notaword", false},
		{"", false},
		{"ABANDON", false}, // wordlist is lower-case; case must match exactly
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("word=%q", tc.word), func(t *testing.T) {
			if got := IsValidWord(tc.word); got != tc.want {
				t.Errorf("IsValidWord(%q) = %v, want %v", tc.word, got, tc.want)
			}
		})
	}
}

// TestSuggestFinalWords_12word is the core correctness check:
// for any 11-word prefix of a 128-bit mnemonic, exactly 128 words produce a
// valid BIP-39 checksum (the last word encodes 7 free entropy bits + 4 checksum
// bits, giving 2^7 = 128 choices).
func TestSuggestFinalWords_12word(t *testing.T) {
	got, err := SuggestFinalWords(abandon11)
	if err != nil {
		t.Fatalf("SuggestFinalWords: %v", err)
	}

	const wantCount = 128
	if len(got) != wantCount {
		t.Errorf("got %d completions, want %d", len(got), wantCount)
	}

	// Every returned word must produce a valid BIP-39 mnemonic.
	prefix := strings.Join(abandon11, " ") + " "
	for _, w := range got {
		if !bip39.IsMnemonicValid(prefix + w) {
			t.Errorf("completion %q does not yield a valid BIP-39 mnemonic", w)
		}
	}

	// The canonical final word "about" must appear in the list.
	found := false
	for _, w := range got {
		if w == "about" {
			found = true
			break
		}
	}
	if !found {
		t.Error("canonical final word \"about\" not found in suggestions")
	}
}

// TestSuggestFinalWords_24word verifies the 23-word / 256-bit case:
// exactly 8 valid completions (2^3 free entropy bits).
func TestSuggestFinalWords_24word(t *testing.T) {
	prefix23 := make([]string, 23)
	for i := range prefix23 {
		prefix23[i] = "abandon"
	}
	got, err := SuggestFinalWords(prefix23)
	if err != nil {
		t.Fatalf("SuggestFinalWords(23 words): %v", err)
	}

	const wantCount = 8
	if len(got) != wantCount {
		t.Errorf("got %d completions, want %d", len(got), wantCount)
	}
	prefix := strings.Join(prefix23, " ") + " "
	for _, w := range got {
		if !bip39.IsMnemonicValid(prefix + w) {
			t.Errorf("completion %q does not yield a valid BIP-39 mnemonic", w)
		}
	}
}

// TestSuggestFinalWords_allPrefixLengths verifies that all valid prefix lengths
// (11, 14, 17, 20, 23) are accepted and return exactly the documented number of
// valid completions.  The counts follow from BIP-39 checksum arithmetic:
//
//	12-word (11 prefix) → 2^7 = 128
//	15-word (14 prefix) → 2^6 =  64
//	18-word (17 prefix) → 2^5 =  32
//	21-word (20 prefix) → 2^4 =  16
//	24-word (23 prefix) → 2^3 =   8
func TestSuggestFinalWords_allPrefixLengths(t *testing.T) {
	wantCounts := map[int]int{
		11: 128,
		14: 64,
		17: 32,
		20: 16,
		23: 8,
	}
	for _, prefixLen := range []int{11, 14, 17, 20, 23} {
		prefixLen := prefixLen
		t.Run(fmt.Sprintf("prefix%d", prefixLen), func(t *testing.T) {
			words := make([]string, prefixLen)
			for i := range words {
				words[i] = "abandon"
			}
			got, err := SuggestFinalWords(words)
			if err != nil {
				t.Fatalf("SuggestFinalWords(%d words): %v", prefixLen, err)
			}
			want := wantCounts[prefixLen]
			if len(got) != want {
				t.Errorf("SuggestFinalWords(%d words): got %d completions, want %d", prefixLen, len(got), want)
			}
			// All completions must be valid BIP-39 words.
			for _, w := range got {
				if !IsValidWord(w) {
					t.Errorf("completion %q is not a BIP-39 word", w)
				}
			}
		})
	}
}

func TestSuggestFinalWords_errors(t *testing.T) {
	// Build an 11-word slice where the last entry is invalid.
	tenAbandons := make([]string, 10)
	for i := range tenAbandons {
		tenAbandons[i] = "abandon"
	}
	invalidPrefix := append(tenAbandons, "notaword") //nolint:gocritic // intentional copy

	cases := []struct {
		name      string
		words     []string
		errSubstr string
	}{
		{
			name:      "zero words",
			words:     []string{},
			errSubstr: "11, 14, 17, 20, or 23",
		},
		{
			name:      "too many words (12 instead of 11)",
			words:     strings.Fields(canonical12),
			errSubstr: "11, 14, 17, 20, or 23",
		},
		{
			name:      "invalid word in prefix",
			words:     invalidPrefix,
			errSubstr: "not in the BIP-39 wordlist",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SuggestFinalWords(tc.words)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}

func TestMnemonicStrength(t *testing.T) {
	mn24, err := GenerateMnemonicWithWordCount(24)
	if err != nil {
		t.Fatalf("GenerateMnemonicWithWordCount(24): %v", err)
	}
	mn15, err := GenerateMnemonicWithWordCount(15)
	if err != nil {
		t.Fatalf("GenerateMnemonicWithWordCount(15): %v", err)
	}
	mn18, err := GenerateMnemonicWithWordCount(18)
	if err != nil {
		t.Fatalf("GenerateMnemonicWithWordCount(18): %v", err)
	}
	mn21, err := GenerateMnemonicWithWordCount(21)
	if err != nil {
		t.Fatalf("GenerateMnemonicWithWordCount(21): %v", err)
	}

	cases := []struct {
		name      string
		mnemonic  string
		wantBits  int
		wantWords int
		wantErr   error
	}{
		{
			name:      "canonical 12-word",
			mnemonic:  canonical12,
			wantBits:  128,
			wantWords: 12,
		},
		{
			name:      "canonical 12-word with surrounding whitespace",
			mnemonic:  "  " + canonical12 + "\n",
			wantBits:  128,
			wantWords: 12,
		},
		{
			name:      "fresh 15-word",
			mnemonic:  mn15,
			wantBits:  160,
			wantWords: 15,
		},
		{
			name:      "fresh 18-word",
			mnemonic:  mn18,
			wantBits:  192,
			wantWords: 18,
		},
		{
			name:      "fresh 21-word",
			mnemonic:  mn21,
			wantBits:  224,
			wantWords: 21,
		},
		{
			name:      "fresh 24-word",
			mnemonic:  mn24,
			wantBits:  256,
			wantWords: 24,
		},
		{
			name:     "invalid phrase",
			mnemonic: "this is not a mnemonic at all",
			wantErr:  ErrInvalidMnemonic,
		},
		{
			name:     "empty string",
			mnemonic: "",
			wantErr:  ErrInvalidMnemonic,
		},
		{
			name:     "bad checksum — 12 identical words",
			mnemonic: strings.Repeat("abandon ", 11) + "abandon",
			wantErr:  ErrInvalidMnemonic,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bits, words, err := MnemonicStrength(tc.mnemonic)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("MnemonicStrength: err=%v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MnemonicStrength: unexpected error: %v", err)
			}
			if bits != tc.wantBits {
				t.Errorf("bits=%d, want %d", bits, tc.wantBits)
			}
			if words != tc.wantWords {
				t.Errorf("words=%d, want %d", words, tc.wantWords)
			}
		})
	}
}
