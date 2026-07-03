package hdwallet

import (
	"errors"
	"strings"
	"testing"
)

const gap14Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// TestSignNil verifies that Sign and SignIndex return ErrInvalidDigest (not panic)
// when called with nil data.
func TestSignNil(t *testing.T) {
	w, err := FromMnemonic(gap14Mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	_, err = w.Sign(ETH, nil)
	if !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("Sign(ETH, nil): want ErrInvalidDigest, got %v", err)
	}

	_, err = w.Sign(SOL, nil)
	if !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("Sign(SOL, nil): want ErrInvalidDigest, got %v", err)
	}

	_, err = w.SignIndex(BTC, 0, nil)
	if !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("SignIndex(BTC, 0, nil): want ErrInvalidDigest, got %v", err)
	}
}

// TestParseBounds verifies that short/corrupt payloads return ErrInvalidAddress
// rather than causing index-out-of-range panics.
func TestParseBounds(t *testing.T) {
	cases := []struct {
		sym  Symbol
		addr string
	}{
		{ETH, "0x000000000000000000000000000000000000000"}, // 41 chars, 1 short
		{SOL, "1"},           // way too short for base58->32 bytes
		{ATOM, "cosmos1abc"}, // too short payload
	}
	for _, c := range cases {
		_, err := ParseAddress(c.sym, c.addr)
		if !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("ParseAddress(%s, %q): want ErrInvalidAddress, got %v", c.sym, c.addr, err)
		}
	}
}

// TestGenerateMnemonicBuffer verifies the secure mnemonic generator.
func TestGenerateMnemonicBuffer(t *testing.T) {
	buf, err := GenerateMnemonicBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if buf == nil || !buf.IsAlive() {
		t.Fatal("expected live LockedBuffer")
	}
	mn := string(buf.Bytes())
	buf.Destroy()

	if err := ValidateMnemonic(mn); err != nil {
		t.Fatalf("GenerateMnemonicBuffer produced invalid mnemonic: %v", err)
	}
}

// TestGenerateMnemonicBufferWordCount verifies the multi-length variant.
func TestGenerateMnemonicBufferWordCount(t *testing.T) {
	for _, words := range []int{12, 15, 18, 21, 24} {
		buf, err := GenerateMnemonicBufferWithWordCount(words)
		if err != nil {
			t.Fatalf("words=%d: %v", words, err)
		}
		mn := string(buf.Bytes())
		buf.Destroy()
		if len(strings.Fields(mn)) != words {
			t.Errorf("words=%d: got %d words", words, len(strings.Fields(mn)))
		}
	}
	_, err := GenerateMnemonicBufferWithWordCount(11)
	if !errors.Is(err, ErrInvalidWordCount) {
		t.Fatalf("words=11: want ErrInvalidWordCount, got %v", err)
	}
}
