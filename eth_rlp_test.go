package hdwallet

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestRLPEncodeYellowPaper checks the canonical Ethereum Yellow Paper / wiki
// examples.
func TestRLPEncodeYellowPaper(t *testing.T) {
	tests := []struct {
		name string
		item RLPItem
		want string // hex
	}{
		{"empty string", RLPString(nil), "80"},
		{"empty string explicit", RLPString([]byte{}), "80"},
		{"single byte 0x00", RLPString([]byte{0x00}), "00"},
		{"single byte 0x0f", RLPString([]byte{0x0f}), "0f"},
		{"single byte 0x7f", RLPString([]byte{0x7f}), "7f"},
		{"single byte 0x80", RLPString([]byte{0x80}), "8180"},
		{"the string dog", RLPString([]byte("dog")), "83646f67"},
		{"empty list", RLPList(), "c0"},
		{
			"cat and dog list",
			RLPList(RLPString([]byte("cat")), RLPString([]byte("dog"))),
			"c88363617483646f67",
		},
		{
			"set theoretical [ [], [[]], [ [], [[]] ] ]",
			RLPList(
				RLPList(),
				RLPList(RLPList()),
				RLPList(RLPList(), RLPList(RLPList())),
			),
			"c7c0c1c0c3c0c1c0",
		},
		{
			// The 56-char "Lorem ipsum dolor sit amet, consectetur adipisicing elit"
			// crosses into the long-string form (0xb8, length 0x38).
			"long string",
			RLPString([]byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit")),
			"b8384c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e7365637465747572206164697069736963696e6720656c6974",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EncodeRLP(tc.item)
			if hex.EncodeToString(got) != tc.want {
				t.Errorf("EncodeRLP = %x, want %s", got, tc.want)
			}
		})
	}
}

// TestRLPRoundTrip ensures decode(encode(x)) == x for representative items.
func TestRLPRoundTrip(t *testing.T) {
	items := []RLPItem{
		RLPString(nil),
		RLPString([]byte{0x00}),
		RLPString([]byte("dog")),
		RLPString(bytes.Repeat([]byte{0xab}, 200)), // long string
		RLPList(RLPString([]byte("cat")), RLPString([]byte("dog"))),
		RLPList(
			RLPString([]byte("nonce")),
			RLPList(RLPString([]byte("a")), RLPString([]byte("b"))),
			RLPString(bytes.Repeat([]byte{0x11}, 70)), // forces long list
		),
	}
	for i, item := range items {
		enc := EncodeRLP(item)
		dec, err := DecodeRLP(enc)
		if err != nil {
			t.Fatalf("item %d: DecodeRLP: %v", i, err)
		}
		if hex.EncodeToString(EncodeRLP(dec)) != hex.EncodeToString(enc) {
			t.Errorf("item %d: round-trip mismatch", i)
		}
	}
}

func TestRLPDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"trailing bytes", "80ff"},
		{"truncated short string", "83646f"},
		{"non-canonical single byte wrapped", "8100"},  // 0x00 should be bare
		{"non-canonical long-string length", "b80100"}, // length 1 in long form
		{"leading zero length", "b900ff"},              // length with leading zero
		{"truncated list", "c483646f"},                 // declares 4 bytes, has 3
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeRLP(mustHex(t, tc.in)); err == nil {
				t.Errorf("DecodeRLP(%s) = nil error, want error", tc.in)
			}
		})
	}
}

// TestRLPDecodeShortStringCanonical confirms a valid wrapped short string decodes.
func TestRLPDecodeShortStringCanonical(t *testing.T) {
	item, err := DecodeRLP(mustHex(t, "8180")) // string {0x80}
	if err != nil {
		t.Fatal(err)
	}
	if item.IsList || !bytes.Equal(item.Str, []byte{0x80}) {
		t.Errorf("decoded %+v, want Str=[0x80]", item)
	}
}
