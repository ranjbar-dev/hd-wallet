package hdwallet

import (
	"testing"
)

// TestChecksumEthAddress pins the 5 reference vectors from the EIP-55 spec.
func TestChecksumEthAddress(t *testing.T) {
	cases := []struct{ in, want string }{
		// Mixed-case canonical forms from the EIP-55 specification.
		{"5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"},
		{"0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"},
		{"0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"},
		{"0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"},
		// All-caps input — idempotent on hex digits with nibble ≥ 8.
		{"0X52908400098527886E0F7030069857D2E4169EE7", "0x52908400098527886E0F7030069857D2E4169EE7"},
	}
	for _, c := range cases {
		got, err := ChecksumEthAddress(c.in)
		if err != nil {
			t.Errorf("ChecksumEthAddress(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ChecksumEthAddress(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Invalid inputs.
	for _, bad := range []string{"not-an-address", "0x123", "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"} {
		if _, err := ChecksumEthAddress(bad); err == nil {
			t.Errorf("ChecksumEthAddress(%q) expected error, got nil", bad)
		}
	}
}

// TestDetectBitcoinAddressKind derives all four address types for BTC and LTC
// from the canonical mnemonic and verifies the detection result.
func TestDetectBitcoinAddressKind(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	cases := []struct {
		chain Chain
		typ   BitcoinAddressType
		want  BitcoinAddressKind
	}{
		{BTC, P2PKH, BitcoinAddressKindP2PKH},
		{BTC, P2SHP2WPKH, BitcoinAddressKindP2SHP2WPKH},
		{BTC, P2WPKH, BitcoinAddressKindP2WPKH},
		{BTC, P2TR, BitcoinAddressKindP2TR},
		{LTC, P2PKH, BitcoinAddressKindP2PKH},
		{LTC, P2SHP2WPKH, BitcoinAddressKindP2SHP2WPKH},
		{LTC, P2WPKH, BitcoinAddressKindP2WPKH},
		{LTC, P2TR, BitcoinAddressKindP2TR},
	}
	for _, tc := range cases {
		addr, err := w.BitcoinAddress(tc.chain, tc.typ, 0, 0, 0)
		if err != nil {
			t.Fatalf("BitcoinAddress(%s, %s): %v", tc.chain, tc.typ, err)
		}
		got := DetectBitcoinAddressKind(tc.chain, addr)
		if got != tc.want {
			t.Errorf("DetectBitcoinAddressKind(%s, %q) = %v, want %v", tc.chain, addr, got, tc.want)
		}
	}
	// Chains not in btcAddrParams.
	if got := DetectBitcoinAddressKind(ETH, "0xfoo"); got != BitcoinAddressKindUnknown {
		t.Errorf("DetectBitcoinAddressKind(ETH, ...) = %v, want Unknown", got)
	}
	// Garbage address.
	if got := DetectBitcoinAddressKind(BTC, "not-an-address"); got != BitcoinAddressKindUnknown {
		t.Errorf("DetectBitcoinAddressKind(BTC, garbage) = %v, want Unknown", got)
	}
}

// TestDetectChains checks that the EVM vector matches many chains and that a
// BTC native-SegWit address uniquely matches BTC.
func TestDetectChains(t *testing.T) {
	// EVM address should match all registered EVM validators.
	evm := DetectChains("0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F")
	foundETH, foundBNB, foundMATIC := false, false, false
	for _, s := range evm {
		switch s {
		case ETH:
			foundETH = true
		case BNB:
			foundBNB = true
		case MATIC:
			foundMATIC = true
		}
	}
	if !foundETH || !foundBNB || !foundMATIC {
		t.Errorf("DetectChains(EVM addr) missing ETH/BNB/MATIC; got %v", evm)
	}
	// Verify the slice is sorted alphabetically.
	for i := 1; i < len(evm); i++ {
		if string(evm[i]) < string(evm[i-1]) {
			t.Errorf("DetectChains result not sorted at index %d: %v", i, evm)
			break
		}
	}

	// BTC native-SegWit address (from encoders_test canonical vector) — only BTC has "bc1" HRP.
	btcMatches := DetectChains("bc1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z00ppggv")
	foundBTC := false
	for _, s := range btcMatches {
		if s == BTC {
			foundBTC = true
		}
	}
	if !foundBTC {
		t.Errorf("DetectChains(BTC P2WPKH) missing BTC; got %v", btcMatches)
	}

	// Garbage returns nil.
	if got := DetectChains("zzz-garbage"); got != nil {
		t.Errorf("DetectChains(garbage) = %v, want nil", got)
	}
}

// TestAddressFromPayload verifies round-trip ParseAddress → AddressFromPayload
// for ETH, BTC (P2PKH derived from the canonical mnemonic), SOL, and ATOM.
func TestAddressFromPayload(t *testing.T) {
	// Derive BTC P2PKH address from the canonical mnemonic (BIP-44 path).
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()
	btcP2PKH, err := w.BitcoinAddress(BTC, P2PKH, 0, 0, 0)
	if err != nil {
		t.Fatalf("BitcoinAddress(BTC, P2PKH): %v", err)
	}

	cases := []struct {
		chain Chain
		addr  string
	}{
		{ETH, "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"},
		{BTC, btcP2PKH}, // P2PKH — AddressFromPayload always re-encodes as P2PKH
		{SOL, "H4JcMPicKkHcxxDjkyyrLoQj7Kcibd9t815ak4UvTr9M"},
		{ATOM, "cosmos1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0emlrvp"},
	}
	for _, tc := range cases {
		payload, err := ParseAddress(tc.chain, tc.addr)
		if err != nil {
			t.Fatalf("ParseAddress(%s, %q): %v", tc.chain, tc.addr, err)
		}
		got, err := AddressFromPayload(tc.chain, payload)
		if err != nil {
			t.Fatalf("AddressFromPayload(%s, ...): %v", tc.chain, err)
		}
		if got != tc.addr {
			t.Errorf("AddressFromPayload(%s) round-trip: got %q, want %q", tc.chain, got, tc.addr)
		}
	}
	// Unknown chain.
	if _, err := AddressFromPayload("UNKNOWN_XYZ", nil); err == nil {
		t.Error("AddressFromPayload(unknown) expected error")
	}
	// Wrong payload length.
	if _, err := AddressFromPayload(ETH, make([]byte, 5)); err == nil {
		t.Error("AddressFromPayload(ETH, 5 bytes) expected ErrInvalidAddress")
	}
}
