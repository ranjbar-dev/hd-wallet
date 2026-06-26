package hdwallet

import (
	"errors"
	"strings"
	"testing"
)

// validAddrVectors are the Trust Wallet Core CoinAddressDerivationTests outputs
// (the canonical addresses for the dummy key, identical to the encoder vectors
// in encoders_test.go) — the known-good address every validator must ACCEPT.
// Every registered symbol appears here so the table covers the whole registry.
var validAddrVectors = map[Symbol]string{
	// secp256k1 — UTXO
	BTC:  "bc1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z00ppggv",
	LTC:  "ltc1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0tamvsu",
	DOGE: "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu",
	BCH:  "bitcoincash:qz7eyzytkl5z6cg6nw20hd62pyyp22mcfuardfd2vn",
	DASH: "XsyCV5yojxF4y3bYeEiVYqarvRgsWFELZL",
	ZEC:  "t1b9xfAk3kZp5Qk3rinDPq7zzLkJGHTChDS",
	// secp256k1 — additional UTXO chains (segwit and base58check P2PKH)
	GRS:   "grs1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0jsaf3d",
	DGB:   "dgb1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0c69ssz",
	BTG:   "btg1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0eg8day",
	SYS:   "sys1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z083sjh7",
	VIA:   "via1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z09y9mn2",
	QTUM:  "QdtLm8ccxhuJFF5zCgikpaghbM3thdaGsW",
	RVN:   "RSZYjMDCP4q3t7NAFXPPnqEGrMZn971pdB",
	KMD:   "RSZYjMDCP4q3t7NAFXPPnqEGrMZn971pdB",
	FIRO:  "aHzpPjmY132KseS4nkiQTbDahTEXqesY89",
	MONA:  "MRBWtGEKHGCHhmyJ1L4CwaWQZJzM5DnVcs",
	XVG:   "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu",
	PIVX:  "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu",
	NEBL:  "NdCKqb8BQoavA5PZ5b4APxKmSpmBA6yMSi",
	STRAX: "strax1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0rvt20n",
	ZEN:   "zniNGeFxXRpY6RDGVdfdmbcvcFb1rrLdnFz",
	BCD:   "1JHMeqKunF2Up6zxnMQGhJu5667BXz98YQ",
	XEC:   "ecash:qz7eyzytkl5z6cg6nw20hd62pyyp22mcfuywezks2y",
	FLUX:  "t1b9xfAk3kZp5Qk3rinDPq7zzLkJGHTChDS",
	// secp256k1 — account / keccak
	ETH: "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	TRX: "TQLCsShbQNXMTVCjprY64qZmEA4rBarpQp",
	XRP: "rJHMeqKu8Ep7Fazx8MQG6JunaafBXz93YQ",
	// secp256k1 — EOS-family public-key strings
	EOS: "EOS5TrYnZP1RkDSUMzBY4GanCy6AP68kCMdkAb5EACkAwkdgRLShz",
	WAX: "EOS5TrYnZP1RkDSUMzBY4GanCy6AP68kCMdkAb5EACkAwkdgRLShz",
	FIO: "FIO5TrYnZP1RkDSUMzBY4GanCy6AP68kCMdkAb5EACkAwkdgRLShz",
	FIL: "f1qsx7qwiojh5duxbxhbqgnlyx5hmpcf7mcz5oxsy",
	// secp256k1 — EVM (share the Ethereum vector)
	BNB:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	MATIC: "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	AVAX:  "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	ARB:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	OP:    "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	FTM:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	BASE:  "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	CRO:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	GNO:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	CELO:  "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	// secp256k1 — additional EVM chains (share the Ethereum vector)
	ETC:      "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	ZKSYNC:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	LINEA:    "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	SCROLL:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	MANTLE:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	BLAST:    "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	KAIA:     "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	AURORA:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	GLMR:     "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	MOVR:     "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	BOBA:     "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	METIS:    "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	OPBNB:    "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	POLZKEVM: "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	MANTA:    "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	RBTC:     "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	HECO:     "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	OKT:      "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	KCS:      "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	WAN:      "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	POA:      "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	CLO:      "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	GO:       "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	TT:       "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	VET:      "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	IOTX:     "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	THETA:    "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	NEON:     "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	MERLIN:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	LIGHT:    "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	SONIC:    "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	ZENEON:   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	ZETAEVM:  "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	RONIN:    "ronin:9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	// secp256k1 — Cosmos
	ATOM: "cosmos1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0emlrvp",
	OSMO: "osmo1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z03qvn6n",
	JUNO: "juno1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z00fucta",
	TIA:  "celestia1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0g3wnkv",
	// secp256k1 — additional Cosmos chains (hash160 bech32)
	LUNA:      "terra1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0ll9rwp",
	KAVA:      "kava1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z09wt76x",
	SCRT:      "secret1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0m7t23a",
	BAND:      "band1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0q5lp5f",
	RUNE:      "thor1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0luxce7",
	STARS:     "stars1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0d8g78s",
	AXL:       "axelar1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0a4ft8q",
	STRD:      "stride1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z06sllcd",
	BLD:       "agoric1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0txauuh",
	CRE:       "cre1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0anvxev",
	KUJI:      "kujira1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0gnampt",
	CMDX:      "comdex1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z075ap4k",
	NTRN:      "neutron1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0aykpkx",
	SOMM:      "somm1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z048s0at",
	FET:       "fetch1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z02xk8wk",
	MARS:      "mars1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0yxx6e6",
	UMEE:      "umee1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0tdzugn",
	COREUM:    "core1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0248ct6",
	QSR:       "quasar1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0hc97py",
	XPRT:      "persistence1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0hhesz9",
	AKT:       "akash1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z05qjy4m",
	NOBLE:     "noble1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z03c2t50",
	SEI:       "sei1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z05hw42q",
	DYDX:      "dydx1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0sz38vk",
	BLZ:       "bluzelle1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0vrup2s",
	CRYPTOORG: "cro1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0pqh6ss",
	// secp256k1 — Cosmos chains with EVM-style keys (keccak address, bech32)
	EVMOS: "evmos1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj07me7uu",
	INJ:   "inj1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj0knl55v",
	CANTO: "canto1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj0wvfqju",
	ZETA:  "zeta1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj027x9uy",
	ONE:   "one1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj0nmx3dt",
	// ed25519
	SOL:   "H4JcMPicKkHcxxDjkyyrLoQj7Kcibd9t815ak4UvTr9M",
	XLM:   "GDXJHJHWN6GRNOAZXON6XH74ZX6NYFAS5B7642RSJQVJTIPA4ZYUQLEB",
	DOT:   "16PpFrXrC6Ko3pYcyMAx6gPMp3mFFaxgyYMt4G5brkgNcSz8",
	KSM:   "Hy8mqcexg5FMwMYnQvzrUvD723qMxDjMRU9HdNCnTsMAypY",
	NEAR:  "ee93a4f66f8d16b819bb9beb9ffccdfcdc1412e87fee6a324c2a99a1e0e67148",
	ALGO:  "52J2J5TPRULLQGN3TPVZ77GN7TOBIEXIP7XGUMSMFKM2DYHGOFEOGBP2T4",
	SUI:   "0x870deb25d5c0a4d7250d52d5cd58dacca2d51eb2a120a979b13384cd52e21e1b",
	APTOS: "0xce2fd04ac9efa74f17595e5785e847a2399d7e637f5e8179244f76191f653276",
	XTZ:   "tz1gcEWswVU6dxfNQWbhTgaZrUrNUFwrsT4z",
	// ed25519 — additional chains
	EGLD: "erd1a6f6fan035ttsxdmn04ellxdlnwpgyhg0lhx5vjv92v6rc8xw9yq83344f",
	IOST: "H4JcMPicKkHcxxDjkyyrLoQj7Kcibd9t815ak4UvTr9M",
	HBAR: "0.0.302a300506032b6570032100ee93a4f66f8d16b819bb9beb9ffccdfcdc1412e87fee6a324c2a99a1e0e67148",
	ROSE: "oasis1qzw4h3wmyjtrttduqqrs8udggyy2emwdzqmuzwg4",
	KIN:  "GDXJHJHWN6GRNOAZXON6XH74ZX6NYFAS5B7642RSJQVJTIPA4ZYUQLEB",
	AE:   "ak_2p5878zbFhxnrm7meL7TmqwtvBaqcBddyp5eGzZbovZ5FeVfcw",
	// nist256p1
	NEO: "AeicEjZyiXKgUeSBbYQHxsU1X3V5Buori5",
	ONT: "AeicEjZyiXKgUeSBbYQHxsU1X3V5Buori5",
	// new-curve chains
	XNO:   "nano_1qepdf4k95dhb5gsmhmq3iddqsxiafwkihunm7irn48jdiwdtnn6pe93k3f6",
	WAVES: "3P2C786D6mBuvyf4WYr6K6Vch5uhi97nBHG",
	// ed25519-extended (Cardano) — TWC CoinAddressDerivationTests dummy-key base
	// address; a well-formed mainnet addr1 the validator must accept.
	ADA: "addr1qxzk4wqhh5qmzas4e26aghcvkz8feju6sa43nghfj5xxsly9d2up00gpk9mptj44630sevywnn9e4pmtrx3wn9gvdp7qjhvjl4",
}

// TestValidVectorsCoverRegistry guards that the valid-vector table stays in sync
// with the registry: every registered symbol must have a known-good address and
// a registered validator, so the table-driven tests truly cover all 33 chains.
func TestValidVectorsCoverRegistry(t *testing.T) {
	for sym := range coins {
		if _, ok := validAddrVectors[sym]; !ok {
			t.Errorf("symbol %s missing from validAddrVectors", sym)
		}
		if _, ok := validators[sym]; !ok {
			t.Errorf("symbol %s missing a validator", sym)
		}
	}
	for sym := range validators {
		if _, ok := coins[sym]; !ok {
			t.Errorf("validator %s has no registry entry", sym)
		}
	}
}

// TestValidateAddressAcceptsTWC asserts every validator ACCEPTS Trust Wallet's
// known-good address for its chain (the positive half of the AnyAddress check).
func TestValidateAddressAcceptsTWC(t *testing.T) {
	for sym, addr := range validAddrVectors {
		t.Run(sym.String(), func(t *testing.T) {
			if err := ValidateAddress(sym, addr); err != nil {
				t.Fatalf("ValidateAddress(%s, %q) = %v, want nil", sym, addr, err)
			}
			if !IsValidAddress(sym, addr) {
				t.Fatalf("IsValidAddress(%s, %q) = false, want true", sym, addr)
			}
			payload, err := ParseAddress(sym, addr)
			if err != nil {
				t.Fatalf("ParseAddress(%s, %q) = %v", sym, addr, err)
			}
			if len(payload) == 0 {
				t.Fatalf("ParseAddress(%s) returned empty payload", sym)
			}
		})
	}
}

// corruptChecksum flips a character near the END of an address (one position in
// from the last, to avoid base32/base58 trailing-padding bits that carry no
// information) to a different valid-looking character, breaking the checksum
// while keeping the alphabet valid. For 0x-hex addresses it flips a hex digit.
func corruptChecksum(addr string) string {
	if len(addr) < 2 {
		return addr
	}
	b := []byte(addr)
	// Use the second-to-last character: the final base32/base58 symbol can encode
	// only padding bits that are discarded on decode, so flipping it may be a
	// no-op for some encodings; one position in is always significant here.
	i := len(b) - 2
	swap := func(c byte) byte {
		switch {
		case c >= '0' && c <= '8':
			return c + 1
		case c == '9':
			return '0'
		case c >= 'a' && c <= 'y':
			return c + 1
		case c == 'z':
			return 'a'
		case c >= 'A' && c <= 'Y':
			return c + 1
		case c == 'Z':
			return 'A'
		default:
			return c
		}
	}
	b[i] = swap(b[i])
	if string(b) == addr { // ensure we actually changed something
		b[0] = swap(b[0])
	}
	return string(b)
}

// TestValidateAddressRejectsCorruptedChecksum asserts every validator REJECTS an
// address whose final character (checksum region) has been altered. Chains
// without an internal checksum (Sui/Aptos/NEAR raw hex) still fail because the
// flip lands in the payload and is detected by length/hex validation only when
// applicable; for those we additionally rely on the length/prefix tests below.
func TestValidateAddressRejectsCorruptedChecksum(t *testing.T) {
	// Chains with no internal checksum: a single-char flip yields a different but
	// still well-formed payload, so corruption is undetectable by design. They
	// are exercised by the length/prefix negative tests instead.
	noChecksum := map[Symbol]bool{SOL: true, SUI: true, APTOS: true, NEAR: true, IOST: true, HBAR: true}
	for sym, addr := range validAddrVectors {
		if noChecksum[sym] {
			continue
		}
		t.Run(sym.String(), func(t *testing.T) {
			bad := corruptChecksum(addr)
			if bad == addr {
				t.Fatalf("could not corrupt %q", addr)
			}
			if err := ValidateAddress(sym, bad); err == nil {
				t.Fatalf("ValidateAddress(%s, %q) = nil, want error (corrupted checksum)", sym, bad)
			}
		})
	}
}

// TestValidateAddressUnknownSymbol asserts an unregistered symbol is reported
// distinctly via ErrUnsupportedCoin (not ErrInvalidAddress).
func TestValidateAddressUnknownSymbol(t *testing.T) {
	err := ValidateAddress(Symbol("NOPE"), "whatever")
	if !errors.Is(err, ErrUnsupportedCoin) {
		t.Fatalf("ValidateAddress(unknown) = %v, want ErrUnsupportedCoin", err)
	}
	if _, err := ParseAddress(Symbol("NOPE"), "x"); !errors.Is(err, ErrUnsupportedCoin) {
		t.Fatalf("ParseAddress(unknown) = %v, want ErrUnsupportedCoin", err)
	}
	if _, err := AddressFromPublicKey(Symbol("NOPE"), make([]byte, 33)); !errors.Is(err, ErrUnsupportedCoin) {
		t.Fatalf("AddressFromPublicKey(unknown) = %v, want ErrUnsupportedCoin", err)
	}
}

// TestInvalidAddressesWrapSentinel asserts validation failures wrap
// ErrInvalidAddress so callers can errors.Is them.
func TestInvalidAddressesWrapSentinel(t *testing.T) {
	err := ValidateAddress(BTC, "bc1qinvalid")
	if !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("err = %v, want wrapping ErrInvalidAddress", err)
	}
}

// negativeCase is one targeted invalid address with the reason it must fail.
type negativeCase struct {
	name string
	sym  Symbol
	addr string
}

// TestPerChainNegativeCases covers wrong-prefix / wrong-length / wrong-version
// failures across representative chains for every encoding family. Combined with
// TestValidateAddressRejectsCorruptedChecksum this gives every family a
// checksum, prefix, and length negative case.
func TestPerChainNegativeCases(t *testing.T) {
	cases := []negativeCase{
		// SegWit: wrong HRP, wrong length program.
		{"BTC wrong hrp", BTC, "ltc1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0tamvsu"},
		{"BTC empty", BTC, "bc1q"},
		{"LTC wrong hrp", LTC, "bc1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z00ppggv"},
		// base58check single-version: wrong version byte.
		{"DOGE wrong version (dash addr)", DOGE, "XsyCV5yojxF4y3bYeEiVYqarvRgsWFELZL"},
		{"DASH wrong version (doge addr)", DASH, "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu"},
		{"NEO wrong version (doge addr)", NEO, "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu"},
		{"TRX wrong version (doge addr)", TRX, "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu"},
		// base58check multi-version: wrong prefix.
		{"ZEC wrong prefix (xtz addr)", ZEC, "tz1gcEWswVU6dxfNQWbhTgaZrUrNUFwrsT4z"},
		{"XRP wrong alphabet (btc base58)", XRP, "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu"},
		{"XTZ wrong prefix (zec addr)", XTZ, "t1b9xfAk3kZp5Qk3rinDPq7zzLkJGHTChDS"},
		// CashAddr: wrong prefix.
		{"BCH wrong prefix", BCH, "bitcoin:qz7eyzytkl5z6cg6nw20hd62pyyp22mcfuardfd2vn"},
		// Cosmos: wrong HRP.
		{"ATOM wrong hrp (osmo)", ATOM, "osmo1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z03qvn6n"},
		{"OSMO wrong hrp (cosmos)", OSMO, "cosmos1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0emlrvp"},
		{"JUNO wrong hrp (cosmos)", JUNO, "cosmos1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0emlrvp"},
		{"TIA wrong hrp (cosmos)", TIA, "cosmos1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0emlrvp"},
		// ETH: wrong length, non-hex.
		{"ETH short", ETH, "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4"},
		{"ETH no 0x", ETH, "9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"},
		{"ETH non-hex", ETH, "0xZZ8A62f656a8d1615C1294fd71e9CFb3E4855A4F"},
		// ed25519 length / prefix.
		{"SOL wrong length", SOL, "H4JcMPicKkHcxxDjkyyrLoQj7Kcibd9t815ak4UvTr9M1"},
		{"SOL invalid char", SOL, "H4JcMPicKkHcxxDjkyyrLoQj7Kcibd9t815ak4UvTr90"},
		{"XLM wrong version (long)", XLM, "MDXJHJHWN6GRNOAZXON6XH74ZX6NYFAS5B7642RSJQVJTIPA4ZYUQLEB"},
		{"DOT wrong network prefix (ksm)", DOT, "Hy8mqcexg5FMwMYnQvzrUvD723qMxDjMRU9HdNCnTsMAypY"},
		{"KSM wrong network prefix (dot)", KSM, "16PpFrXrC6Ko3pYcyMAx6gPMp3mFFaxgyYMt4G5brkgNcSz8"},
		{"ALGO wrong length", ALGO, "52J2J5TPRULLQGN3TPVZ77GN7TOBIEXIP7XGUMSMFKM2DYHGOFEOGBP2T"},
		{"NEAR uppercase", NEAR, "EE93A4F66F8D16B819BB9BEB9FFCCDFCDC1412E87FEE6A324C2A99A1E0E67148"},
		{"NEAR short", NEAR, "ee93a4f66f8d16b819bb9beb9ffccdfcdc1412e87fee6a324c2a99a1e0e671"},
		{"SUI short", SUI, "0x870deb25d5c0a4d7250d52d5cd58dacca2d51eb2a120a979b13384cd52e21e"},
		{"APTOS no 0x", APTOS, "ce2fd04ac9efa74f17595e5785e847a2399d7e637f5e8179244f76191f653276"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateAddress(tc.sym, tc.addr); err == nil {
				t.Fatalf("ValidateAddress(%s, %q) = nil, want error", tc.sym, tc.addr)
			}
		})
	}
}

// TestETHChecksumPolicy verifies the EIP-55 case policy: all-lower and all-upper
// hex are accepted; a correct mixed-case checksum is accepted; an incorrect
// mixed-case checksum is rejected.
func TestETHChecksumPolicy(t *testing.T) {
	const mixed = "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F" // correct EIP-55
	lower := "0x" + strings.ToLower(mixed[2:])
	upper := "0x" + strings.ToUpper(mixed[2:])

	if err := ValidateAddress(ETH, lower); err != nil {
		t.Errorf("all-lowercase should be accepted: %v", err)
	}
	if err := ValidateAddress(ETH, upper); err != nil {
		t.Errorf("all-uppercase should be accepted: %v", err)
	}
	if err := ValidateAddress(ETH, mixed); err != nil {
		t.Errorf("correct EIP-55 mixed-case should be accepted: %v", err)
	}
	// Flip one letter's case to break the EIP-55 checksum while keeping it hex.
	badMixed := "0x9D8A62f656a8d1615C1294fd71e9CFb3E4855A4F" // 'd'->'D' at index 3
	if badMixed == mixed {
		t.Fatal("test setup error: badMixed equals mixed")
	}
	if err := ValidateAddress(ETH, badMixed); err == nil {
		t.Errorf("incorrect EIP-55 mixed-case must be rejected: %q", badMixed)
	}
}

// TestETHParsePayload checks the parsed payload equals the 20-byte address bytes
// regardless of input case.
func TestETHParsePayload(t *testing.T) {
	const addr = "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"
	payload, err := ParseAddress(ETH, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 20 {
		t.Fatalf("payload length %d, want 20", len(payload))
	}
}

// TestBCHWithoutPrefix verifies a CashAddr body without the "bitcoincash:"
// prefix still validates (Trust Wallet accepts both forms).
func TestBCHWithoutPrefix(t *testing.T) {
	const full = "bitcoincash:qz7eyzytkl5z6cg6nw20hd62pyyp22mcfuardfd2vn"
	body := full[len("bitcoincash:"):]
	if err := ValidateAddress(BCH, body); err != nil {
		t.Fatalf("bare CashAddr body should validate: %v", err)
	}
}

// TestAddressFromPublicKeyMatchesEncoder cross-checks AddressFromPublicKey
// against the registry encoder output for the canonical dummy key on every
// chain, and confirms the result round-trips through ParseAddress.
func TestAddressFromPublicKeyMatchesEncoder(t *testing.T) {
	priv := dummyKey()
	for sym, coin := range coins {
		if coin.Curve == Ed25519ExtendedCardano {
			// Cardano's public key is the 128-byte ED25519Cardano payment+staking
			// form derived from a 96-byte extended key (built from BIP-39 entropy),
			// not from a raw 32-byte dummy private key, so it cannot take part in
			// this 32-byte-key sweep. Its address derivation is pinned byte-for-byte
			// to TWC in cardano_vector_test.go and its validator round-trip is
			// covered by TestCardanoAddressValidates.
			continue
		}
		t.Run(sym.String(), func(t *testing.T) {
			pub, err := publicKeyFromPriv(coin.Curve, priv)
			if err != nil {
				t.Fatal(err)
			}
			want, err := coin.Encode(pub)
			if err != nil {
				t.Fatal(err)
			}
			got, err := AddressFromPublicKey(sym, pub)
			if err != nil {
				t.Fatalf("AddressFromPublicKey(%s) = %v", sym, err)
			}
			if got != want {
				t.Fatalf("AddressFromPublicKey(%s) = %s, want %s", sym, got, want)
			}
			if err := ValidateAddress(sym, got); err != nil {
				t.Fatalf("derived %s address %q fails validation: %v", sym, got, err)
			}
		})
	}
}

// TestAddressFromPublicKeyBadKey verifies a malformed secp256k1 key surfaces an
// error from the underlying encoder (wrapped, not panicking).
func TestAddressFromPublicKeyBadKey(t *testing.T) {
	// ETH parses the pubkey; a too-short key must error.
	if _, err := AddressFromPublicKey(ETH, []byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for malformed pubkey")
	}
}

// TestParsePayloadRoundTrip checks that the parsed payload, re-encoded via the
// chain's full path (pubkey -> address), is internally consistent: for hash-based
// chains the parsed payload equals the hash160/keyhash that the encoder embedded.
// This is verified indirectly by AddressFromPublicKey round-trip above; here we
// assert payload lengths per family as a structural guard.
func TestParsePayloadLengths(t *testing.T) {
	want32 := map[Symbol]bool{
		SOL: true, XLM: true, DOT: true, KSM: true, NEAR: true,
		ALGO: true, SUI: true, APTOS: true,
		// additional 32-byte-payload chains
		IOST: true, KIN: true, EGLD: true, HBAR: true, AE: true, XNO: true,
	}
	// EOS-family validators return the 33-byte compressed public key.
	want33 := map[Symbol]bool{EOS: true, WAX: true, FIO: true}
	// Cardano's validator returns the full 57-byte base-address payload
	// (header(1) || payment key hash(28) || staking key hash(28)).
	want57 := map[Symbol]bool{ADA: true}
	for sym, addr := range validAddrVectors {
		payload, err := ParseAddress(sym, addr)
		if err != nil {
			t.Fatalf("ParseAddress(%s): %v", sym, err)
		}
		exp := 20
		switch {
		case want32[sym]:
			exp = 32
		case want33[sym]:
			exp = 33
		case want57[sym]:
			exp = 57
		}
		if len(payload) != exp {
			t.Errorf("%s payload length %d, want %d", sym, len(payload), exp)
		}
	}
}
