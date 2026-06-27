package hdwallet

import (
	"bytes"
	"testing"
)

// dummyKey is the fixed private key used by Trust Wallet Core's
// CoinAddressDerivationTests (0x4646...46, 32 bytes). Deriving the public key
// per curve and encoding it must reproduce Trust Wallet's exact addresses,
// which proves the encoders and per-curve public-key logic are correct,
// independently of HD path derivation.
func dummyKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0x46
	}
	return k
}

// trustWalletVectors are the exact expected addresses from Trust Wallet Core's
// CoinAddressDerivationTests for the dummy key above.
var trustWalletVectors = map[string]string{
	// secp256k1
	"BTC":  "bc1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z00ppggv",
	"LTC":  "ltc1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0tamvsu",
	"DOGE": "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu",
	"BCH":  "bitcoincash:qz7eyzytkl5z6cg6nw20hd62pyyp22mcfuardfd2vn",
	"DASH": "XsyCV5yojxF4y3bYeEiVYqarvRgsWFELZL",
	"ZEC":  "t1b9xfAk3kZp5Qk3rinDPq7zzLkJGHTChDS",
	// secp256k1 — additional UTXO chains (segwit and base58check P2PKH).
	"GRS":   "grs1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0jsaf3d",
	"DGB":   "dgb1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0c69ssz",
	"BTG":   "btg1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0eg8day",
	"SYS":   "sys1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z083sjh7",
	"VIA":   "via1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z09y9mn2",
	"QTUM":  "QdtLm8ccxhuJFF5zCgikpaghbM3thdaGsW",
	"RVN":   "RSZYjMDCP4q3t7NAFXPPnqEGrMZn971pdB",
	"KMD":   "RSZYjMDCP4q3t7NAFXPPnqEGrMZn971pdB",
	"FIRO":  "aHzpPjmY132KseS4nkiQTbDahTEXqesY89",
	"MONA":  "MRBWtGEKHGCHhmyJ1L4CwaWQZJzM5DnVcs",
	"XVG":   "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu",
	"PIVX":  "DNRTC6GZ5evmM7BZWwPqF54fyDqUqULMyu",
	"NEBL":  "NdCKqb8BQoavA5PZ5b4APxKmSpmBA6yMSi",
	"STRAX": "strax1qhkfq3zahaqkkzx5mjnamwjsfpq2jk7z0rvt20n",
	"ZEN":   "zniNGeFxXRpY6RDGVdfdmbcvcFb1rrLdnFz",
	"BCD":   "1JHMeqKunF2Up6zxnMQGhJu5667BXz98YQ",
	"XEC":   "ecash:qz7eyzytkl5z6cg6nw20hd62pyyp22mcfuywezks2y",
	"FLUX":  "t1b9xfAk3kZp5Qk3rinDPq7zzLkJGHTChDS",
	"ETH":   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	"TRX":   "TQLCsShbQNXMTVCjprY64qZmEA4rBarpQp",
	"XRP":   "rJHMeqKu8Ep7Fazx8MQG6JunaafBXz93YQ",
	"EOS":   "EOS5TrYnZP1RkDSUMzBY4GanCy6AP68kCMdkAb5EACkAwkdgRLShz",
	"WAX":   "EOS5TrYnZP1RkDSUMzBY4GanCy6AP68kCMdkAb5EACkAwkdgRLShz",
	"FIO":   "FIO5TrYnZP1RkDSUMzBY4GanCy6AP68kCMdkAb5EACkAwkdgRLShz",
	"FIL":   "f1qsx7qwiojh5duxbxhbqgnlyx5hmpcf7mcz5oxsy",
	// secp256k1 EVM — Ronin uses the "ronin:" prefix instead of "0x".
	"RONIN": "ronin:9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F",
	// ICON: same keccak20 as ETH but lowercase with "hx" prefix (no EIP-55 checksum).
	// TWC CoinAddressDerivationTests: ICON address for dummyKey().
	"ICX": "hx9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f",
	// Nervos CKB: bech32m full address (RFC 0021); code_hash=secp256k1-sighash-all,
	// hash_type=0x01 (type), args=blake2b-160(compressed pubkey).
	// TWC CoinAddressDerivationTests: CKB address for dummyKey().
	"CKB": "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqfzayeck2k4hlcqu40lwpzv0nqqkqs5lncej05rm",
	// Zilliqa: bech32("zil", sha256(compressed_pub)[12:]).
	// TWC CoinAddressDerivationTests: ZIL address for dummyKey().
	"ZIL":  "zil1j2cvtd7j9n7fnxfv2r3neucjw8tp4xz9sp07v4",
	"ATOM": "cosmos1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0emlrvp",
	"OSMO": "osmo1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z03qvn6n",
	// secp256k1 — additional Cosmos chains (hash160 bech32).
	"LUNA":      "terra1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0ll9rwp",
	"KAVA":      "kava1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z09wt76x",
	"SCRT":      "secret1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0m7t23a",
	"BAND":      "band1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0q5lp5f",
	"RUNE":      "thor1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0luxce7",
	"STARS":     "stars1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0d8g78s",
	"AXL":       "axelar1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0a4ft8q",
	"STRD":      "stride1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z06sllcd",
	"BLD":       "agoric1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0txauuh",
	"CRE":       "cre1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0anvxev",
	"KUJI":      "kujira1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0gnampt",
	"CMDX":      "comdex1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z075ap4k",
	"NTRN":      "neutron1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0aykpkx",
	"SOMM":      "somm1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z048s0at",
	"FET":       "fetch1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z02xk8wk",
	"MARS":      "mars1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0yxx6e6",
	"UMEE":      "umee1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0tdzugn",
	"COREUM":    "core1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0248ct6",
	"QSR":       "quasar1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0hc97py",
	"XPRT":      "persistence1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0hhesz9",
	"AKT":       "akash1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z05qjy4m",
	"NOBLE":     "noble1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z03c2t50",
	"SEI":       "sei1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z05hw42q",
	"DYDX":      "dydx1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0sz38vk",
	"BLZ":       "bluzelle1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0vrup2s",
	"CRYPTOORG": "cro1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0pqh6ss",
	// secp256k1 — Cosmos chains with EVM-style keys (keccak address, bech32).
	"EVMOS": "evmos1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj07me7uu",
	"INJ":   "inj1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj0knl55v",
	"CANTO": "canto1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj0wvfqju",
	"ZETA":  "zeta1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj027x9uy",
	"ONE":   "one1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj0nmx3dt",
	// ed25519
	"SOL":   "H4JcMPicKkHcxxDjkyyrLoQj7Kcibd9t815ak4UvTr9M",
	"XLM":   "GDXJHJHWN6GRNOAZXON6XH74ZX6NYFAS5B7642RSJQVJTIPA4ZYUQLEB",
	"DOT":   "16PpFrXrC6Ko3pYcyMAx6gPMp3mFFaxgyYMt4G5brkgNcSz8",
	"KSM":   "Hy8mqcexg5FMwMYnQvzrUvD723qMxDjMRU9HdNCnTsMAypY",
	"NEAR":  "ee93a4f66f8d16b819bb9beb9ffccdfcdc1412e87fee6a324c2a99a1e0e67148",
	"ALGO":  "52J2J5TPRULLQGN3TPVZ77GN7TOBIEXIP7XGUMSMFKM2DYHGOFEOGBP2T4",
	"SUI":   "0x870deb25d5c0a4d7250d52d5cd58dacca2d51eb2a120a979b13384cd52e21e1b",
	"APTOS": "0xce2fd04ac9efa74f17595e5785e847a2399d7e637f5e8179244f76191f653276",
	"XTZ":   "tz1gcEWswVU6dxfNQWbhTgaZrUrNUFwrsT4z",
	// ed25519 — additional chains
	"EGLD": "erd1a6f6fan035ttsxdmn04ellxdlnwpgyhg0lhx5vjv92v6rc8xw9yq83344f",
	"IOST": "H4JcMPicKkHcxxDjkyyrLoQj7Kcibd9t815ak4UvTr9M",
	"HBAR": "0.0.302a300506032b6570032100ee93a4f66f8d16b819bb9beb9ffccdfcdc1412e87fee6a324c2a99a1e0e67148",
	"ROSE": "oasis1qzw4h3wmyjtrttduqqrs8udggyy2emwdzqmuzwg4",
	"KIN":  "GDXJHJHWN6GRNOAZXON6XH74ZX6NYFAS5B7642RSJQVJTIPA4ZYUQLEB",
	"AE":   "ak_2p5878zbFhxnrm7meL7TmqwtvBaqcBddyp5eGzZbovZ5FeVfcw",
	// nist256p1
	"NEO": "AeicEjZyiXKgUeSBbYQHxsU1X3V5Buori5",
	"ONT": "AeicEjZyiXKgUeSBbYQHxsU1X3V5Buori5",
	// new-curve chains
	"XNO":   "nano_1qepdf4k95dhb5gsmhmq3iddqsxiafwkihunm7irn48jdiwdtnn6pe93k3f6",
	"WAVES": "3P2C786D6mBuvyf4WYr6K6Vch5uhi97nBHG",
}

func TestEncodersAgainstTrustWalletVectors(t *testing.T) {
	priv := dummyKey()
	for symbol, want := range trustWalletVectors {
		t.Run(symbol, func(t *testing.T) {
			coin, ok := coins[Symbol(symbol)]
			if !ok {
				t.Fatalf("coin %s not in registry", symbol)
			}
			pub, err := publicKeyFromPriv(coin.Curve, priv)
			if err != nil {
				t.Fatal(err)
			}
			got, err := coin.Encode(pub)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s address = %s, want %s", symbol, got, want)
			}
		})
	}
}

// TestEVMChainsMatchEthereum verifies that every EVM chain reuses the Ethereum
// address format (same key, same encoder), matching Trust Wallet.
func TestEVMChainsMatchEthereum(t *testing.T) {
	priv := dummyKey()
	const wantETH = "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"
	for _, symbol := range []Symbol{
		BNB, MATIC, AVAX, ARB, OP, FTM, BASE, CRO, GNO, CELO,
		ETC, ZKSYNC, LINEA, SCROLL, MANTLE, BLAST, KAIA, AURORA, GLMR, MOVR,
		BOBA, METIS, OPBNB, POLZKEVM, MANTA, RBTC, HECO, OKT, KCS, WAN,
		POA, CLO, GO, TT, VET, IOTX, THETA, NEON, MERLIN, LIGHT,
		SONIC, ZENEON, ZETAEVM,
	} {
		coin := coins[symbol]
		pub, err := publicKeyFromPriv(coin.Curve, priv)
		if err != nil {
			t.Fatal(err)
		}
		got, err := coin.Encode(pub)
		if err != nil {
			t.Fatal(err)
		}
		if got != wantETH {
			t.Errorf("%s = %s, want %s", symbol, got, wantETH)
		}
	}
}

// TestCosmosFamilyHRP verifies the bech32 human-readable prefixes for the
// Cosmos-family chains that share the Cosmos encoder.
func TestCosmosFamilyHRP(t *testing.T) {
	priv := dummyKey()
	prefixes := map[string]string{
		"JUNO": "juno1",
		"TIA":  "celestia1",
	}
	for symbol, wantPrefix := range prefixes {
		coin := coins[Symbol(symbol)]
		pub, err := publicKeyFromPriv(coin.Curve, priv)
		if err != nil {
			t.Fatal(err)
		}
		got, err := coin.Encode(pub)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix([]byte(got), []byte(wantPrefix)) {
			t.Errorf("%s = %s, want prefix %s", symbol, got, wantPrefix)
		}
	}
}
