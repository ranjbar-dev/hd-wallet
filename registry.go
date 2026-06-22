package hdwallet

import "strconv"

// Curve identifies the elliptic curve a coin derives keys on. Each curve has a
// distinct derivation scheme (BIP-32 for secp256k1, SLIP-0010 for the others).
type Curve int

const (
	// Secp256k1 covers Bitcoin-style, Ethereum/EVM, Cosmos, XRP and Tron.
	Secp256k1 Curve = iota
	// Ed25519 covers Solana, Stellar, Polkadot, NEAR, Algorand, Sui, Aptos, Tezos.
	Ed25519
	// Nist256p1 (NIST P-256) covers NEO.
	Nist256p1
	// Ed25519Blake2bNano is the ed25519 EdDSA variant Nano uses: identical to
	// ed25519 except the internal 512-bit hash is BLAKE2b-512 instead of SHA-512
	// (both for key expansion and the R/challenge hashes). SLIP-0010 ed25519
	// derivation is used for the leaf private key. Matches Trust Wallet Core's
	// TWCurveED25519Blake2bNano.
	Ed25519Blake2bNano
	// Curve25519 is the public-key/signing scheme Waves uses: the leaf private
	// key is derived via SLIP-0010 ed25519, the public key is the X25519
	// (Montgomery) point, and signing is ed25519 with the public-key sign bit
	// folded into S[63] (the "curve25519_sign" construction). Matches Trust
	// Wallet Core's TWCurveCurve25519.
	Curve25519
	// Ed25519ExtendedCardano is BIP32-Ed25519 (CIP-1852) with 64-byte extended
	// private keys, as used by Cardano. The master secret comes from the Icarus
	// (PBKDF2-HMAC-SHA512 over the BIP-39 entropy) scheme. Matches Trust Wallet
	// Core's TWCurveED25519ExtendedCardano.
	Ed25519ExtendedCardano
	// Starkex is the STARK curve (StarkNet/StarkEx), EIP-2645 key derivation with
	// grinding, RFC-6979 deterministic ECDSA. Matches Trust Wallet Core's
	// TWCurveStarkex.
	Starkex
	// Sr25519 is schnorrkel/ristretto255, the native key scheme for
	// Polkadot/Kusama. NOTE: this is NOT part of Trust Wallet Core's curve set
	// (TWC uses plain ed25519 for Polkadot); it is provided here as an additional
	// curve for native substrate signing.
	Sr25519
)

// String returns the SLIP-0010/BIP-32 name of the curve for diagnostics. The
// strings for the Trust Wallet Core curves match TWCurve.h exactly.
func (c Curve) String() string {
	switch c {
	case Secp256k1:
		return "secp256k1"
	case Ed25519:
		return "ed25519"
	case Nist256p1:
		return "nist256p1"
	case Ed25519Blake2bNano:
		return "ed25519-blake2b-nano"
	case Curve25519:
		return "curve25519"
	case Ed25519ExtendedCardano:
		return "ed25519-cardano-seed"
	case Starkex:
		return "starkex"
	case Sr25519:
		return "sr25519"
	default:
		return "unknown(" + strconv.Itoa(int(c)) + ")"
	}
}

// Symbol is a typed network identifier used to look up a registry entry. Use the
// exported constants below (hdwallet.BTC, hdwallet.ETH, …) when calling methods
// such as (*HDWallet).Address and AddressIndex; the typed enum gives
// compile-time checking and editor autocomplete instead of bare strings.
type Symbol string

// String implements fmt.Stringer.
func (s Symbol) String() string { return string(s) }

// IsValid reports whether the symbol is a registered network.
func (s Symbol) IsValid() bool { _, ok := coins[s]; return ok }

// Supported network symbols. These mirror the registry below and match Trust
// Wallet's tickers.
const (
	// secp256k1 — Bitcoin-style UTXO chains.
	BTC  Symbol = "BTC"
	LTC  Symbol = "LTC"
	DOGE Symbol = "DOGE"
	BCH  Symbol = "BCH"
	DASH Symbol = "DASH"
	ZEC  Symbol = "ZEC"

	// secp256k1 — additional UTXO chains.
	GRS   Symbol = "GRS"   // Groestlcoin (segwit)
	DGB   Symbol = "DGB"   // DigiByte (segwit)
	BTG   Symbol = "BTG"   // Bitcoin Gold (segwit)
	SYS   Symbol = "SYS"   // Syscoin (segwit)
	VIA   Symbol = "VIA"   // Viacoin (segwit)
	QTUM  Symbol = "QTUM"  // Qtum (base58check P2PKH)
	RVN   Symbol = "RVN"   // Ravencoin (base58check P2PKH)
	KMD   Symbol = "KMD"   // Komodo (base58check P2PKH)
	FIRO  Symbol = "FIRO"  // Firo (base58check P2PKH)
	MONA  Symbol = "MONA"  // MonaCoin (base58check P2PKH)
	XVG   Symbol = "XVG"   // Verge (base58check P2PKH)
	PIVX  Symbol = "PIVX"  // PIVX (base58check P2PKH)
	NEBL  Symbol = "NEBL"  // Neblio (base58check P2PKH)
	STRAX Symbol = "STRAX" // Stratis (segwit)
	ZEN   Symbol = "ZEN"   // Horizen (base58check 2-byte)
	BCD   Symbol = "BCD"   // Bitcoin Diamond (base58check P2PKH)
	XEC   Symbol = "XEC"   // eCash (CashAddr)
	FLUX  Symbol = "FLUX"  // Flux/Zelcash (base58check 2-byte)

	// secp256k1 — account-based / keccak.
	ETH Symbol = "ETH"
	TRX Symbol = "TRX"
	XRP Symbol = "XRP"

	// secp256k1 — EOS-family public-key strings.
	EOS Symbol = "EOS"
	WAX Symbol = "WAX"
	FIO Symbol = "FIO"

	// secp256k1 — Filecoin (f1 base32 address).
	FIL Symbol = "FIL"

	// secp256k1 — EVM chains (same key & address format as Ethereum).
	BNB   Symbol = "BNB"
	MATIC Symbol = "MATIC"
	AVAX  Symbol = "AVAX"
	ARB   Symbol = "ARB"
	OP    Symbol = "OP"
	FTM   Symbol = "FTM"
	BASE  Symbol = "BASE"
	CRO   Symbol = "CRO"
	GNO   Symbol = "GNO"
	CELO  Symbol = "CELO"

	// secp256k1 — additional EVM chains (Ethereum address format, EIP-55).
	ETC      Symbol = "ETC"
	RONIN    Symbol = "RONIN"
	ZKSYNC   Symbol = "ZKSYNC"
	LINEA    Symbol = "LINEA"
	SCROLL   Symbol = "SCROLL"
	MANTLE   Symbol = "MANTLE"
	BLAST    Symbol = "BLAST"
	KAIA     Symbol = "KAIA"
	AURORA   Symbol = "AURORA"
	GLMR     Symbol = "GLMR"
	MOVR     Symbol = "MOVR"
	BOBA     Symbol = "BOBA"
	METIS    Symbol = "METIS"
	OPBNB    Symbol = "OPBNB"
	POLZKEVM Symbol = "POLZKEVM"
	MANTA    Symbol = "MANTA"
	RBTC     Symbol = "RBTC"
	HECO     Symbol = "HECO"
	OKT      Symbol = "OKT"
	KCS      Symbol = "KCS"
	WAN      Symbol = "WAN"
	POA      Symbol = "POA"
	CLO      Symbol = "CLO"
	GO       Symbol = "GO"
	TT       Symbol = "TT"
	VET      Symbol = "VET"
	IOTX     Symbol = "IOTX"
	THETA    Symbol = "THETA"
	NEON     Symbol = "NEON"
	MERLIN   Symbol = "MERLIN"
	LIGHT    Symbol = "LIGHT"
	SONIC    Symbol = "SONIC"
	ZENEON   Symbol = "ZENEON"
	ZETAEVM  Symbol = "ZETAEVM"

	// secp256k1 — Cosmos SDK chains.
	ATOM Symbol = "ATOM"
	OSMO Symbol = "OSMO"
	JUNO Symbol = "JUNO"
	TIA  Symbol = "TIA"

	// secp256k1 — additional Cosmos SDK chains (hash160 bech32, per-chain HRP).
	LUNA      Symbol = "LUNA"
	KAVA      Symbol = "KAVA"
	SCRT      Symbol = "SCRT"
	BAND      Symbol = "BAND"
	RUNE      Symbol = "RUNE"
	STARS     Symbol = "STARS"
	AXL       Symbol = "AXL"
	STRD      Symbol = "STRD"
	BLD       Symbol = "BLD"
	CRE       Symbol = "CRE"
	KUJI      Symbol = "KUJI"
	CMDX      Symbol = "CMDX"
	NTRN      Symbol = "NTRN"
	SOMM      Symbol = "SOMM"
	FET       Symbol = "FET"
	MARS      Symbol = "MARS"
	UMEE      Symbol = "UMEE"
	COREUM    Symbol = "COREUM"
	QSR       Symbol = "QSR"
	XPRT      Symbol = "XPRT"
	AKT       Symbol = "AKT"
	NOBLE     Symbol = "NOBLE"
	SEI       Symbol = "SEI"
	DYDX      Symbol = "DYDX"
	BLZ       Symbol = "BLZ"
	CRYPTOORG Symbol = "CRYPTOORG"

	// secp256k1 — Cosmos chains with EVM-style keys (keccak address, bech32).
	EVMOS Symbol = "EVMOS"
	INJ   Symbol = "INJ"
	CANTO Symbol = "CANTO"
	ZETA  Symbol = "ZETA"
	ONE   Symbol = "ONE"

	// ed25519 (SLIP-0010).
	SOL   Symbol = "SOL"
	XLM   Symbol = "XLM"
	DOT   Symbol = "DOT"
	KSM   Symbol = "KSM"
	NEAR  Symbol = "NEAR"
	ALGO  Symbol = "ALGO"
	SUI   Symbol = "SUI"
	APTOS Symbol = "APTOS"
	XTZ   Symbol = "XTZ"

	// ed25519 (SLIP-0010) — additional chains.
	EGLD Symbol = "EGLD" // MultiversX (bech32 of pubkey)
	IOST Symbol = "IOST" // IOST (base58 of pubkey)
	HBAR Symbol = "HBAR" // Hedera (0.0.<DER-encoded pubkey hex>)
	ROSE Symbol = "ROSE" // Oasis (bech32 of context-hashed pubkey)
	KIN  Symbol = "KIN"  // Kin (Stellar strkey)
	AE   Symbol = "AE"   // Aeternity (ak_ base58check)

	// nist256p1 (SLIP-0010).
	NEO Symbol = "NEO"
	ONT Symbol = "ONT" // Ontology (same NEO-style address)

	// new-curve chains (SLIP-0010 ed25519 leaf key, chain-specific signing).
	XNO   Symbol = "XNO"   // Nano (ed25519-blake2b)
	WAVES Symbol = "WAVES" // Waves (curve25519)

	// Roadmap — Trust Wallet Core networks intentionally NOT registered yet (each
	// needs more than a vector-verified encoder over the standard seed path, so
	// adding one now would break AllAddresses or ship an unverified address):
	//   - Cardano: needs BIP-39 ENTROPY (Icarus master), not the seed; the seed
	//     path returns errCardanoNeedsEntropy, so a row would break AllAddresses.
	//   - StarkNet/StarkEx: seed->key derivation is provisional/unverified.
	//   - Zilliqa: requires a Schnorr scheme that is not implemented.
	//   - TON: address is the hash of a v4r2 wallet StateInit cell (BoC); too
	//     chain-specific to reproduce and vector-match safely here.
	//   - ICON, Nervos, NULS, Nebulas, Nimiq, Polymesh, Pactus, Internet Computer,
	//     Everscale, Aion: address scheme not yet reproduced against the TWC
	//     expected vector; omitted until vector-verified.
)

// Coin describes a supported network: its curve, BIP-32 derivation path, and the
// function that turns a derived public key into an address string. Adding a
// network is a single entry in the registry below.
type Coin struct {
	Name   string
	Symbol Symbol
	Curve  Curve
	Path   string
	Encode func(pub []byte) (string, error)
}

// coins is the address registry. Paths and address formats match Trust Wallet's
// defaults so seeds are interchangeable. Encoders verified against Trust Wallet
// Core's CoinAddressDerivation test vectors are marked accordingly in the tests.
var coins = map[Symbol]Coin{
	// ---- secp256k1 : Bitcoin-style UTXO chains ----
	"BTC":  {"Bitcoin", "BTC", Secp256k1, "m/84'/0'/0'/0/0", encodeBTC},
	"LTC":  {"Litecoin", "LTC", Secp256k1, "m/84'/2'/0'/0/0", encodeLTC},
	"DOGE": {"Dogecoin", "DOGE", Secp256k1, "m/44'/3'/0'/0/0", encodeDOGE},
	"BCH":  {"Bitcoin Cash", "BCH", Secp256k1, "m/44'/145'/0'/0/0", encodeBCH},
	"DASH": {"Dash", "DASH", Secp256k1, "m/44'/5'/0'/0/0", encodeDASH},
	"ZEC":  {"Zcash", "ZEC", Secp256k1, "m/44'/133'/0'/0/0", encodeZEC},

	// ---- secp256k1 : additional UTXO chains ----
	// Native SegWit (P2WPKH, bech32) chains — witness program is hash160(pub).
	"GRS": {"Groestlcoin", "GRS", Secp256k1, "m/84'/17'/0'/0/0", encodeGRS},
	"DGB": {"DigiByte", "DGB", Secp256k1, "m/84'/20'/0'/0/0", encodeDGB},
	"BTG": {"Bitcoin Gold", "BTG", Secp256k1, "m/84'/156'/0'/0/0", encodeBTG},
	"SYS": {"Syscoin", "SYS", Secp256k1, "m/84'/57'/0'/0/0", encodeSYS},
	"VIA": {"Viacoin", "VIA", Secp256k1, "m/84'/14'/0'/0/0", encodeVIA},
	// Legacy P2PKH (base58check, single version byte).
	"QTUM":  {"Qtum", "QTUM", Secp256k1, "m/44'/2301'/0'/0/0", encodeQTUM},
	"RVN":   {"Ravencoin", "RVN", Secp256k1, "m/44'/175'/0'/0/0", encodeRVN},
	"KMD":   {"Komodo", "KMD", Secp256k1, "m/44'/141'/0'/0/0", encodeKMD},
	"FIRO":  {"Firo", "FIRO", Secp256k1, "m/44'/136'/0'/0/0", encodeFIRO},
	"MONA":  {"MonaCoin", "MONA", Secp256k1, "m/44'/22'/0'/0/0", encodeMONA},
	"XVG":   {"Verge", "XVG", Secp256k1, "m/44'/77'/0'/0/0", encodeXVG},
	"PIVX":  {"PIVX", "PIVX", Secp256k1, "m/44'/119'/0'/0/0", encodePIVX},
	"NEBL":  {"Neblio", "NEBL", Secp256k1, "m/44'/146'/0'/0/0", encodeNEBL},
	"STRAX": {"Stratis", "STRAX", Secp256k1, "m/84'/105105'/0'/0/0", encodeStratis},
	"ZEN":   {"Horizen", "ZEN", Secp256k1, "m/44'/121'/0'/0/0", encodeZEN},
	"BCD":   {"Bitcoin Diamond", "BCD", Secp256k1, "m/44'/999'/0'/0/0", encodeBCD},
	"XEC":   {"eCash", "XEC", Secp256k1, "m/44'/899'/0'/0/0", encodeECash},
	"FLUX":  {"Flux", "FLUX", Secp256k1, "m/44'/19167'/0'/0/0", encodeFLUX},

	// ---- secp256k1 : account-based / keccak ----
	"ETH": {"Ethereum", "ETH", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"TRX": {"Tron", "TRX", Secp256k1, "m/44'/195'/0'/0/0", encodeTRX},
	"XRP": {"XRP Ledger", "XRP", Secp256k1, "m/44'/144'/0'/0/0", encodeXRP},

	// ---- secp256k1 : EOS-family public-key strings ----
	"EOS": {"EOS", "EOS", Secp256k1, "m/44'/194'/0'/0/0", eosEncoder("EOS")},
	"WAX": {"WAX", "WAX", Secp256k1, "m/44'/194'/0'/0/0", eosEncoder("EOS")},
	"FIO": {"FIO", "FIO", Secp256k1, "m/44'/235'/0'/0/0", eosEncoder("FIO")},

	// ---- secp256k1 : Filecoin ----
	"FIL": {"Filecoin", "FIL", Secp256k1, "m/44'/461'/0'/0/0", encodeFIL},

	// ---- secp256k1 : EVM chains (same key & address format as Ethereum) ----
	"BNB":   {"BNB Smart Chain", "BNB", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"MATIC": {"Polygon", "MATIC", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"AVAX":  {"Avalanche C-Chain", "AVAX", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"ARB":   {"Arbitrum", "ARB", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"OP":    {"Optimism", "OP", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"FTM":   {"Fantom", "FTM", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"BASE":  {"Base", "BASE", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"CRO":   {"Cronos", "CRO", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"GNO":   {"Gnosis", "GNO", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"CELO":  {"Celo", "CELO", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},

	// ---- secp256k1 : additional EVM chains (Ethereum address format) ----
	"ETC":      {"Ethereum Classic", "ETC", Secp256k1, "m/44'/61'/0'/0/0", encodeETH},
	"RONIN":    {"Ronin", "RONIN", Secp256k1, "m/44'/60'/0'/0/0", encodeRonin},
	"ZKSYNC":   {"zkSync Era", "ZKSYNC", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"LINEA":    {"Linea", "LINEA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"SCROLL":   {"Scroll", "SCROLL", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"MANTLE":   {"Mantle", "MANTLE", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"BLAST":    {"Blast", "BLAST", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"KAIA":     {"Kaia", "KAIA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"AURORA":   {"Aurora", "AURORA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"GLMR":     {"Moonbeam", "GLMR", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"MOVR":     {"Moonriver", "MOVR", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"BOBA":     {"Boba", "BOBA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"METIS":    {"Metis", "METIS", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"OPBNB":    {"opBNB", "OPBNB", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"POLZKEVM": {"Polygon zkEVM", "POLZKEVM", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"MANTA":    {"Manta Pacific", "MANTA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"RBTC":     {"Rootstock", "RBTC", Secp256k1, "m/44'/137'/0'/0/0", encodeETH},
	"HECO":     {"Huobi ECO Chain", "HECO", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"OKT":      {"OKX Chain", "OKT", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"KCS":      {"KuCoin Community Chain", "KCS", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"WAN":      {"Wanchain", "WAN", Secp256k1, "m/44'/5718350'/0'/0/0", encodeETH},
	"POA":      {"POA Network", "POA", Secp256k1, "m/44'/178'/0'/0/0", encodeETH},
	"CLO":      {"Callisto", "CLO", Secp256k1, "m/44'/820'/0'/0/0", encodeETH},
	"GO":       {"GoChain", "GO", Secp256k1, "m/44'/6060'/0'/0/0", encodeETH},
	"TT":       {"ThunderCore", "TT", Secp256k1, "m/44'/1001'/0'/0/0", encodeETH},
	"VET":      {"VeChain", "VET", Secp256k1, "m/44'/818'/0'/0/0", encodeETH},
	"IOTX":     {"IoTeX", "IOTX", Secp256k1, "m/44'/304'/0'/0/0", encodeETH},
	"THETA":    {"Theta", "THETA", Secp256k1, "m/44'/500'/0'/0/0", encodeETH},
	"NEON":     {"Neon", "NEON", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"MERLIN":   {"Merlin", "MERLIN", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"LIGHT":    {"Lightlink", "LIGHT", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"SONIC":    {"Sonic", "SONIC", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"ZENEON":   {"Horizen EON", "ZENEON", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"ZETAEVM":  {"ZetaChain EVM", "ZETAEVM", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},

	// ---- secp256k1 : Cosmos SDK chains (bech32, same key, per-chain HRP) ----
	"ATOM": {"Cosmos", "ATOM", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("cosmos")},
	"OSMO": {"Osmosis", "OSMO", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("osmo")},
	"JUNO": {"Juno", "JUNO", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("juno")},
	"TIA":  {"Celestia", "TIA", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("celestia")},

	// ---- secp256k1 : additional Cosmos SDK chains (hash160 bech32) ----
	"LUNA":      {"Terra", "LUNA", Secp256k1, "m/44'/330'/0'/0/0", cosmosEncoder("terra")},
	"KAVA":      {"Kava", "KAVA", Secp256k1, "m/44'/459'/0'/0/0", cosmosEncoder("kava")},
	"SCRT":      {"Secret", "SCRT", Secp256k1, "m/44'/529'/0'/0/0", cosmosEncoder("secret")},
	"BAND":      {"Band Protocol", "BAND", Secp256k1, "m/44'/494'/0'/0/0", cosmosEncoder("band")},
	"RUNE":      {"THORChain", "RUNE", Secp256k1, "m/44'/931'/0'/0/0", cosmosEncoder("thor")},
	"STARS":     {"Stargaze", "STARS", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("stars")},
	"AXL":       {"Axelar", "AXL", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("axelar")},
	"STRD":      {"Stride", "STRD", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("stride")},
	"BLD":       {"Agoric", "BLD", Secp256k1, "m/44'/564'/0'/0/0", cosmosEncoder("agoric")},
	"CRE":       {"Crescent", "CRE", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("cre")},
	"KUJI":      {"Kujira", "KUJI", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("kujira")},
	"CMDX":      {"Comdex", "CMDX", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("comdex")},
	"NTRN":      {"Neutron", "NTRN", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("neutron")},
	"SOMM":      {"Sommelier", "SOMM", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("somm")},
	"FET":       {"Fetch.ai", "FET", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("fetch")},
	"MARS":      {"Mars", "MARS", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("mars")},
	"UMEE":      {"Umee", "UMEE", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("umee")},
	"COREUM":    {"Coreum", "COREUM", Secp256k1, "m/44'/990'/0'/0/0", cosmosEncoder("core")},
	"QSR":       {"Quasar", "QSR", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("quasar")},
	"XPRT":      {"Persistence", "XPRT", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("persistence")},
	"AKT":       {"Akash", "AKT", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("akash")},
	"NOBLE":     {"Noble", "NOBLE", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("noble")},
	"SEI":       {"Sei", "SEI", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("sei")},
	"DYDX":      {"dYdX", "DYDX", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("dydx")},
	"BLZ":       {"Bluzelle", "BLZ", Secp256k1, "m/44'/483'/0'/0/0", cosmosEncoder("bluzelle")},
	"CRYPTOORG": {"Crypto.org", "CRYPTOORG", Secp256k1, "m/44'/394'/0'/0/0", cosmosEncoder("cro")},

	// ---- secp256k1 : Cosmos chains with EVM-style keys (keccak address) ----
	"EVMOS": {"Evmos", "EVMOS", Secp256k1, "m/44'/60'/0'/0/0", cosmosEvmEncoder("evmos")},
	"INJ":   {"Injective", "INJ", Secp256k1, "m/44'/60'/0'/0/0", cosmosEvmEncoder("inj")},
	"CANTO": {"Canto", "CANTO", Secp256k1, "m/44'/60'/0'/0/0", cosmosEvmEncoder("canto")},
	"ZETA":  {"ZetaChain", "ZETA", Secp256k1, "m/44'/60'/0'/0/0", cosmosEvmEncoder("zeta")},
	"ONE":   {"Harmony", "ONE", Secp256k1, "m/44'/1023'/0'/0/0", cosmosEvmEncoder("one")},

	// ---- ed25519 (SLIP-0010) ----
	"SOL":   {"Solana", "SOL", Ed25519, "m/44'/501'/0'", encodeSOL},
	"XLM":   {"Stellar", "XLM", Ed25519, "m/44'/148'/0'", encodeXLM},
	"DOT":   {"Polkadot", "DOT", Ed25519, "m/44'/354'/0'/0'/0'", ss58Encoder(0)},
	"KSM":   {"Kusama", "KSM", Ed25519, "m/44'/434'/0'/0'/0'", ss58Encoder(2)},
	"NEAR":  {"NEAR", "NEAR", Ed25519, "m/44'/397'/0'", encodeNEAR},
	"ALGO":  {"Algorand", "ALGO", Ed25519, "m/44'/283'/0'/0'/0'", encodeALGO},
	"SUI":   {"Sui", "SUI", Ed25519, "m/44'/784'/0'/0'/0'", encodeSUI},
	"APTOS": {"Aptos", "APTOS", Ed25519, "m/44'/637'/0'/0'/0'", encodeAPTOS},
	"XTZ":   {"Tezos", "XTZ", Ed25519, "m/44'/1729'/0'/0'", encodeXTZ},

	// ---- ed25519 (SLIP-0010) : additional chains ----
	"EGLD": {"MultiversX", "EGLD", Ed25519, "m/44'/508'/0'/0'/0'", encodeEGLD},
	"IOST": {"IOST", "IOST", Ed25519, "m/44'/899'/0'/0'/0'", encodeSOL},
	"HBAR": {"Hedera", "HBAR", Ed25519, "m/44'/3030'/0'/0'/0'", encodeHBAR},
	"ROSE": {"Oasis", "ROSE", Ed25519, "m/44'/474'/0'", encodeOasis},
	"KIN":  {"Kin", "KIN", Ed25519, "m/44'/2017'/0'", encodeXLM},
	"AE":   {"Aeternity", "AE", Ed25519, "m/44'/457'/0'/0'/0'", encodeAE},

	// ---- nist256p1 (SLIP-0010) ----
	"NEO": {"NEO", "NEO", Nist256p1, "m/44'/888'/0'/0/0", encodeNEO},
	"ONT": {"Ontology", "ONT", Nist256p1, "m/44'/1024'/0'/0/0", encodeNEO},

	// ---- new-curve chains ----
	"XNO":   {"Nano", "XNO", Ed25519Blake2bNano, "m/44'/165'/0'", encodeNano},
	"WAVES": {"Waves", "WAVES", Curve25519, "m/44'/5741564'/0'/0'/0'", encodeWaves},
}

// init registers address validators for the networks added beyond the original
// base set, reusing the validator constructors defined in address_validate.go.
// Keeping these registrations here (rather than in address_validate.go) lets new
// chains ship as a single registry change while ValidateAddress/ParseAddress and
// the AddressFromPublicKey round-trip test stay correct for every coin.
func init() {
	// EVM chains validate exactly like Ethereum (0x + EIP-55).
	for _, s := range []Symbol{
		ETC, ZKSYNC, LINEA, SCROLL, MANTLE, BLAST, KAIA, AURORA, GLMR, MOVR,
		BOBA, METIS, OPBNB, POLZKEVM, MANTA, RBTC, HECO, OKT, KCS, WAN,
		POA, CLO, GO, TT, VET, IOTX, THETA, NEON, MERLIN, LIGHT,
		SONIC, ZENEON, ZETAEVM,
	} {
		validators[s] = ethValidator(s)
	}
	// Ronin is an Ethereum address with a "ronin:" prefix instead of "0x".
	validators[RONIN] = roninValidator(RONIN)

	// EOS-family public-key strings.
	validators[EOS] = eosValidator("EOS", EOS)
	validators[WAX] = eosValidator("EOS", WAX)
	validators[FIO] = eosValidator("FIO", FIO)

	// Filecoin f1 address.
	validators[FIL] = filValidator(FIL)

	// Additional native-SegWit UTXO chains (witness program is hash160).
	validators[GRS] = segwitValidator("grs", GRS)
	validators[DGB] = segwitValidator("dgb", DGB)
	validators[BTG] = segwitValidator("btg", BTG)
	validators[SYS] = segwitValidator("sys", SYS)
	validators[VIA] = segwitValidator("via", VIA)
	// Additional legacy P2PKH (base58check, single version byte) chains.
	validators[QTUM] = base58CheckValidator1(0x3a, QTUM)
	validators[RVN] = base58CheckValidator1(0x3c, RVN)
	validators[KMD] = base58CheckValidator1(0x3c, KMD)
	validators[FIRO] = base58CheckValidator1(0x52, FIRO)
	validators[MONA] = base58CheckValidator1(0x32, MONA)
	validators[XVG] = base58CheckValidator1(0x1e, XVG)
	validators[PIVX] = base58CheckValidator1(0x1e, PIVX)
	validators[NEBL] = base58CheckValidator1(0x35, NEBL)
	validators[STRAX] = segwitValidator("strax", STRAX)
	validators[ZEN] = base58CheckValidatorN(base58BTC, []byte{0x20, 0x89}, ZEN)
	validators[BCD] = base58CheckValidator1(0x00, BCD)
	validators[FLUX] = base58CheckValidatorN(base58BTC, []byte{0x1c, 0xb8}, FLUX)
	validators[XEC] = cashAddrValidator("ecash", XEC)

	// Additional Cosmos SDK chains (bech32, 20-byte payload, per-HRP). The same
	// validator handles both hash160-key and EVM-key chains since both encode a
	// 20-byte account identifier under the chain HRP.
	cosmos := map[Symbol]string{
		LUNA: "terra", KAVA: "kava", SCRT: "secret", BAND: "band", RUNE: "thor",
		STARS: "stars", AXL: "axelar", STRD: "stride", BLD: "agoric", CRE: "cre",
		KUJI: "kujira", CMDX: "comdex", NTRN: "neutron", SOMM: "somm", FET: "fetch",
		MARS: "mars", UMEE: "umee", COREUM: "core", QSR: "quasar", XPRT: "persistence",
		AKT: "akash", NOBLE: "noble", SEI: "sei", DYDX: "dydx", BLZ: "bluzelle",
		CRYPTOORG: "cro",
		EVMOS:     "evmos", INJ: "inj", CANTO: "canto", ZETA: "zeta", ONE: "one",
	}
	for sym, hrp := range cosmos {
		validators[sym] = cosmosValidator(hrp, sym)
	}

	// Additional ed25519 / nist256p1 chains.
	validators[EGLD] = egldValidator(EGLD)             // bech32("erd", 32-byte pubkey)
	validators[IOST] = solValidator(IOST)              // base58 32-byte pubkey
	validators[HBAR] = hbarValidator(HBAR)             // 0.0.<DER hex>
	validators[ROSE] = oasisValidator(ROSE)            // bech32("oasis", ...)
	validators[KIN] = strkeyValidator(6<<3, KIN)       // Stellar strkey (version 'G')
	validators[AE] = aeValidator(AE)                   // ak_ base58check
	validators[ONT] = base58CheckValidator1(0x17, ONT) // same NEO-style address

	// New-curve chains.
	validators[XNO] = nanoValidator(XNO)      // nano_ base32 + blake2b-40 checksum
	validators[WAVES] = wavesValidator(WAVES) // base58 secure-hash address
}
