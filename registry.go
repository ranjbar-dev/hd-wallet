package hdwallet

import (
	"slices"
	"strconv"
)

// Curve identifies the elliptic curve a coin derives keys on. Each curve has a
// distinct derivation scheme (BIP-32 for secp256k1, SLIP-0010 for the others).
type Curve int

const (
	// Secp256k1 covers Bitcoin-style, Ethereum/EVM, Cosmos, XRP and Tron.
	Secp256k1 Curve = iota
	// Ed25519 covers Solana, Stellar, Algorand, Aptos.
	Ed25519
)

// String returns the SLIP-0010/BIP-32 name of the curve for diagnostics. The
// strings for the Trust Wallet Core curves match TWCurve.h exactly.
func (c Curve) String() string {
	switch c {
	case Secp256k1:
		return "secp256k1"
	case Ed25519:
		return "ed25519"
	default:
		return "unknown(" + strconv.Itoa(int(c)) + ")"
	}
}

// Chain is a typed network identifier used to look up a registry entry. Use the
// exported constants below (hdwallet.BTC, hdwallet.ETH, …) when calling methods
// such as (*HDWallet).Address and AddressIndex; the typed enum gives
// compile-time checking and editor autocomplete instead of bare strings.
type Chain string

// String implements fmt.Stringer.
func (s Chain) String() string { return string(s) }

// IsValid reports whether the chain is a registered network.
func (s Chain) IsValid() bool { _, ok := coins[s]; return ok }

// Supported network chains. These mirror the registry below and match Trust
// Wallet's tickers.
const (
	// secp256k1 — Bitcoin-style UTXO chains.
	BTC  Chain = "BTC"
	LTC  Chain = "LTC"
	DOGE Chain = "DOGE"
	BCH  Chain = "BCH"
	DASH Chain = "DASH"
	ZEC  Chain = "ZEC"

	// secp256k1 — additional UTXO chains.
	DGB   Chain = "DGB"   // DigiByte (segwit)
	SYS   Chain = "SYS"   // Syscoin (segwit)
	VIA   Chain = "VIA"   // Viacoin (segwit)
	QTUM  Chain = "QTUM"  // Qtum (base58check P2PKH)
	RVN   Chain = "RVN"   // Ravencoin (base58check P2PKH)
	FIRO  Chain = "FIRO"  // Firo (base58check P2PKH)
	MONA  Chain = "MONA"  // MonaCoin (base58check P2PKH)
	PIVX  Chain = "PIVX"  // PIVX (base58check P2PKH)
	STRAX Chain = "STRAX" // Stratis (segwit)

	// secp256k1 — account-based / keccak.
	ETH Chain = "ETH"
	TRX Chain = "TRX"
	XRP Chain = "XRP"

	// secp256k1 — EVM chains (same key & address format as Ethereum).
	BNB   Chain = "BNB"
	MATIC Chain = "MATIC"
	AVAX  Chain = "AVAX"
	ARB   Chain = "ARB"
	OP    Chain = "OP"
	FTM   Chain = "FTM"
	BASE  Chain = "BASE"
	CRO   Chain = "CRO"
	GNO   Chain = "GNO"
	CELO  Chain = "CELO"

	// secp256k1 — additional EVM chains (Ethereum address format, EIP-55).
	ETC      Chain = "ETC"
	RONIN    Chain = "RONIN"
	ZKSYNC   Chain = "ZKSYNC"
	LINEA    Chain = "LINEA"
	SCROLL   Chain = "SCROLL"
	MANTLE   Chain = "MANTLE"
	BLAST    Chain = "BLAST"
	KAIA     Chain = "KAIA"
	AURORA   Chain = "AURORA"
	GLMR     Chain = "GLMR"
	MOVR     Chain = "MOVR"
	BOBA     Chain = "BOBA"
	METIS    Chain = "METIS"
	OPBNB    Chain = "OPBNB"
	POLZKEVM Chain = "POLZKEVM"
	MANTA    Chain = "MANTA"
	RBTC     Chain = "RBTC"
	HECO     Chain = "HECO"
	OKT      Chain = "OKT"
	KCS      Chain = "KCS"
	WAN      Chain = "WAN"
	POA      Chain = "POA"
	CLO      Chain = "CLO"
	GO       Chain = "GO"
	TT       Chain = "TT"
	VET      Chain = "VET"
	IOTX     Chain = "IOTX"
	THETA    Chain = "THETA"
	NEON     Chain = "NEON"
	MERLIN   Chain = "MERLIN"
	LIGHT    Chain = "LIGHT"
	SONIC    Chain = "SONIC"
	ZENEON   Chain = "ZENEON"
	ZETAEVM  Chain = "ZETAEVM"

	// secp256k1 — Cosmos SDK chains.
	ATOM Chain = "ATOM"
	OSMO Chain = "OSMO"
	JUNO Chain = "JUNO"
	TIA  Chain = "TIA"

	// secp256k1 — additional Cosmos SDK chains (hash160 bech32, per-chain HRP).
	LUNA      Chain = "LUNA"
	KAVA      Chain = "KAVA"
	SCRT      Chain = "SCRT"
	BAND      Chain = "BAND"
	RUNE      Chain = "RUNE"
	STARS     Chain = "STARS"
	AXL       Chain = "AXL"
	STRD      Chain = "STRD"
	BLD       Chain = "BLD"
	CRE       Chain = "CRE"
	KUJI      Chain = "KUJI"
	CMDX      Chain = "CMDX"
	NTRN      Chain = "NTRN"
	SOMM      Chain = "SOMM"
	FET       Chain = "FET"
	MARS      Chain = "MARS"
	UMEE      Chain = "UMEE"
	COREUM    Chain = "COREUM"
	QSR       Chain = "QSR"
	XPRT      Chain = "XPRT"
	AKT       Chain = "AKT"
	NOBLE     Chain = "NOBLE"
	SEI       Chain = "SEI"
	DYDX      Chain = "DYDX"
	BLZ       Chain = "BLZ"
	CRYPTOORG Chain = "CRYPTOORG"

	// secp256k1 — Cosmos chains with EVM-style keys (keccak address, bech32).
	EVMOS Chain = "EVMOS"
	INJ   Chain = "INJ"

	// ed25519 (SLIP-0010).
	SOL   Chain = "SOL"
	XLM   Chain = "XLM"
	ALGO  Chain = "ALGO"
	APTOS Chain = "APTOS"
	TON   Chain = "TON"

	// Roadmap — Trust Wallet Core networks intentionally NOT registered yet (each
	// needs more than a vector-verified encoder over the standard seed path, so
	// adding one now would break AllAddresses or ship an unverified address):
	//   - NULS, Nebulas, Nimiq, Polymesh, Pactus, Internet Computer,
	//     Everscale, Aion: address scheme not yet reproduced against the TWC
	//     expected vector; omitted until vector-verified.
	//
	// Unsupported — see the "Unsupported chains" section in README.md/CLAUDE.md
	// for the 36 chains removed from this library entirely (ADA, AE, BCD, BTG,
	// CANTO, CKB, DOT, EGLD, EOS, FIL, FIO, FLUX, GRS, HBAR, ICX, IOST, KIN, KMD,
	// KSM, NEAR, NEBL, NEO, ONE, ONT, ROSE, STRK, SUI, WAVES, WAX, XEC, XNO, XTZ,
	// XVG, ZEN, ZETA, ZIL). A PR re-adding any of them must follow the
	// test-vector rule below.
)

// Coin describes a supported network: its curve, BIP-32 derivation path, and the
// function that turns a derived public key into an address string. Adding a
// network is a single entry in the registry below.
//
// Decimals is the number of fractional digits in the chain's native unit (e.g. 8
// for Bitcoin satoshis, 18 for Ethereum wei, 6 for Cosmos uatom) and is used to
// format on-chain balances. ChainID is the EIP-155 numeric chain id used to build
// EVM transactions; it is non-zero only for EVM chains (the evmTxChains set in
// tx_families.go) and 0 for every non-EVM coin. Both mirror the Trust Wallet Core
// coins registry. The SLIP-44 coin type is NOT stored — it is derived from Path
// via the SLIP44 method below.
type Coin struct {
	Name     string
	Chain    Chain
	Curve    Curve
	Path     string
	Encode   func(pub []byte) (string, error)
	Decimals uint8
	ChainID  uint64
}

// SLIP44 returns the SLIP-44 coin type for the coin, derived from the second
// element of its BIP-32 Path (e.g. "m/44'/60'/0'/0/0" → 60). The hardened flag is
// stripped. It is computed from Path rather than stored separately so the two can
// never drift; a malformed path returns 0.
func (c Coin) SLIP44() uint32 {
	idx, err := parsePath(c.Path)
	if err != nil || len(idx) < 2 {
		return 0
	}
	// idx[0] is purpose (44'/84'/…); idx[1] is the coin type. parsePath applies
	// the hardened offset, so strip it to recover the bare SLIP-44 number.
	coinType := idx[1]
	if coinType >= hardenedOffset {
		coinType -= hardenedOffset
	}
	return coinType
}

// coins is the address registry. Paths and address formats match Trust Wallet's
// defaults so seeds are interchangeable. Encoders verified against Trust Wallet
// Core's CoinAddressDerivation test vectors are marked accordingly in the tests.
//
// Field order is positional: Name, Chain, Curve, Path, Encode, Decimals, ChainID.
// Decimals is the native-unit precision (verified against Trust Wallet Core's
// registry.json); ChainID is the EIP-155 chain id and is non-zero ONLY for EVM
// chains (the evmTxChains set in tx_families.go), 0 for everything else.
var coins = map[Chain]Coin{
	// ---- secp256k1 : Bitcoin-style UTXO chains ----
	"BTC":  {"Bitcoin", "BTC", Secp256k1, "m/84'/0'/0'/0/0", encodeBTC, 8, 0},
	"LTC":  {"Litecoin", "LTC", Secp256k1, "m/84'/2'/0'/0/0", encodeLTC, 8, 0},
	"DOGE": {"Dogecoin", "DOGE", Secp256k1, "m/44'/3'/0'/0/0", encodeDOGE, 8, 0},
	"BCH":  {"Bitcoin Cash", "BCH", Secp256k1, "m/44'/145'/0'/0/0", encodeBCH, 8, 0},
	"DASH": {"Dash", "DASH", Secp256k1, "m/44'/5'/0'/0/0", encodeDASH, 8, 0},
	"ZEC":  {"Zcash", "ZEC", Secp256k1, "m/44'/133'/0'/0/0", encodeZEC, 8, 0},

	// ---- secp256k1 : additional UTXO chains ----
	// Native SegWit (P2WPKH, bech32) chains — witness program is hash160(pub).
	"DGB": {"DigiByte", "DGB", Secp256k1, "m/84'/20'/0'/0/0", encodeDGB, 8, 0},
	"SYS": {"Syscoin", "SYS", Secp256k1, "m/84'/57'/0'/0/0", encodeSYS, 8, 0},
	"VIA": {"Viacoin", "VIA", Secp256k1, "m/84'/14'/0'/0/0", encodeVIA, 8, 0},
	// Legacy P2PKH (base58check, single version byte).
	"QTUM":  {"Qtum", "QTUM", Secp256k1, "m/44'/2301'/0'/0/0", encodeQTUM, 8, 0},
	"RVN":   {"Ravencoin", "RVN", Secp256k1, "m/44'/175'/0'/0/0", encodeRVN, 8, 0},
	"FIRO":  {"Firo", "FIRO", Secp256k1, "m/44'/136'/0'/0/0", encodeFIRO, 8, 0},
	"MONA":  {"MonaCoin", "MONA", Secp256k1, "m/44'/22'/0'/0/0", encodeMONA, 8, 0},
	"PIVX":  {"PIVX", "PIVX", Secp256k1, "m/44'/119'/0'/0/0", encodePIVX, 8, 0},
	"STRAX": {"Stratis", "STRAX", Secp256k1, "m/84'/105105'/0'/0/0", encodeStratis, 8, 0},

	// ---- secp256k1 : account-based / keccak ----
	"ETH": {"Ethereum", "ETH", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 1},
	"TRX": {"Tron", "TRX", Secp256k1, "m/44'/195'/0'/0/0", encodeTRX, 6, 0},
	"XRP": {"XRP Ledger", "XRP", Secp256k1, "m/44'/144'/0'/0/0", encodeXRP, 6, 0},

	// ---- secp256k1 : EVM chains (same key & address format as Ethereum) ----
	"BNB":   {"BNB Smart Chain", "BNB", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 56},
	"MATIC": {"Polygon", "MATIC", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 137},
	"AVAX":  {"Avalanche C-Chain", "AVAX", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 43114},
	"ARB":   {"Arbitrum", "ARB", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 42161},
	"OP":    {"Optimism", "OP", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 10},
	"FTM":   {"Fantom", "FTM", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 250},
	"BASE":  {"Base", "BASE", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 8453},
	"CRO":   {"Cronos", "CRO", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 25},
	"GNO":   {"Gnosis", "GNO", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 100},
	"CELO":  {"Celo", "CELO", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 42220},

	// ---- secp256k1 : additional EVM chains (Ethereum address format) ----
	"ETC":      {"Ethereum Classic", "ETC", Secp256k1, "m/44'/61'/0'/0/0", encodeETH, 18, 61},
	"RONIN":    {"Ronin", "RONIN", Secp256k1, "m/44'/60'/0'/0/0", encodeRonin, 18, 2020},
	"ZKSYNC":   {"zkSync Era", "ZKSYNC", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 324},
	"LINEA":    {"Linea", "LINEA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 59144},
	"SCROLL":   {"Scroll", "SCROLL", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 534352},
	"MANTLE":   {"Mantle", "MANTLE", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 5000},
	"BLAST":    {"Blast", "BLAST", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 81457},
	"KAIA":     {"Kaia", "KAIA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 8217},
	"AURORA":   {"Aurora", "AURORA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 1313161554},
	"GLMR":     {"Moonbeam", "GLMR", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 1284},
	"MOVR":     {"Moonriver", "MOVR", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 1285},
	"BOBA":     {"Boba", "BOBA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 288},
	"METIS":    {"Metis", "METIS", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 1088},
	"OPBNB":    {"opBNB", "OPBNB", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 204},
	"POLZKEVM": {"Polygon zkEVM", "POLZKEVM", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 1101},
	"MANTA":    {"Manta Pacific", "MANTA", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 169},
	"RBTC":     {"Rootstock", "RBTC", Secp256k1, "m/44'/137'/0'/0/0", encodeETH, 18, 30},
	"HECO":     {"Huobi ECO Chain", "HECO", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 128},
	"OKT":      {"OKX Chain", "OKT", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 66},
	"KCS":      {"KuCoin Community Chain", "KCS", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 321},
	"WAN":      {"Wanchain", "WAN", Secp256k1, "m/44'/5718350'/0'/0/0", encodeETH, 18, 888},
	"POA":      {"POA Network", "POA", Secp256k1, "m/44'/178'/0'/0/0", encodeETH, 18, 99},
	"CLO":      {"Callisto", "CLO", Secp256k1, "m/44'/820'/0'/0/0", encodeETH, 18, 820},
	"GO":       {"GoChain", "GO", Secp256k1, "m/44'/6060'/0'/0/0", encodeETH, 18, 60},
	"TT":       {"ThunderCore", "TT", Secp256k1, "m/44'/1001'/0'/0/0", encodeETH, 18, 108},
	// VeChain does not use EIP-155 chain ids (its tx uses a 32-byte chainTag), so
	// ChainID is 0 even though VET is an EVM-keyed chain. TWC's registry lists 74.
	"VET":     {"VeChain", "VET", Secp256k1, "m/44'/818'/0'/0/0", encodeETH, 18, 0},
	"IOTX":    {"IoTeX", "IOTX", Secp256k1, "m/44'/304'/0'/0/0", encodeETH, 18, 4689},
	"THETA":   {"Theta", "THETA", Secp256k1, "m/44'/500'/0'/0/0", encodeETH, 18, 361},
	"NEON":    {"Neon", "NEON", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 245022934},
	"MERLIN":  {"Merlin", "MERLIN", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 4200},
	"LIGHT":   {"Lightlink", "LIGHT", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 1890},
	"SONIC":   {"Sonic", "SONIC", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 146},
	"ZENEON":  {"Horizen EON", "ZENEON", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 7332},
	"ZETAEVM": {"ZetaChain EVM", "ZETAEVM", Secp256k1, "m/44'/60'/0'/0/0", encodeETH, 18, 7000},

	// ---- secp256k1 : Cosmos SDK chains (bech32, same key, per-chain HRP) ----
	"ATOM": {"Cosmos", "ATOM", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("cosmos"), 6, 0},
	"OSMO": {"Osmosis", "OSMO", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("osmo"), 6, 0},
	"JUNO": {"Juno", "JUNO", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("juno"), 6, 0},
	"TIA":  {"Celestia", "TIA", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("celestia"), 6, 0},

	// ---- secp256k1 : additional Cosmos SDK chains (hash160 bech32) ----
	"LUNA":      {"Terra", "LUNA", Secp256k1, "m/44'/330'/0'/0/0", cosmosEncoder("terra"), 6, 0},
	"KAVA":      {"Kava", "KAVA", Secp256k1, "m/44'/459'/0'/0/0", cosmosEncoder("kava"), 6, 0},
	"SCRT":      {"Secret", "SCRT", Secp256k1, "m/44'/529'/0'/0/0", cosmosEncoder("secret"), 6, 0},
	"BAND":      {"Band Protocol", "BAND", Secp256k1, "m/44'/494'/0'/0/0", cosmosEncoder("band"), 6, 0},
	"RUNE":      {"THORChain", "RUNE", Secp256k1, "m/44'/931'/0'/0/0", cosmosEncoder("thor"), 8, 0}, // TWC: 8 decimals
	"STARS":     {"Stargaze", "STARS", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("stars"), 6, 0},
	"AXL":       {"Axelar", "AXL", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("axelar"), 6, 0},
	"STRD":      {"Stride", "STRD", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("stride"), 6, 0},
	"BLD":       {"Agoric", "BLD", Secp256k1, "m/44'/564'/0'/0/0", cosmosEncoder("agoric"), 6, 0},
	"CRE":       {"Crescent", "CRE", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("cre"), 6, 0},
	"KUJI":      {"Kujira", "KUJI", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("kujira"), 6, 0},
	"CMDX":      {"Comdex", "CMDX", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("comdex"), 6, 0},
	"NTRN":      {"Neutron", "NTRN", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("neutron"), 6, 0},
	"SOMM":      {"Sommelier", "SOMM", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("somm"), 6, 0},
	"FET":       {"Fetch.ai", "FET", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("fetch"), 6, 0},
	"MARS":      {"Mars", "MARS", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("mars"), 6, 0},
	"UMEE":      {"Umee", "UMEE", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("umee"), 6, 0},
	"COREUM":    {"Coreum", "COREUM", Secp256k1, "m/44'/990'/0'/0/0", cosmosEncoder("core"), 6, 0},
	"QSR":       {"Quasar", "QSR", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("quasar"), 6, 0},
	"XPRT":      {"Persistence", "XPRT", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("persistence"), 6, 0},
	"AKT":       {"Akash", "AKT", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("akash"), 6, 0},
	"NOBLE":     {"Noble", "NOBLE", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("noble"), 6, 0},
	"SEI":       {"Sei", "SEI", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("sei"), 6, 0},
	"DYDX":      {"dYdX", "DYDX", Secp256k1, "m/44'/118'/0'/0/0", cosmosEncoder("dydx"), 18, 0}, // dYdX chain native = 18
	"BLZ":       {"Bluzelle", "BLZ", Secp256k1, "m/44'/483'/0'/0/0", cosmosEncoder("bluzelle"), 6, 0},
	"CRYPTOORG": {"Crypto.org", "CRYPTOORG", Secp256k1, "m/44'/394'/0'/0/0", cosmosEncoder("cro"), 8, 0}, // TWC: 8 decimals

	// ---- secp256k1 : Cosmos chains with EVM-style keys (keccak address) ----
	// These are Ethermint/Cosmos chains, not standard EVM tx chains (they are not in
	// evmTxChains), so ChainID stays 0.
	"EVMOS": {"Evmos", "EVMOS", Secp256k1, "m/44'/60'/0'/0/0", cosmosEvmEncoder("evmos"), 18, 0},
	"INJ":   {"Injective", "INJ", Secp256k1, "m/44'/60'/0'/0/0", cosmosEvmEncoder("inj"), 18, 0},

	// ---- ed25519 (SLIP-0010) ----
	"SOL":   {"Solana", "SOL", Ed25519, "m/44'/501'/0'", encodeSOL, 9, 0},
	"XLM":   {"Stellar", "XLM", Ed25519, "m/44'/148'/0'", encodeXLM, 7, 0},
	"ALGO":  {"Algorand", "ALGO", Ed25519, "m/44'/283'/0'/0'/0'", encodeALGO, 6, 0},
	"APTOS": {"Aptos", "APTOS", Ed25519, "m/44'/637'/0'/0'/0'", encodeAPTOS, 8, 0},
	"TON":   {"TON", "TON", Ed25519, "m/44'/607'/0'", encodeTONAddress, 9, 0},
}

// init registers address validators for the networks added beyond the original
// base set, reusing the validator constructors defined in address_validate.go.
// Keeping these registrations here (rather than in address_validate.go) lets new
// chains ship as a single registry change while ValidateAddress/ParseAddress and
// the AddressFromPublicKey round-trip test stay correct for every coin.
func init() {
	// EVM chains validate exactly like Ethereum (0x + EIP-55).
	for _, s := range []Chain{
		ETC, ZKSYNC, LINEA, SCROLL, MANTLE, BLAST, KAIA, AURORA, GLMR, MOVR,
		BOBA, METIS, OPBNB, POLZKEVM, MANTA, RBTC, HECO, OKT, KCS, WAN,
		POA, CLO, GO, TT, VET, IOTX, THETA, NEON, MERLIN, LIGHT,
		SONIC, ZENEON, ZETAEVM,
	} {
		validators[s] = ethValidator(s)
	}
	// Ronin is an Ethereum address with a "ronin:" prefix instead of "0x".
	validators[RONIN] = roninValidator(RONIN)

	// Additional native-SegWit UTXO chains (witness program is hash160).
	validators[DGB] = segwitValidator("dgb", DGB)
	validators[SYS] = segwitValidator("sys", SYS)
	validators[VIA] = segwitValidator("via", VIA)
	// Additional legacy P2PKH (base58check, single version byte) chains.
	validators[QTUM] = base58CheckValidator1(0x3a, QTUM)
	validators[RVN] = base58CheckValidator1(0x3c, RVN)
	validators[FIRO] = base58CheckValidator1(0x52, FIRO)
	validators[MONA] = base58CheckValidator1(0x32, MONA)
	validators[PIVX] = base58CheckValidator1(0x1e, PIVX)
	validators[STRAX] = segwitValidator("strax", STRAX)

	// Additional Cosmos SDK chains (bech32, 20-byte payload, per-HRP). The same
	// validator handles both hash160-key and EVM-key chains since both encode a
	// 20-byte account identifier under the chain HRP.
	cosmos := map[Chain]string{
		LUNA: "terra", KAVA: "kava", SCRT: "secret", BAND: "band", RUNE: "thor",
		STARS: "stars", AXL: "axelar", STRD: "stride", BLD: "agoric", CRE: "cre",
		KUJI: "kujira", CMDX: "comdex", NTRN: "neutron", SOMM: "somm", FET: "fetch",
		MARS: "mars", UMEE: "umee", COREUM: "core", QSR: "quasar", XPRT: "persistence",
		AKT: "akash", NOBLE: "noble", SEI: "sei", DYDX: "dydx", BLZ: "bluzelle",
		CRYPTOORG: "cro",
		EVMOS:     "evmos", INJ: "inj",
	}
	for sym, hrp := range cosmos {
		validators[sym] = cosmosValidator(hrp, sym)
	}
}

// CoinFamily returns a string identifying the chain family for routing purposes.
// Values: "evm", "cosmos", "bitcoin-utxo", "solana", "tron", "ripple", "stellar",
// or "unknown".
func CoinFamily(chain Chain) string {
	if _, ok := evmTxChains[chain]; ok {
		return "evm"
	}
	if _, ok := cosmosTxChains[chain]; ok {
		return "cosmos"
	}
	if _, ok := ethermintTxChains[chain]; ok {
		return "cosmos"
	}
	if IsUTXO(chain) {
		return "bitcoin-utxo"
	}
	switch chain {
	case TRX:
		return "tron"
	case XRP:
		return "ripple"
	case SOL:
		return "solana"
	case XLM:
		return "stellar"
	default:
		return "unknown"
	}
}

// IsEVM returns true if chain is an EVM-compatible chain (Ethereum, BNB, Polygon, etc.)
func IsEVM(chain Chain) bool { _, ok := evmTxChains[chain]; return ok }

// IsCosmosSDK returns true if chain uses the Cosmos SDK signing path.
func IsCosmosSDK(chain Chain) bool {
	_, ok1 := cosmosTxChains[chain]
	_, ok2 := ethermintTxChains[chain]
	return ok1 || ok2
}

// IsUTXO returns true if chain uses Bitcoin-style UTXO transaction model.
func IsUTXO(chain Chain) bool {
	if _, ok := utxoTxChains[chain]; ok {
		return true
	}
	return chain == BTC || chain == LTC
}

// CoinDecimals returns the number of decimal places for the base unit of chain.
// Returns 0 if chain is not registered.
func CoinDecimals(chain Chain) int {
	c, ok := coins[chain]
	if !ok {
		return 0
	}
	return int(c.Decimals)
}

// SupportedTxCoins returns chains for which SignTransaction is implemented,
// sorted alphabetically.
func SupportedTxCoins() []Chain {
	set := make(map[Chain]struct{})
	for s := range evmTxChains {
		set[s] = struct{}{}
	}
	for s := range cosmosTxChains {
		set[s] = struct{}{}
	}
	for s := range ethermintTxChains {
		set[s] = struct{}{}
	}
	for s := range utxoTxChains {
		set[s] = struct{}{}
	}
	for _, s := range []Chain{BTC, LTC, TRX, XRP, SOL} {
		set[s] = struct{}{}
	}
	out := make([]Chain, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}
