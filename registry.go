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
	GRS  Symbol = "GRS"  // Groestlcoin (segwit)
	DGB  Symbol = "DGB"  // DigiByte (segwit)
	BTG  Symbol = "BTG"  // Bitcoin Gold (segwit)
	SYS  Symbol = "SYS"  // Syscoin (segwit)
	VIA  Symbol = "VIA"  // Viacoin (segwit)
	QTUM Symbol = "QTUM" // Qtum (base58check P2PKH)
	RVN  Symbol = "RVN"  // Ravencoin (base58check P2PKH)
	KMD  Symbol = "KMD"  // Komodo (base58check P2PKH)
	FIRO Symbol = "FIRO" // Firo (base58check P2PKH)
	MONA Symbol = "MONA" // MonaCoin (base58check P2PKH)
	XVG  Symbol = "XVG"  // Verge (base58check P2PKH)
	PIVX Symbol = "PIVX" // PIVX (base58check P2PKH)
	NEBL Symbol = "NEBL" // Neblio (base58check P2PKH)

	// secp256k1 — account-based / keccak.
	ETH Symbol = "ETH"
	TRX Symbol = "TRX"
	XRP Symbol = "XRP"

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

	// nist256p1 (SLIP-0010).
	NEO Symbol = "NEO"
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
	"QTUM": {"Qtum", "QTUM", Secp256k1, "m/44'/2301'/0'/0/0", encodeQTUM},
	"RVN":  {"Ravencoin", "RVN", Secp256k1, "m/44'/175'/0'/0/0", encodeRVN},
	"KMD":  {"Komodo", "KMD", Secp256k1, "m/44'/141'/0'/0/0", encodeKMD},
	"FIRO": {"Firo", "FIRO", Secp256k1, "m/44'/136'/0'/0/0", encodeFIRO},
	"MONA": {"MonaCoin", "MONA", Secp256k1, "m/44'/22'/0'/0/0", encodeMONA},
	"XVG":  {"Verge", "XVG", Secp256k1, "m/44'/77'/0'/0/0", encodeXVG},
	"PIVX": {"PIVX", "PIVX", Secp256k1, "m/44'/119'/0'/0/0", encodePIVX},
	"NEBL": {"Neblio", "NEBL", Secp256k1, "m/44'/146'/0'/0/0", encodeNEBL},

	// ---- secp256k1 : account-based / keccak ----
	"ETH": {"Ethereum", "ETH", Secp256k1, "m/44'/60'/0'/0/0", encodeETH},
	"TRX": {"Tron", "TRX", Secp256k1, "m/44'/195'/0'/0/0", encodeTRX},
	"XRP": {"XRP Ledger", "XRP", Secp256k1, "m/44'/144'/0'/0/0", encodeXRP},

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

	// ---- nist256p1 (SLIP-0010) ----
	"NEO": {"NEO", "NEO", Nist256p1, "m/44'/888'/0'/0/0", encodeNEO},
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
}
