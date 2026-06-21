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
)

// String returns the SLIP-0010/BIP-32 name of the curve for diagnostics.
func (c Curve) String() string {
	switch c {
	case Secp256k1:
		return "secp256k1"
	case Ed25519:
		return "ed25519"
	case Nist256p1:
		return "nist256p1"
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
