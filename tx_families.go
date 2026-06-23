package hdwallet

// Transaction-family membership.
//
// txFamilyOf routes a symbol to its transaction builder. EVM chains share one
// builder (the chain id is supplied in the SigningInput, so the bytes are
// identical across chains for the same key and input), as do the standard
// Cosmos SDK chains (the bech32 HRP lives only in the address strings the caller
// passes, not in the signed bytes). These sets are the single source of truth
// for that routing; they mirror the registry in registry.go / address_validate.go.
//
// IMPORTANT — ethermint-keyed Cosmos chains (EVMOS, INJ, CANTO, ZETA, ONE; the
// cosmosEvmEncoder rows) are deliberately NOT in cosmosTxChains: they sign with
// an "/ethermint.crypto.v1.ethsecp256k1.PubKey" public-key type, so the standard
// "/cosmos.crypto.secp256k1.PubKey" Cosmos builder would emit an on-chain-invalid
// transaction for them. They remain unsupported until handled explicitly.

// evmTxChains is every chain whose transaction is a standard Ethereum RLP tx
// (the encodeETH / encodeRonin registry rows).
var evmTxChains = symbolSet(
	// base EVM
	ETH, BNB, MATIC, AVAX, ARB, OP, FTM, BASE, CRO, GNO, CELO,
	// additional EVM (Ethereum address format)
	ETC, RONIN, ZKSYNC, LINEA, SCROLL, MANTLE, BLAST, KAIA, AURORA, GLMR,
	MOVR, BOBA, METIS, OPBNB, POLZKEVM, MANTA, RBTC, HECO, OKT, KCS,
	WAN, POA, CLO, GO, TT, VET, IOTX, THETA, NEON, MERLIN,
	LIGHT, SONIC, ZENEON, ZETAEVM,
)

// cosmosTxChains is every standard Cosmos SDK chain (the cosmosEncoder rows,
// secp256k1 / "/cosmos.crypto.secp256k1.PubKey"). Ethermint-keyed Cosmos chains
// are intentionally excluded (see the package note above).
var cosmosTxChains = symbolSet(
	// base Cosmos
	ATOM, OSMO, JUNO, TIA,
	// additional Cosmos (hash160 bech32, per-chain HRP)
	LUNA, KAVA, SCRT, BAND, RUNE, STARS, AXL, STRD, BLD, CRE,
	KUJI, CMDX, NTRN, SOMM, FET, MARS, UMEE, COREUM, QSR, XPRT,
	AKT, NOBLE, SEI, DYDX, BLZ, CRYPTOORG,
)

// ethermintTxChains is every Ethermint-keyed Cosmos chain whose direct-mode tx is
// vector-verified. These sign with an eth_secp256k1 key: keccak256(SignDoc) digest
// and the "/ethermint.crypto.v1.ethsecp256k1.PubKey" type URL (see
// signCosmosEthermintTx). Only EVMOS is included because its Trust Wallet Core
// vector is reproduced byte-for-byte (tx_cosmos_ethermint_test.go).
//
// Roadmap — the other Ethermint-keyed rows (CANTO, ZETA) and INJECTIVE are NOT
// listed: unlike standard Cosmos chains (where only the caller-supplied HRP
// differs and never enters the signed bytes), an Ethermint chain's pubkey type
// URL DOES enter the signed bytes and is chain-specific — Injective uses
// "/injective.crypto.v1beta1.ethsecp256k1.PubKey", not the ethermint URL. Each
// therefore needs its own TWC vector before routing; until then they fall through
// to ErrTxUnsupported rather than risk an on-chain-invalid signature.
var ethermintTxChains = symbolSet(EVMOS)

// symbolSet builds a set from a list of symbols.
func symbolSet(symbols ...Symbol) map[Symbol]struct{} {
	m := make(map[Symbol]struct{}, len(symbols))
	for _, s := range symbols {
		m[s] = struct{}{}
	}
	return m
}
