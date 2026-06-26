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
// cosmosEvmEncoder rows) are deliberately NOT in cosmosTxChains: they sign with an
// eth_secp256k1 public-key type (not the standard "/cosmos.crypto.secp256k1.PubKey"),
// so the standard Cosmos builder would emit an on-chain-invalid transaction for
// them. The vector-verified ones are routed via ethermintTxChains instead; the rest
// remain unsupported until handled explicitly.

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

// utxoTxChains is every additional Bitcoin-family UTXO chain (beyond BTC/LTC)
// whose transaction is signed by the Bitcoin wire signer (signBitcoinTx /
// signZcashTx). DOGE and DASH share Bitcoin's legacy SIGHASH_ALL P2PKH algorithm
// (pinned via the btcd oracle); BCH signs with a BIP-143 preimage + SIGHASH_FORKID
// (pinned to Trust Wallet Core's BitcoinCash vector); ZEC signs transparent inputs
// with the Sapling v4 / ZIP-243 sighash (pinned to TWC's Zcash vector). All four
// route to familyBitcoin (see txFamilyOf).
var utxoTxChains = symbolSet(DOGE, DASH, BCH, ZEC)

// ethermintTxChains is every Ethermint-keyed Cosmos chain whose direct-mode tx is
// vector-verified. These sign with an eth_secp256k1 key: keccak256(SignDoc) digest
// and a chain-specific pubkey type URL (see signCosmosEthermintTx /
// ethermintPubKeyTypeURLs). EVMOS and INJ are included because each is reproduced
// byte-for-byte against its Trust Wallet Core vector — EVMOS uses
// "/ethermint.crypto.v1.ethsecp256k1.PubKey" with a compressed key
// (tx_cosmos_ethermint_test.go); INJ uses
// "/injective.crypto.v1beta1.ethsecp256k1.PubKey" with an UNCOMPRESSED key
// (tx_cosmos_injective_test.go).
//
// Roadmap — the other Ethermint-keyed rows (CANTO, ZETA, ONE) are NOT listed: an
// Ethermint chain's pubkey type URL (and, for some, its compressed/uncompressed
// encoding) DOES enter the signed bytes and is chain-specific, so each needs its
// own TWC vector before routing. Until then they fall through to ErrTxUnsupported
// rather than risk an on-chain-invalid signature.
var ethermintTxChains = symbolSet(EVMOS, INJ)

// symbolSet builds a set from a list of symbols.
func symbolSet(symbols ...Symbol) map[Symbol]struct{} {
	m := make(map[Symbol]struct{}, len(symbols))
	for _, s := range symbols {
		m[s] = struct{}{}
	}
	return m
}
