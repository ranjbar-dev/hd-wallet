package hdwallet

import "math/big"

// Chain-constraint helpers: informational sanity floors for account-existence
// and relay-dust rules on chains that enforce them. These are NOT fund-critical
// signing data (no Trust Wallet Core vector is required) — they exist so a
// caller can pre-flight "will this transfer leave the account/UTXO below the
// network's floor" before broadcasting. Protocol parameters can change by
// governance/hard-fork; treat the returned values as sanity floors, not
// consensus data, and re-check the cited sources before relying on them for
// anything beyond a warning.

// utxoDustChains is every Bitcoin-family UTXO chain that shares the package's
// single dust-relay threshold (btcDustThreshold, tx_bitcoin.go) — the union of
// btcAddrParams (BTC, LTC, and the native-SegWit altcoins) and utxoOutParams
// (the legacy-P2PKH altcoins plus BCH/ZEC). All of them sign through the same
// Bitcoin wire signer, so they all inherit the same 546-sat floor; see
// tx_bitcoin.go's btcDustThreshold doc comment.
var utxoDustChains = chainSet(
	BTC, LTC,
	DOGE, DASH, BCH, ZEC,
	DGB, SYS, VIA, STRAX,
	QTUM, RVN, FIRO, MONA, PIVX,
)

// xrpBaseReserveDrops is the XRP Ledger's per-account base reserve, in drops
// (1 XRP = 1_000_000 drops). Source: https://xrpl.org/docs/concepts/accounts/reserves
// — reduced from 10 XRP to 1 XRP in the December 2024 amendment. As of 2026-07-04.
var xrpBaseReserveDrops = big.NewInt(1_000_000)

// xlmMinimumReserveStroops is Stellar's minimum account balance: 2 × the
// network's base reserve (0.5 XLM each = 1 XLM = 10_000_000 stroops), the
// floor for any account holding zero subentries. Source:
// https://developers.stellar.org/docs/learn/fundamentals/fees-resource-limits-metering#base-reserves
// As of 2026-07-04.
var xlmMinimumReserveStroops = big.NewInt(10_000_000)

// solRentExemptZeroDataLamports is the rent-exempt minimum balance for a
// zero-data (system-owned) Solana account, in lamports. Source:
// https://docs.solanalabs.com/implemented-proposals/rent (rent-exempt minimum
// for 0 bytes of account data under the current lamports-per-byte-year rate).
// As of 2026-07-04.
var solRentExemptZeroDataLamports = big.NewInt(890_880)

// trxNewAccountFeeSun is TRON's fee for activating a previously unseen
// account by sending it value, in sun (1 TRX = 1_000_000 sun). TRON has two
// account-creation paths — a ~1 TRX contract-created-account fee, or a
// bandwidth-points path that can cost as little as ~0.1 TRX when the sender
// has spare bandwidth — so this is documented conservatively at the higher
// end (1.1 TRX) rather than pinning the cheaper, bandwidth-dependent path.
// Source: https://developers.tron.network/docs/account#create-account As of
// 2026-07-04.
var trxNewAccountFeeSun = big.NewInt(1_100_000)

// MinimumBalance returns the minimum native balance (in base units) an account
// must retain to exist on-chain, and whether the chain has such a constraint.
// Values are protocol parameters as of 2026-07-04 (sources in the package-level
// var comments above) and can change by governance — treat as sanity floors,
// not consensus data.
func MinimumBalance(chain Chain) (*big.Int, bool) {
	switch chain {
	case XRP:
		return new(big.Int).Set(xrpBaseReserveDrops), true
	case XLM:
		return new(big.Int).Set(xlmMinimumReserveStroops), true
	case SOL:
		return new(big.Int).Set(solRentExemptZeroDataLamports), true
	default:
		return nil, false
	}
}

// DustThreshold returns the standard-relay dust limit for UTXO chains (sats),
// reusing tx_bitcoin.go's btcDustThreshold — the same constant the signer
// itself uses to decide whether a change output is worth creating.
func DustThreshold(chain Chain) (*big.Int, bool) {
	if _, ok := utxoDustChains[chain]; !ok {
		return nil, false
	}
	return big.NewInt(btcDustThreshold), true
}

// ActivationCost returns the one-off cost charged when first funding a
// previously unseen account (TRX account-creation fee, XLM/XRP reserves).
func ActivationCost(chain Chain) (*big.Int, bool) {
	switch chain {
	case TRX:
		return new(big.Int).Set(trxNewAccountFeeSun), true
	default:
		return nil, false
	}
}
