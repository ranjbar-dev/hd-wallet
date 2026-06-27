package hdwallet

import (
	"github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

const tronMinBandwidth int64 = 268

// TronBandwidth returns the estimated bandwidth for a Tron signing input.
// All transactions consume at least 268 bandwidth units.
func TronBandwidth(_ *tron.SigningInput) int64 {
	return tronMinBandwidth
}

// TronEnergy returns the estimated energy for a Tron signing input.
// Returns 0 for non-contract transactions; 65000 for TRC-20 transfers;
// 100000 for generic smart contract calls.
func TronEnergy(in *tron.SigningInput) int64 {
	if in == nil || in.GetTransaction() == nil {
		return 0
	}
	tx := in.GetTransaction()
	switch {
	case tx.GetTransferTrc20() != nil:
		return 65000
	case tx.GetTransfer() != nil:
		return 0
	case tx.GetTransferAsset() != nil:
		return 0
	default:
		// FreezeBalanceV2, UnfreezeBalanceV2, DelegateResource, etc. — conservative.
		return 100000
	}
}
