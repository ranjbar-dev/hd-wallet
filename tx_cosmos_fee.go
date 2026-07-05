package hdwallet

import (
	"fmt"
	"math"

	"github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// CosmosMinGasPrices maps well-known Cosmos chains to their minimum gas price.
var CosmosMinGasPrices = map[Chain]struct {
	Price float64
	Denom string
}{
	ATOM: {0.005, "uatom"},
	OSMO: {0.0025, "uosmo"},
	JUNO: {0.001, "ujuno"},
	KAVA: {0.001, "ukava"},
}

// CosmosGasLimit returns a conservative gas limit for the given Cosmos signing input.
// It sums per-message estimates; returns 80000 if no messages are present.
func CosmosGasLimit(in *cosmos.SigningInput) uint64 {
	if in == nil {
		return 80000
	}

	msgs := in.GetMessages()

	// Legacy single-send path.
	if len(msgs) == 0 {
		if in.GetSend() != nil {
			return 80000
		}
		return 80000
	}

	var total uint64
	for _, m := range msgs {
		total += cosmosMessageGas(m)
	}
	return total
}

func cosmosMessageGas(m *cosmos.Message) uint64 {
	if m == nil {
		return 80000
	}
	switch {
	case m.GetSend() != nil:
		return 80000
	case m.GetDelegate() != nil:
		return 200000
	case m.GetUndelegate() != nil:
		return 200000
	case m.GetWithdrawReward() != nil:
		return 150000
	default:
		return 80000
	}
}

// CosmosMinFee returns the minimum fee string (e.g. "5000uatom") for the given
// gas limit and minimum gas price in the chain's smallest denom unit.
func CosmosMinFee(gasLimit uint64, minGasPrice float64, denom string) string {
	fee := uint64(math.Ceil(float64(gasLimit) * minGasPrice))
	return fmt.Sprintf("%d%s", fee, denom)
}
