package hdwallet

import (
	"encoding/binary"

	"github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// SolanaComputeUnits returns a conservative compute unit estimate for the input.
func SolanaComputeUnits(in *solana.SigningInput) uint32 {
	if in == nil {
		return 150
	}
	if in.GetTokenTransferTransaction() != nil {
		return 6000
	}
	return 150 // SOL native transfer
}

// SolanaComputeBudgetInstructions returns the serialized ComputeBudget program
// instructions to prepend: SetComputeUnitLimit (always) and SetComputeUnitPrice
// (only when priorityMicroLamportsPerCU > 0).
// Encoding: discriminator byte + little-endian value (no Borsh library needed).
func SolanaComputeBudgetInstructions(units uint32, priorityMicroLamportsPerCU uint64) [][]byte {
	limit := make([]byte, 5)
	limit[0] = 0x02
	binary.LittleEndian.PutUint32(limit[1:], units)

	if priorityMicroLamportsPerCU == 0 {
		return [][]byte{limit}
	}

	price := make([]byte, 9)
	price[0] = 0x03
	binary.LittleEndian.PutUint64(price[1:], priorityMicroLamportsPerCU)

	return [][]byte{limit, price}
}
