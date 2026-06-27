package hdwallet

import (
	"encoding/binary"
	"testing"

	"github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

func TestSolanaComputeUnits(t *testing.T) {
	tests := []struct {
		name string
		in   *solana.SigningInput
		want uint32
	}{
		{"nil", nil, 150},
		{
			"SOL transfer",
			&solana.SigningInput{
				TransactionType: &solana.SigningInput_TransferTransaction{
					TransferTransaction: &solana.Transfer{},
				},
			},
			150,
		},
		{
			"SPL token transfer",
			&solana.SigningInput{
				TransactionType: &solana.SigningInput_TokenTransferTransaction{
					TokenTransferTransaction: &solana.TokenTransfer{},
				},
			},
			6000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SolanaComputeUnits(tc.in)
			if got != tc.want {
				t.Errorf("SolanaComputeUnits() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSolanaComputeBudgetInstructions(t *testing.T) {
	t.Run("limit only", func(t *testing.T) {
		instrs := SolanaComputeBudgetInstructions(150, 0)
		if len(instrs) != 1 {
			t.Fatalf("want 1 instruction, got %d", len(instrs))
		}
		// discriminator 0x02, then uint32 LE
		if instrs[0][0] != 0x02 {
			t.Errorf("discriminator = %#x, want 0x02", instrs[0][0])
		}
		if binary.LittleEndian.Uint32(instrs[0][1:]) != 150 {
			t.Errorf("units = %d, want 150", binary.LittleEndian.Uint32(instrs[0][1:]))
		}
	})

	t.Run("limit + price", func(t *testing.T) {
		instrs := SolanaComputeBudgetInstructions(6000, 1000)
		if len(instrs) != 2 {
			t.Fatalf("want 2 instructions, got %d", len(instrs))
		}
		if instrs[0][0] != 0x02 {
			t.Errorf("limit discriminator = %#x, want 0x02", instrs[0][0])
		}
		if binary.LittleEndian.Uint32(instrs[0][1:]) != 6000 {
			t.Errorf("units = %d, want 6000", binary.LittleEndian.Uint32(instrs[0][1:]))
		}
		if instrs[1][0] != 0x03 {
			t.Errorf("price discriminator = %#x, want 0x03", instrs[1][0])
		}
		if binary.LittleEndian.Uint64(instrs[1][1:]) != 1000 {
			t.Errorf("price = %d, want 1000", binary.LittleEndian.Uint64(instrs[1][1:]))
		}
	})
}
