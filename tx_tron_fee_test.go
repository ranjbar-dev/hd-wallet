package hdwallet

import (
	"testing"

	"github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

func TestTronBandwidth(t *testing.T) {
	tests := []struct {
		name string
		in   *tron.SigningInput
		want int64
	}{
		{"nil", nil, 268},
		{
			"TRX transfer",
			&tron.SigningInput{
				Transaction: &tron.Transaction{
					ContractOneof: &tron.Transaction_Transfer{
						Transfer: &tron.TransferContract{Amount: 1000000},
					},
				},
			},
			268,
		},
		{
			"TRC-20 transfer",
			&tron.SigningInput{
				Transaction: &tron.Transaction{
					ContractOneof: &tron.Transaction_TransferTrc20{
						TransferTrc20: &tron.TransferTRC20Contract{},
					},
				},
			},
			268,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TronBandwidth(tc.in)
			if got != tc.want {
				t.Errorf("TronBandwidth() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestTronEnergy(t *testing.T) {
	tests := []struct {
		name string
		in   *tron.SigningInput
		want int64
	}{
		{"nil", nil, 0},
		{
			"TRX transfer → 0 energy",
			&tron.SigningInput{
				Transaction: &tron.Transaction{
					ContractOneof: &tron.Transaction_Transfer{
						Transfer: &tron.TransferContract{Amount: 1000000},
					},
				},
			},
			0,
		},
		{
			"TRC-20 transfer → 65000 energy",
			&tron.SigningInput{
				Transaction: &tron.Transaction{
					ContractOneof: &tron.Transaction_TransferTrc20{
						TransferTrc20: &tron.TransferTRC20Contract{},
					},
				},
			},
			65000,
		},
		{
			"TRC-10 asset transfer → 0 energy",
			&tron.SigningInput{
				Transaction: &tron.Transaction{
					ContractOneof: &tron.Transaction_TransferAsset{
						TransferAsset: &tron.TransferAssetContract{},
					},
				},
			},
			0,
		},
		{
			"FreezeBalanceV2 → 100000 energy (generic contract)",
			&tron.SigningInput{
				Transaction: &tron.Transaction{
					ContractOneof: &tron.Transaction_FreezeBalanceV2{
						FreezeBalanceV2: &tron.FreezeBalanceV2Contract{},
					},
				},
			},
			100000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TronEnergy(tc.in)
			if got != tc.want {
				t.Errorf("TronEnergy() = %d, want %d", got, tc.want)
			}
		})
	}
}
