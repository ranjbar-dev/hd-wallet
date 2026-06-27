package hdwallet

import (
	"testing"

	"github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

func TestCosmosGasLimit(t *testing.T) {
	tests := []struct {
		name string
		in   *cosmos.SigningInput
		want uint64
	}{
		{"nil", nil, 80000},
		{
			"single MsgSend via Send field",
			&cosmos.SigningInput{Send: &cosmos.SendCoinsMessage{}},
			80000,
		},
		{
			"single MsgSend via Messages",
			&cosmos.SigningInput{
				Messages: []*cosmos.Message{
					{MessageOneof: &cosmos.Message_Send{Send: &cosmos.SendCoinsMessage{}}},
				},
			},
			80000,
		},
		{
			"MsgDelegate",
			&cosmos.SigningInput{
				Messages: []*cosmos.Message{
					{MessageOneof: &cosmos.Message_Delegate{Delegate: &cosmos.MsgDelegate{}}},
				},
			},
			200000,
		},
		{
			"MsgUndelegate",
			&cosmos.SigningInput{
				Messages: []*cosmos.Message{
					{MessageOneof: &cosmos.Message_Undelegate{Undelegate: &cosmos.MsgDelegate{}}},
				},
			},
			200000,
		},
		{
			"MsgWithdrawReward",
			&cosmos.SigningInput{
				Messages: []*cosmos.Message{
					{MessageOneof: &cosmos.Message_WithdrawReward{WithdrawReward: &cosmos.MsgWithdrawReward{}}},
				},
			},
			150000,
		},
		{
			"two messages: send + delegate",
			&cosmos.SigningInput{
				Messages: []*cosmos.Message{
					{MessageOneof: &cosmos.Message_Send{Send: &cosmos.SendCoinsMessage{}}},
					{MessageOneof: &cosmos.Message_Delegate{Delegate: &cosmos.MsgDelegate{}}},
				},
			},
			80000 + 200000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CosmosGasLimit(tc.in)
			if got != tc.want {
				t.Errorf("CosmosGasLimit() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCosmosMinFee(t *testing.T) {
	tests := []struct {
		gas   uint64
		price float64
		denom string
		want  string
	}{
		{80000, 0.005, "uatom", "400uatom"},
		{200000, 0.0025, "uosmo", "500uosmo"},
		{150000, 0.001, "ujuno", "150ujuno"},
		// ceil: 80000 * 0.005 = 400 exactly
		{80001, 0.005, "uatom", "401uatom"},
	}

	for _, tc := range tests {
		got := CosmosMinFee(tc.gas, tc.price, tc.denom)
		if got != tc.want {
			t.Errorf("CosmosMinFee(%d, %v, %q) = %q, want %q", tc.gas, tc.price, tc.denom, got, tc.want)
		}
	}
}
