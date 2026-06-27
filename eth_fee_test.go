package hdwallet

import (
	"testing"

	"github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

func TestEthGasLimit(t *testing.T) {
	tests := []struct {
		name string
		in   *ethereum.SigningInput
		want uint64
	}{
		{
			name: "nil input",
			in:   nil,
			want: 21000,
		},
		{
			name: "native ETH transfer (no data, has to_address)",
			in: &ethereum.SigningInput{
				ToAddress:   "0xdeadbeef",
				Transaction: &ethereum.Transaction{},
			},
			want: 21000,
		},
		{
			name: "contract deploy (empty to_address)",
			in: &ethereum.SigningInput{
				ToAddress: "",
				Transaction: &ethereum.Transaction{
					TransactionOneof: &ethereum.Transaction_ContractGeneric_{
						ContractGeneric: &ethereum.Transaction_ContractGeneric{
							Data: make([]byte, 100),
						},
					},
				},
			},
			want: 32000 + 200*100,
		},
		{
			name: "ERC-20 transfer selector",
			in: &ethereum.SigningInput{
				ToAddress: "0xtoken",
				Transaction: &ethereum.Transaction{
					TransactionOneof: &ethereum.Transaction_ContractGeneric_{
						ContractGeneric: &ethereum.Transaction_ContractGeneric{
							// transfer(address,uint256) selector = 0xa9059cbb
							Data: []byte{0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x00},
						},
					},
				},
			},
			want: 65000,
		},
		{
			name: "ERC-721 transferFrom selector",
			in: &ethereum.SigningInput{
				ToAddress: "0xnft",
				Transaction: &ethereum.Transaction{
					TransactionOneof: &ethereum.Transaction_ContractGeneric_{
						ContractGeneric: &ethereum.Transaction_ContractGeneric{
							Data: []byte{0x23, 0xb8, 0x72, 0xdd, 0x00, 0x00},
						},
					},
				},
			},
			want: 85000,
		},
		{
			name: "approve selector",
			in: &ethereum.SigningInput{
				ToAddress: "0xtoken",
				Transaction: &ethereum.Transaction{
					TransactionOneof: &ethereum.Transaction_ContractGeneric_{
						ContractGeneric: &ethereum.Transaction_ContractGeneric{
							Data: []byte{0x09, 0x5e, 0xa7, 0xb3, 0x00, 0x00},
						},
					},
				},
			},
			want: 46000,
		},
		{
			name: "unknown calldata (1 non-zero byte)",
			in: &ethereum.SigningInput{
				ToAddress: "0xcontract",
				Transaction: &ethereum.Transaction{
					TransactionOneof: &ethereum.Transaction_ContractGeneric_{
						ContractGeneric: &ethereum.Transaction_ContractGeneric{
							Data: []byte{0xff, 0xff, 0xff, 0xff, 0x01},
						},
					},
				},
			},
			// 21000 + 5*16 + 10000 = 31080
			want: 21000 + 5*16 + 10000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EthGasLimit(tc.in)
			if got != tc.want {
				t.Errorf("EthGasLimit() = %d, want %d", got, tc.want)
			}
		})
	}
}
