package hdwallet

import (
	"github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// knownSelectorGas maps 4-byte ABI selectors to their typical gas cost.
var knownSelectorGas = map[[4]byte]uint64{
	{0xa9, 0x05, 0x9c, 0xbb}: 65000, // ERC-20 transfer(address,uint256)
	{0x23, 0xb8, 0x72, 0xdd}: 85000, // ERC-721 transferFrom(address,address,uint256)
	{0x09, 0x5e, 0xa7, 0xb3}: 46000, // ERC-20 approve(address,uint256)
}

// EthGasLimit returns a conservative gas limit estimate for the given signing input.
// Native transfers return exactly 21000. Known selectors return the table value.
// Contract deploys and generic calls use calldata cost + headroom.
func EthGasLimit(in *ethereum.SigningInput) uint64 {
	if in == nil {
		return 21000
	}

	// Contract deploy: empty to_address.
	if in.GetToAddress() == "" {
		data := calldataFromEthTx(in)
		return 32000 + 200*uint64(len(data))
	}

	data := calldataFromEthTx(in)
	if len(data) == 0 {
		return 21000
	}

	if len(data) >= 4 {
		var sel [4]byte
		copy(sel[:], data[:4])
		if gas, ok := knownSelectorGas[sel]; ok {
			return gas
		}
	}

	return 21000 + calldataGas(data) + 10000
}

func calldataFromEthTx(in *ethereum.SigningInput) []byte {
	if t := in.GetTransaction(); t != nil {
		if g := t.GetContractGeneric(); g != nil {
			return g.GetData()
		}
		if tr := t.GetTransfer(); tr != nil {
			return tr.GetData()
		}
	}
	return nil
}

func calldataGas(data []byte) uint64 {
	var gas uint64
	for _, b := range data {
		if b == 0 {
			gas += 4
		} else {
			gas += 16
		}
	}
	return gas
}
