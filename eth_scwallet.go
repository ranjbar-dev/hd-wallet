package hdwallet

import (
	"fmt"
	"math/big"
)

// scWalletExecuteCalldata builds the execute() calldata for a single inner call
// on a smart-contract wallet of the given type.
//
//   - SC_SIMPLE_ACCOUNT (0): execute(address,uint256,bytes)
//   - BIZ_4337 (1): executeBatch(address[],bytes[]) with one element
//   - BIZ (2): executeBatch(address[],uint256[],bytes[]) with one element
func scWalletExecuteCalldata(walletType int32, to []byte, value *big.Int, data []byte) ([]byte, error) {
	switch walletType {
	case 0: // SC_SIMPLE_ACCOUNT — execute(address,uint256,bytes)
		return ABIEncode("execute", []ABIValue{
			{Type: "address", Value: to},
			{Type: "uint256", Value: value},
			{Type: "bytes", Value: data},
		})
	case 1: // BIZ_4337 — executeBatch(address[],bytes[])
		return ABIEncode("executeBatch", []ABIValue{
			{Type: "address[]", Value: []ABIValue{{Type: "address", Value: to}}},
			{Type: "bytes[]", Value: []ABIValue{{Type: "bytes", Value: data}}},
		})
	case 2: // BIZ — executeBatch(address[],uint256[],bytes[])
		return ABIEncode("executeBatch", []ABIValue{
			{Type: "address[]", Value: []ABIValue{{Type: "address", Value: to}}},
			{Type: "uint256[]", Value: []ABIValue{{Type: "uint256", Value: value}}},
			{Type: "bytes[]", Value: []ABIValue{{Type: "bytes", Value: data}}},
		})
	default:
		return nil, fmt.Errorf("hdwallet: unknown SCWalletType %d", walletType)
	}
}

// scWalletBatchCalldata builds the executeBatch() calldata for a batch of calls.
//
//   - SC_SIMPLE_ACCOUNT (0): executeBatch(address[],uint256[],bytes[])
//   - BIZ_4337 (1): executeBatch(address[],bytes[])
//   - BIZ (2): executeBatch(address[],uint256[],bytes[])
func scWalletBatchCalldata(walletType int32, addrs [][]byte, values []*big.Int, datas [][]byte) ([]byte, error) {
	n := len(addrs)
	addrElems := make([]ABIValue, n)
	dataElems := make([]ABIValue, n)
	for i := range addrs {
		addrElems[i] = ABIValue{Type: "address", Value: addrs[i]}
		dataElems[i] = ABIValue{Type: "bytes", Value: datas[i]}
	}

	switch walletType {
	case 0, 2: // SC_SIMPLE_ACCOUNT / BIZ — executeBatch(address[],uint256[],bytes[])
		valElems := make([]ABIValue, n)
		for i, v := range values {
			valElems[i] = ABIValue{Type: "uint256", Value: v}
		}
		return ABIEncode("executeBatch", []ABIValue{
			{Type: "address[]", Value: addrElems},
			{Type: "uint256[]", Value: valElems},
			{Type: "bytes[]", Value: dataElems},
		})
	case 1: // BIZ_4337 — executeBatch(address[],bytes[])
		return ABIEncode("executeBatch", []ABIValue{
			{Type: "address[]", Value: addrElems},
			{Type: "bytes[]", Value: dataElems},
		})
	default:
		return nil, fmt.Errorf("hdwallet: unknown SCWalletType %d", walletType)
	}
}
