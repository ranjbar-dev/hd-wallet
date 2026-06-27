package hdwallet

import "math/big"

// ERC-1155 calldata builders. Selectors are computed once at package init.
var (
	erc1155SelSafeTransferFrom      = ABIFunctionSelector("safeTransferFrom", []string{"address", "address", "uint256", "uint256", "bytes"})
	erc1155SelSafeBatchTransferFrom = ABIFunctionSelector("safeBatchTransferFrom", []string{"address", "address", "uint256[]", "uint256[]", "bytes"})
	erc1155SelSetApprovalForAll     = ABIFunctionSelector("setApprovalForAll", []string{"address", "bool"})
)

// ERC1155SafeTransferCalldata builds safeTransferFrom(from, to, id, amount, data) calldata.
func ERC1155SafeTransferCalldata(from, to []byte, id, amount *big.Int, data []byte) []byte {
	return abiCalldata(erc1155SelSafeTransferFrom, []ABIValue{
		{Type: "address", Value: from},
		{Type: "address", Value: to},
		{Type: "uint256", Value: id},
		{Type: "uint256", Value: amount},
		{Type: "bytes", Value: data},
	})
}

// ERC1155SafeBatchTransferCalldata builds safeBatchTransferFrom(from, to, ids, amounts, data) calldata.
func ERC1155SafeBatchTransferCalldata(from, to []byte, ids, amounts []*big.Int, data []byte) []byte {
	idVals := make([]ABIValue, len(ids))
	for i, id := range ids {
		idVals[i] = ABIValue{Type: "uint256", Value: id}
	}
	amtVals := make([]ABIValue, len(amounts))
	for i, a := range amounts {
		amtVals[i] = ABIValue{Type: "uint256", Value: a}
	}
	return abiCalldata(erc1155SelSafeBatchTransferFrom, []ABIValue{
		{Type: "address", Value: from},
		{Type: "address", Value: to},
		{Type: "uint256[]", Value: idVals},
		{Type: "uint256[]", Value: amtVals},
		{Type: "bytes", Value: data},
	})
}

// ERC1155SetApprovalForAllCalldata builds setApprovalForAll(operator, approved) calldata.
func ERC1155SetApprovalForAllCalldata(operator []byte, approved bool) []byte {
	return abiCalldata(erc1155SelSetApprovalForAll, []ABIValue{
		{Type: "address", Value: operator},
		{Type: "bool", Value: approved},
	})
}
