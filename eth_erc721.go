package hdwallet

import "math/big"

// ERC-721 calldata builders. Selectors are computed once at package init.
var (
	erc721SelTransferFrom         = ABIFunctionSelector("transferFrom", []string{"address", "address", "uint256"})
	erc721SelSafeTransferFrom     = ABIFunctionSelector("safeTransferFrom", []string{"address", "address", "uint256"})
	erc721SelSafeTransferFromData = ABIFunctionSelector("safeTransferFrom", []string{"address", "address", "uint256", "bytes"})
	erc721SelApprove              = ABIFunctionSelector("approve", []string{"address", "uint256"})
	erc721SelSetApprovalForAll    = ABIFunctionSelector("setApprovalForAll", []string{"address", "bool"})
)

// abiCalldata prepends a 4-byte selector to ABIEncodeParams output.
// Returns nil only if the caller passes mismatched types; impossible for
// well-typed helpers in this package.
func abiCalldata(sel []byte, args []ABIValue) []byte {
	params, err := ABIEncodeParams(args)
	if err != nil {
		return nil
	}
	out := make([]byte, 4+len(params))
	copy(out, sel)
	copy(out[4:], params)
	return out
}

// ERC721TransferCalldata builds transferFrom(from, to, tokenId) calldata.
func ERC721TransferCalldata(from, to []byte, tokenID *big.Int) []byte {
	return abiCalldata(erc721SelTransferFrom, []ABIValue{
		{Type: "address", Value: from},
		{Type: "address", Value: to},
		{Type: "uint256", Value: tokenID},
	})
}

// ERC721SafeTransferCalldata builds safeTransferFrom(from, to, tokenId) calldata.
func ERC721SafeTransferCalldata(from, to []byte, tokenID *big.Int) []byte {
	return abiCalldata(erc721SelSafeTransferFrom, []ABIValue{
		{Type: "address", Value: from},
		{Type: "address", Value: to},
		{Type: "uint256", Value: tokenID},
	})
}

// ERC721SafeTransferWithDataCalldata builds safeTransferFrom(from, to, tokenId, data) calldata.
func ERC721SafeTransferWithDataCalldata(from, to []byte, tokenID *big.Int, data []byte) []byte {
	return abiCalldata(erc721SelSafeTransferFromData, []ABIValue{
		{Type: "address", Value: from},
		{Type: "address", Value: to},
		{Type: "uint256", Value: tokenID},
		{Type: "bytes", Value: data},
	})
}

// ERC721ApproveCalldata builds approve(to, tokenId) calldata.
func ERC721ApproveCalldata(to []byte, tokenID *big.Int) []byte {
	return abiCalldata(erc721SelApprove, []ABIValue{
		{Type: "address", Value: to},
		{Type: "uint256", Value: tokenID},
	})
}

// ERC721SetApprovalForAllCalldata builds setApprovalForAll(operator, approved) calldata.
func ERC721SetApprovalForAllCalldata(operator []byte, approved bool) []byte {
	return abiCalldata(erc721SelSetApprovalForAll, []ABIValue{
		{Type: "address", Value: operator},
		{Type: "bool", Value: approved},
	})
}
