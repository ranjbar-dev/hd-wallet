package hdwallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
)

// ERC-20 and EIP-2612 calldata builders + permit signer.
// Selectors are computed once at package init.
var (
	erc20SelApprove = ABIFunctionSelector("approve", []string{"address", "uint256"})
	erc20SelPermit  = ABIFunctionSelector("permit", []string{"address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"})
)

// ERC20ApproveCalldata builds approve(spender, amount) calldata.
func ERC20ApproveCalldata(spender []byte, amount *big.Int) []byte {
	return abiCalldata(erc20SelApprove, []ABIValue{
		{Type: "address", Value: spender},
		{Type: "uint256", Value: amount},
	})
}

// ERC20PermitCalldata builds permit(owner, spender, value, deadline, v, r, s) calldata for EIP-2612.
func ERC20PermitCalldata(owner, spender []byte, value, deadline *big.Int, v uint8, r, s [32]byte) []byte {
	return abiCalldata(erc20SelPermit, []ABIValue{
		{Type: "address", Value: owner},
		{Type: "address", Value: spender},
		{Type: "uint256", Value: value},
		{Type: "uint256", Value: deadline},
		{Type: "uint8", Value: new(big.Int).SetUint64(uint64(v))},
		{Type: "bytes32", Value: r[:]},
		{Type: "bytes32", Value: s[:]},
	})
}

// SignERC20Permit signs an EIP-2612 permit for tokenAddr on chainID.
// tokenName is the token contract's name() used in the EIP-712 domain separator.
// The owner is derived from the wallet's key at chain/index.
// Returns (v, r, s) ready for ERC20PermitCalldata.
func (w *HDWallet) SignERC20Permit(
	chain Chain,
	index uint32,
	chainID *big.Int,
	tokenAddr []byte,
	tokenName string,
	spender []byte,
	value, nonce, deadline *big.Int,
) (v uint8, r, s [32]byte, err error) {
	owner, err := w.AddressIndex(chain, index)
	if err != nil {
		return
	}
	td, err := eip2612TypedData(chainID, tokenAddr, tokenName, owner, spender, value, nonce, deadline)
	if err != nil {
		return
	}
	sig, err := w.SignTypedData(chain, index, td)
	if err != nil {
		return
	}
	v = sig[64]
	copy(r[:], sig[:32])
	copy(s[:], sig[32:64])
	return
}

type eip712Member struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// eip2612TypedData builds the MetaMask-shape EIP-712 JSON for an EIP-2612 Permit.
func eip2612TypedData(chainID *big.Int, tokenAddr []byte, tokenName, owner string, spender []byte, value, nonce, deadline *big.Int) ([]byte, error) {
	td := map[string]any{
		"types": map[string][]eip712Member{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Permit": {
				{Name: "owner", Type: "address"},
				{Name: "spender", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "nonce", Type: "uint256"},
				{Name: "deadline", Type: "uint256"},
			},
		},
		"primaryType": "Permit",
		"domain": map[string]string{
			"name":              tokenName,
			"version":           "1",
			"chainId":           chainID.String(),
			"verifyingContract": fmt.Sprintf("0x%s", hex.EncodeToString(tokenAddr)),
		},
		"message": map[string]string{
			"owner":    owner,
			"spender":  fmt.Sprintf("0x%s", hex.EncodeToString(spender)),
			"value":    value.String(),
			"nonce":    nonce.String(),
			"deadline": deadline.String(),
		},
	}
	return json.Marshal(td)
}
