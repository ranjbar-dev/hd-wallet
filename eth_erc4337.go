package hdwallet

import "math/big"

// UserOperation is the ERC-4337 v0.6 struct submitted to the EntryPoint.
type UserOperation struct {
	Sender               []byte   // 20-byte address
	Nonce                *big.Int
	InitCode             []byte
	CallData             []byte
	CallGasLimit         *big.Int
	VerificationGasLimit *big.Int
	PreVerificationGas   *big.Int
	MaxFeePerGas         *big.Int
	MaxPriorityFeePerGas *big.Int
	PaymasterAndData     []byte
	Signature            []byte
}

// UserOperationHash computes the ERC-4337 v0.6 userOp hash (the value to sign).
//
// Inner hash: keccak256(abi.encode(sender, nonce, keccak256(initCode),
// keccak256(callData), callGasLimit, verificationGasLimit, preVerificationGas,
// maxFeePerGas, maxPriorityFeePerGas, keccak256(paymasterAndData)))
//
// Outer hash: keccak256(abi.encode(innerHash, entryPoint, chainID))
func UserOperationHash(op *UserOperation, entryPoint []byte, chainID *big.Int) []byte {
	inner, _ := ABIEncodeParams([]ABIValue{
		{Type: "address", Value: op.Sender},
		{Type: "uint256", Value: op.Nonce},
		{Type: "bytes32", Value: keccak256(op.InitCode)},
		{Type: "bytes32", Value: keccak256(op.CallData)},
		{Type: "uint256", Value: op.CallGasLimit},
		{Type: "uint256", Value: op.VerificationGasLimit},
		{Type: "uint256", Value: op.PreVerificationGas},
		{Type: "uint256", Value: op.MaxFeePerGas},
		{Type: "uint256", Value: op.MaxPriorityFeePerGas},
		{Type: "bytes32", Value: keccak256(op.PaymasterAndData)},
	})
	innerHash := keccak256(inner)
	outer, _ := ABIEncodeParams([]ABIValue{
		{Type: "bytes32", Value: innerHash},
		{Type: "address", Value: entryPoint},
		{Type: "uint256", Value: chainID},
	})
	return keccak256(outer)
}

// SignUserOperation signs op via EIP-191 personal_sign over its hash, sets
// op.Signature, and returns the 65-byte r‖s‖v recoverable signature.
func (w *HDWallet) SignUserOperation(
	symbol Symbol,
	index uint32,
	op *UserOperation,
	entryPoint []byte,
	chainID *big.Int,
) ([]byte, error) {
	hash := UserOperationHash(op, entryPoint, chainID)
	sig, err := w.SignMessage(symbol, index, hash)
	if err != nil {
		return nil, err
	}
	op.Signature = sig
	return sig, nil
}
