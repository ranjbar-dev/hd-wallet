package hdwallet

import (
	"fmt"
	"math/big"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// userOpV07Hash computes the ERC-4337 v0.7 userOperation hash (what to sign).
//
// v0.7 packs gas fields into 32-byte words:
//
//	accountGasLimits = verificationGasLimit(uint128,16B) || callGasLimit(uint128,16B)
//	gasFees          = maxPriorityFeePerGas(uint128,16B) || maxFeePerGas(uint128,16B)
//
// initCode bytes      = factory(20B) ++ factoryData  (or empty if no factory)
// paymasterAndData    = paymaster(20B) ++ pmVerGasLimit(16B) ++ pmPostOpGasLimit(16B) ++ pmData
//
//	(or empty if no paymaster)
//
// Inner hash = keccak256(abi.encode(
//
//	address(sender), uint256(nonce),
//	bytes32(keccak256(initCode)), bytes32(keccak256(callData)),
//	bytes32(accountGasLimits), uint256(preVerificationGas),
//	bytes32(gasFees), bytes32(keccak256(paymasterAndData))
//
// ))
// Outer hash = keccak256(abi.encode(bytes32(innerHash), address(entryPoint), uint256(chainID)))
func userOpV07Hash(
	sender, entryPoint []byte,
	nonce *big.Int,
	factory []byte, factoryData []byte,
	callData []byte,
	callGasLimit, verificationGasLimit, preVerificationGas *big.Int,
	maxFeePerGas, maxPriorityFeePerGas *big.Int,
	paymaster []byte,
	paymasterVerGasLimit, paymasterPostOpGasLimit *big.Int,
	paymasterData []byte,
	chainID *big.Int,
) []byte {
	// Build initCode: factory(20B) ++ factoryData, or empty.
	var initCode []byte
	if len(factory) == 20 {
		initCode = append(append([]byte(nil), factory...), factoryData...)
	}

	// Build paymasterAndData: paymaster(20B) ++ pmVerGas(16B) ++ pmPostOpGas(16B) ++ pmData, or empty.
	var paymasterAndData []byte
	if len(paymaster) == 20 {
		pmVer := uint128Bytes(paymasterVerGasLimit)
		pmPost := uint128Bytes(paymasterPostOpGasLimit)
		paymasterAndData = append(append(append(append([]byte(nil), paymaster...), pmVer...), pmPost...), paymasterData...)
	}

	// accountGasLimits: verificationGasLimit(16B big-endian) || callGasLimit(16B big-endian).
	accountGasLimits := append(uint128Bytes(verificationGasLimit), uint128Bytes(callGasLimit)...)

	// gasFees: maxPriorityFeePerGas(16B) || maxFeePerGas(16B).
	gasFees := append(uint128Bytes(maxPriorityFeePerGas), uint128Bytes(maxFeePerGas)...)

	// Inner ABI encoding.
	inner, _ := ABIEncodeParams([]ABIValue{
		{Type: "address", Value: sender},
		{Type: "uint256", Value: nonce},
		{Type: "bytes32", Value: keccak256(initCode)},
		{Type: "bytes32", Value: keccak256(callData)},
		{Type: "bytes32", Value: accountGasLimits},
		{Type: "uint256", Value: preVerificationGas},
		{Type: "bytes32", Value: gasFees},
		{Type: "bytes32", Value: keccak256(paymasterAndData)},
	})
	innerHash := keccak256(inner)

	outer, _ := ABIEncodeParams([]ABIValue{
		{Type: "bytes32", Value: innerHash},
		{Type: "address", Value: entryPoint},
		{Type: "uint256", Value: chainID},
	})
	return keccak256(outer)
}

// uint128Bytes returns n as a 16-byte big-endian unsigned integer (uint128).
// n must fit in 16 bytes; excess leading bytes are silently truncated.
func uint128Bytes(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 16 {
		return b[len(b)-16:]
	}
	out := make([]byte, 16)
	copy(out[16-len(b):], b)
	return out
}

// signEthereumUserOpV07 builds and signs an ERC-4337 v0.7 UserOperation.
// callData is built from the inner Transaction payload via SimpleAccount's
// execute(address,uint256,bytes). The v0.7 packed hash is signed with EIP-191.
// SigningOutput.Encoded = 65-byte signature; TxId = "0x" + v0.7 userOpHash hex.
func (w *HDWallet) signEthereumUserOpV07(chain Chain, index uint32, in *txeth.SigningInput) (*txeth.SigningOutput, error) {
	meta := in.GetUserOperationV0_7()
	if meta == nil {
		return nil, fmt.Errorf("%w: %s: user_operation_v0_7 required for tx_mode 6", ErrTxInput, chain)
	}
	sender, err := hexToBytes(meta.GetSender())
	if err != nil || len(sender) != 20 {
		return nil, fmt.Errorf("%w: %s: bad user_operation_v0_7.sender", ErrTxInput, chain)
	}
	entryPoint, err := hexToBytes(meta.GetEntryPoint())
	if err != nil || len(entryPoint) != 20 {
		return nil, fmt.Errorf("%w: %s: bad user_operation_v0_7.entry_point", ErrTxInput, chain)
	}
	// factory is optional (empty string = not deploying).
	var factory []byte
	if f := meta.GetFactory(); f != "" {
		factory, err = hexToBytes(f)
		if err != nil || len(factory) != 20 {
			return nil, fmt.Errorf("%w: %s: bad user_operation_v0_7.factory", ErrTxInput, chain)
		}
	}
	var paymaster []byte
	if p := meta.GetPaymaster(); p != "" {
		paymaster, err = hexToBytes(p)
		if err != nil || len(paymaster) != 20 {
			return nil, fmt.Errorf("%w: %s: bad user_operation_v0_7.paymaster", ErrTxInput, chain)
		}
	}

	// Build callData from inner Transaction.
	innerTo, innerValue, innerData, err := ethDestination(in)
	if err != nil {
		return nil, err
	}
	execSel := ABIFunctionSelector("execute", []string{"address", "uint256", "bytes"})
	innerBig := new(big.Int)
	if len(innerValue) > 0 {
		innerBig.SetBytes(innerValue)
	}
	callData := abiCalldata(execSel, []ABIValue{
		{Type: "address", Value: innerTo},
		{Type: "uint256", Value: innerBig},
		{Type: "bytes", Value: innerData},
	})

	chainID := new(big.Int).SetBytes(in.GetChainId())
	hash := userOpV07Hash(
		sender, entryPoint,
		new(big.Int).SetBytes(in.GetNonce()),
		factory, meta.GetFactoryData(),
		callData,
		new(big.Int).SetBytes(in.GetGasLimit()), // callGasLimit
		new(big.Int).SetBytes(meta.GetVerificationGasLimit()),
		new(big.Int).SetBytes(meta.GetPreVerificationGas()),
		new(big.Int).SetBytes(in.GetMaxFeePerGas()),
		new(big.Int).SetBytes(in.GetMaxInclusionFeePerGas()),
		paymaster,
		new(big.Int).SetBytes(meta.GetPaymasterVerificationGasLimit()),
		new(big.Int).SetBytes(meta.GetPaymasterPostOpGasLimit()),
		meta.GetPaymasterData(),
		chainID,
	)

	sig, err := w.SignMessage(chain, index, hash)
	if err != nil {
		return nil, err
	}
	return &txeth.SigningOutput{
		Encoded:    sig,
		R:          append([]byte(nil), sig[:32]...),
		S:          append([]byte(nil), sig[32:64]...),
		V:          sig[64:65],
		EncodedHex: bytesToHex(sig),
		TxId:       "0x" + bytesToHex(hash),
	}, nil
}
