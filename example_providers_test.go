package hdwallet_test

import (
	"fmt"
	"math/big"

	hdwallet "github.com/ranjbar-dev/hd-wallet"
	ethpb "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// staticNonceProvider is a trivial [hdwallet.NonceProvider] used in examples
// and tests. A production implementation calls eth_getTransactionCount (EVM),
// account_info (XRP), or /cosmos/auth/v1beta1/accounts (Cosmos).
type staticNonceProvider struct{ n uint64 }

func (p *staticNonceProvider) Nonce(_ string) (uint64, error) { return p.n, nil }

// ExampleNonceProvider demonstrates how a caller wires a [hdwallet.NonceProvider]
// into an EVM [ethpb.SigningInput] before calling [hdwallet.HDWallet.SignTransaction].
// In production, Nonce calls eth_getTransactionCount("pending") on an Ethereum
// node; the fake provider here returns a fixed value so the example is deterministic.
func ExampleNonceProvider() {
	// 1. Obtain chain state from your provider implementations.
	var nonces hdwallet.NonceProvider = &staticNonceProvider{n: 9}

	// 2. Derive the sender address from the wallet (not shown; see ExampleHDWallet_Address).
	senderAddr := "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

	nonce, err := nonces.Nonce(senderAddr)
	if err != nil {
		return
	}

	// 3. Build the SigningInput. All chain-state fields come from the providers;
	//    chain constants (chain_id) and transfer details are set directly.
	in := &ethpb.SigningInput{
		ChainId:  big.NewInt(1).Bytes(), // Ethereum mainnet
		Nonce:    big.NewInt(0).SetUint64(nonce).Bytes(),
		GasLimit: big.NewInt(21000).Bytes(),
		GasPrice: big.NewInt(20_000_000_000).Bytes(), // 20 gwei
		TxMode:   0,                                  // hdwallet.EthTxModeLegacy
		// ... set ToAddress, Transaction, etc.
	}

	// 4. Confirm the nonce is set correctly before passing to SignTransaction.
	fmt.Println(new(big.Int).SetBytes(in.Nonce).Uint64())
	// Output: 9
}
