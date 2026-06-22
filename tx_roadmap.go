package hdwallet

// Roadmap stubs for transaction families not yet vector-verified. Each returns
// ErrTxRoadmap rather than a guessed builder: a wrong signature loses funds, so a
// family ships only once it reproduces a Trust Wallet Core AnySigner vector
// byte-for-byte. As each family is verified, its stub here is removed and the
// real builder lives in its own tx_<family>.go file.

import (
	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

func (w *HDWallet) signBitcoinTx(_ Symbol, _ uint32, _ *txbtc.SigningInput) (*txbtc.SigningOutput, error) {
	return nil, ErrTxRoadmap
}
