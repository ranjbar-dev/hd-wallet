package hdwallet

// Roadmap stubs for transaction families not yet vector-verified. Each returns
// ErrTxRoadmap rather than a guessed builder: a wrong signature loses funds, so a
// family ships only once it reproduces a Trust Wallet Core AnySigner vector
// byte-for-byte. As each family is verified, its stub here is removed and the
// real builder lives in its own tx_<family>.go file.

import (
	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

func (w *HDWallet) signRippleTx(_ Symbol, _ uint32, _ *txripple.SigningInput) (*txripple.SigningOutput, error) {
	return nil, ErrTxRoadmap
}

func (w *HDWallet) signCosmosTx(_ Symbol, _ uint32, _ *txcosmos.SigningInput) (*txcosmos.SigningOutput, error) {
	return nil, ErrTxRoadmap
}

func (w *HDWallet) signSolanaTx(_ Symbol, _ uint32, _ *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	return nil, ErrTxRoadmap
}

func (w *HDWallet) signBitcoinTx(_ Symbol, _ uint32, _ *txbtc.SigningInput) (*txbtc.SigningOutput, error) {
	return nil, ErrTxRoadmap
}
