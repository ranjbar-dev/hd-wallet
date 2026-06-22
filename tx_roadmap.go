package hdwallet

// Roadmap stubs for transaction families not yet vector-verified. Each returns
// ErrTxRoadmap rather than a guessed builder: a wrong signature loses funds, so a
// family ships only once it reproduces a Trust Wallet Core AnySigner vector
// byte-for-byte. As each family is verified, its stub here is removed and the
// real builder lives in its own tx_<family>.go file.
//
// roadmap — Bitcoin (P2WPKH, BIP-143):
//
// The low-level building blocks are straightforward (a BIP-143 sighash over a
// 0014<hash> witness program, a witness-format serialization, and signing with
// the existing secp256k1 signer producing a DER signature). What is NOT yet
// pinned is byte-for-byte parity with Trust Wallet Core's AnySigner output:
// TWC runs a coin-selection PLAN (input selection, fee-per-byte sizing, change
// computation, output ordering and dust handling) before serializing, and its
// publicly documented test vectors either wrap P2SH-P2WPKH, use non-segwit
// (P2PK) input scripts, or have multiple plan-selected outputs. Without an
// unambiguous native-P2WPKH AnySigner vector to reproduce exactly, shipping a
// builder here would be a guess. It is therefore intentionally left
// unimplemented; see the skipped TestSignTxBitcoinP2WPKH for the missing vector.

import (
	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

func (w *HDWallet) signBitcoinTx(_ Symbol, _ uint32, _ *txbtc.SigningInput) (*txbtc.SigningOutput, error) {
	return nil, ErrTxRoadmap
}
