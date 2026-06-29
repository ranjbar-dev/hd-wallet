package hdwallet

// TestSignTxBitcoinMultiKey exercises the per-UTXO key_index feature: a single
// transaction spends two P2WPKH UTXOs controlled by derivation index 0 and 1
// respectively. The tx is signed with tx-level index=0; UTXO[1] overrides with
// key_index=1. The oracle re-signs each input individually with the correct
// per-input private key and asserts byte-identical witness signatures.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// TestSignTxBitcoinMultiKey signs a 2-input P2WPKH tx where the two inputs are
// controlled by different derivation indices (0 and 1) of the same wallet.
func TestSignTxBitcoinMultiKey(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub0, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex(0): %v", err)
	}
	pub1, err := w.PublicKeyIndex(BTC, 1)
	if err != nil {
		t.Fatalf("PublicKeyIndex(1): %v", err)
	}

	script0 := p2wpkhScript(pub0) // controlled by index 0
	script1 := p2wpkhScript(pub1) // controlled by index 1

	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 2)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	keyIndex1 := uint32(1)
	in := &txbtc.SigningInput{
		HashType:      0x01,
		Amount:        5000,
		ByteFee:       1,
		ToAddress:     to,
		ChangeAddress: change,
		// Each UTXO is 3500 sat; neither alone covers 5000 + fee, so both are selected.
		Utxo: []*txbtc.UnspentTransaction{
			{
				// UTXO 0: no key_index set → uses tx-level index=0
				OutPointHash:     mustHex(t, dummyPrevTxid),
				OutPointIndex:    0,
				OutPointSequence: 0xffffffff,
				Amount:           3500,
				Script:           script0,
			},
			{
				// UTXO 1: explicit key_index=1
				OutPointHash:     mustHex(t, "2222222222222222222222222222222222222222222222222222222222222222"),
				OutPointIndex:    1,
				OutPointSequence: 0xffffffff,
				Amount:           3500,
				Script:           script1,
				KeyIndex:         &keyIndex1,
			},
		},
	}

	outMsg, err := w.SignTransaction(BTC, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	out := outMsg.(*txbtc.SigningOutput)

	// Deserialize the signed transaction.
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
		t.Fatalf("wire.MsgTx.Deserialize: %v", err)
	}

	if len(msg.TxIn) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(msg.TxIn))
	}

	// Build the prevout fetcher for both UTXOs.
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for _, u := range in.Utxo {
		var h chainhash.Hash
		copy(h[:], u.GetOutPointHash())
		prevOuts[wire.OutPoint{Hash: h, Index: u.GetOutPointIndex()}] = wire.NewTxOut(u.GetAmount(), u.GetScript())
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(&msg, fetcher)

	// Extract the private keys for both indices.
	var priv0, priv1 *btcec.PrivateKey
	if err := w.WithPrivateKey(BTC, 0, func(raw []byte) error {
		priv0, _ = btcec.PrivKeyFromBytes(raw)
		return nil
	}); err != nil {
		t.Fatalf("WithPrivateKey(0): %v", err)
	}
	if err := w.WithPrivateKey(BTC, 1, func(raw []byte) error {
		priv1, _ = btcec.PrivKeyFromBytes(raw)
		return nil
	}); err != nil {
		t.Fatalf("WithPrivateKey(1): %v", err)
	}

	// Oracle re-sign: input 0 uses priv0, input 1 uses priv1.
	privByInput := []*btcec.PrivateKey{priv0, priv1}
	for i := range msg.TxIn {
		prevOut := prevOuts[msg.TxIn[i].PreviousOutPoint]
		oracleWit, err := txscript.RawTxInWitnessSignature(
			&msg, sigHashes, i, prevOut.Value, prevOut.PkScript,
			txscript.SigHashAll, privByInput[i],
		)
		if err != nil {
			t.Fatalf("input %d: oracle RawTxInWitnessSignature: %v", i, err)
		}

		// The ours witness[0] must be byte-identical to the oracle's DER+hashtype sig.
		ourSig := msg.TxIn[i].Witness[0]
		if !bytes.Equal(ourSig, oracleWit) {
			t.Fatalf("input %d: witness[0] mismatch\n got: %x\nwant: %x", i, ourSig, oracleWit)
		}
	}
}

// TestSignTxBitcoinMultiKeyMismatch asserts that a UTXO whose scriptPubKey does
// not match the signing key resolved for it returns ErrTxInput. Specifically:
// UTXO[0] has script1 (keyed to index 1) but no explicit key_index, so the
// signer attempts to use tx-level index=0 — whose hash160 does not match.
func TestSignTxBitcoinMultiKeyMismatch(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub1, err := w.PublicKeyIndex(BTC, 1)
	if err != nil {
		t.Fatalf("PublicKeyIndex(1): %v", err)
	}
	// script1 is controlled by index 1, but we'll present it without key_index
	// so the signer will try index 0 — mismatch.
	script1 := p2wpkhScript(pub1)

	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 2)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	in := &txbtc.SigningInput{
		HashType:      0x01,
		Amount:        3000,
		ByteFee:       1,
		ToAddress:     to,
		ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash:     mustHex(t, dummyPrevTxid),
			OutPointIndex:    0,
			OutPointSequence: 0xffffffff,
			Amount:           8000,
			Script:           script1, // keyed to index 1
			// no KeyIndex set → signer will use tx-level index=0 → mismatch
		}},
	}

	_, err = w.SignTransaction(BTC, 0, in)
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("expected ErrTxInput for key mismatch, got: %v", err)
	}
}
