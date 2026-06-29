package hdwallet

// Tests for the SIGHASH flag implementation: NONE, SINGLE, ANYONECANPAY and
// combinations thereof, for both BIP-143 (P2WPKH) and legacy (P2PKH) inputs.
//
// Each non-ALL path is pinned byte-for-byte to btcd's txscript signer — ECDSA
// RFC-6979 is deterministic so byte identity is the correct assertion.
// See tx_bitcoin_test.go for shared helpers (btcWalletKey, mustHex, etc.).

import (
	"bytes"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// TestSigHashFlagsP2WPKH verifies that NONE (0x02), SINGLE (0x03),
// ANYONECANPAY|ALL (0x81) and SINGLE|ANYONECANPAY (0x83) each produce a
// witness signature that is byte-identical to btcd's RawTxInWitnessSignature
// for the same tx and hash type.
func TestSigHashFlagsP2WPKH(t *testing.T) {
	cases := []struct {
		name     string
		hashType uint32
		btcdType txscript.SigHashType
	}{
		{"NONE", SigHashNone, txscript.SigHashNone},
		{"SINGLE", SigHashSingle, txscript.SigHashSingle},
		{"ANYONECANPAY_ALL", SigHashAll | SigHashAnyoneCanPay, txscript.SigHashAll | txscript.SigHashAnyOneCanPay},
		{"SINGLE_ANYONECANPAY", SigHashSingle | SigHashAnyoneCanPay, txscript.SigHashSingle | txscript.SigHashAnyOneCanPay},
	}

	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	// P2WPKH UTXO controlled by key index 0.
	utxoScript := append([]byte{0x00, 0x14}, btcutil.Hash160(pub)...)

	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	privKey := btcWalletKey(t, w)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := &txbtc.SigningInput{
				HashType:      tc.hashType,
				Amount:        1500,
				ByteFee:       1,
				ToAddress:     to,
				ChangeAddress: change,
				Utxo: []*txbtc.UnspentTransaction{{
					OutPointHash:     mustHex(t, dummyPrevTxid),
					OutPointIndex:    0,
					OutPointSequence: 0xffffffff,
					Amount:           10000,
					Script:           utxoScript,
				}},
			}

			outMsg, err := w.SignTransaction(BTC, 0, in)
			if err != nil {
				t.Fatalf("SignTransaction: %v", err)
			}
			out := outMsg.(*txbtc.SigningOutput)

			// Deserialize the signed tx so the oracle can operate on the same
			// wire structure (inputs/outputs/sequences already set).
			var msg wire.MsgTx
			if err := msg.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
				t.Fatalf("wire.Deserialize: %v", err)
			}

			// Build the prevout fetcher and sig-hash cache for btcd.
			prevOuts := make(map[wire.OutPoint]*wire.TxOut)
			for _, u := range in.Utxo {
				var h chainhash.Hash
				copy(h[:], u.GetOutPointHash())
				prevOuts[wire.OutPoint{Hash: h, Index: u.GetOutPointIndex()}] = wire.NewTxOut(u.GetAmount(), u.GetScript())
			}
			fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
			sigHashes := txscript.NewTxSigHashes(&msg, fetcher)

			for i := range msg.TxIn {
				prevOut := prevOuts[msg.TxIn[i].PreviousOutPoint]
				// RawTxInWitnessSignature returns the DER sig with hash-type byte appended,
				// which is exactly witness[0] for a P2WPKH input.
				oracleSig, err := txscript.RawTxInWitnessSignature(
					&msg, sigHashes, i, prevOut.Value, prevOut.PkScript, tc.btcdType, privKey,
				)
				if err != nil {
					t.Fatalf("input %d: RawTxInWitnessSignature: %v", i, err)
				}
				ourSig := msg.TxIn[i].Witness[0]
				if !bytes.Equal(ourSig, oracleSig) {
					t.Fatalf("input %d witness sig mismatch\n got:  %x\nwant: %x", i, ourSig, oracleSig)
				}
			}
		})
	}
}

// TestSigHashFlagsP2PKH verifies that the legacy (pre-segwit) sighash masking
// for NONE and SINGLE produces a scriptSig that is byte-identical to btcd's
// SignatureScript with the same hash type.
func TestSigHashFlagsP2PKH(t *testing.T) {
	cases := []struct {
		name     string
		hashType uint32
		btcdType txscript.SigHashType
	}{
		{"NONE", SigHashNone, txscript.SigHashNone},
		{"SINGLE", SigHashSingle, txscript.SigHashSingle},
	}

	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	// Legacy P2PKH UTXO controlled by key index 0.
	utxoScript := append(append([]byte{0x76, 0xa9, 0x14}, btcutil.Hash160(pub)...), 0x88, 0xac)

	to, _ := w.BitcoinAddress(BTC, P2PKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2PKH, 0, 1, 0)

	privKey := btcWalletKey(t, w)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := &txbtc.SigningInput{
				HashType:      tc.hashType,
				Amount:        1500,
				ByteFee:       1,
				ToAddress:     to,
				ChangeAddress: change,
				Utxo: []*txbtc.UnspentTransaction{{
					OutPointHash:     mustHex(t, dummyPrevTxid),
					OutPointIndex:    0,
					OutPointSequence: 0xffffffff,
					Amount:           10000,
					Script:           utxoScript,
				}},
			}

			outMsg, err := w.SignTransaction(BTC, 0, in)
			if err != nil {
				t.Fatalf("SignTransaction: %v", err)
			}
			out := outMsg.(*txbtc.SigningOutput)

			var msg wire.MsgTx
			if err := msg.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
				t.Fatalf("wire.Deserialize: %v", err)
			}

			for i := range msg.TxIn {
				// SignatureScript builds push(sig) push(pub) using btcd's legacy sighash
				// — the same algorithm as our legacySighash with the same hash type.
				wantScriptSig, err := txscript.SignatureScript(&msg, i, utxoScript, tc.btcdType, privKey, true)
				if err != nil {
					t.Fatalf("input %d: oracle SignatureScript: %v", i, err)
				}
				if !bytes.Equal(msg.TxIn[i].SignatureScript, wantScriptSig) {
					t.Fatalf("input %d scriptSig mismatch\n got:  %x\nwant: %x",
						i, msg.TxIn[i].SignatureScript, wantScriptSig)
				}
			}
		})
	}
}

// TestSigHashSingleEdgeCase asserts that signing a P2PKH input with
// SIGHASH_SINGLE when the input's index is >= the output count returns
// ErrTxInput. The legacy sighash has no valid encoding for this case —
// unlike BIP-143 which specifies hashOutputs = 32 zero bytes.
//
// Setup: two P2PKH UTXOs + UseMaxAmount (exactly 1 output, no change).
// When signing input[1] (idx=1), idx=1 >= len(outputs)=1 → ErrTxInput.
func TestSigHashSingleEdgeCase(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	utxoScript := append(append([]byte{0x76, 0xa9, 0x14}, btcutil.Hash160(pub)...), 0x88, 0xac)
	to, _ := w.BitcoinAddress(BTC, P2PKH, 0, 0, 1)

	_, err = w.SignTransaction(BTC, 0, &txbtc.SigningInput{
		HashType:     SigHashSingle,
		UseMaxAmount: true,
		ByteFee:      1,
		ToAddress:    to,
		Utxo: []*txbtc.UnspentTransaction{
			{
				OutPointHash:     mustHex(t, dummyPrevTxid),
				OutPointIndex:    0,
				OutPointSequence: 0xffffffff,
				Amount:           5000,
				Script:           utxoScript,
			},
			{
				OutPointHash:     mustHex(t, "2222222222222222222222222222222222222222222222222222222222222222"),
				OutPointIndex:    0,
				OutPointSequence: 0xffffffff,
				Amount:           5000,
				Script:           utxoScript,
			},
		},
	})
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("SIGHASH_SINGLE edge case: got error %v, want ErrTxInput", err)
	}
}
