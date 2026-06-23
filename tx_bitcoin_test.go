package hdwallet

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// dummyPrevTxid is an arbitrary 32-byte previous-output txid (internal order).
const dummyPrevTxid = "1111111111111111111111111111111111111111111111111111111111111111"

// TestSignTxBitcoinP2WPKH asserts our signed P2WPKH transaction is byte-identical
// to github.com/btcsuite/btcd's signer for the exact same unsigned transaction
// (ECDSA RFC-6979 low-S is deterministic, so the bytes must match).
func TestSignTxBitcoinP2WPKH(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	utxoScript := append([]byte{0x00, 0x14}, btcutil.Hash160(pub)...)

	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	in := &txbtc.SigningInput{
		HashType:      0x01,
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

	want, msg := btcOracleResign(t, w, out.Encoded, in.Utxo)
	if out.EncodedHex != want {
		t.Fatalf("tx hex mismatch\n got: %s\nwant: %s", out.EncodedHex, want)
	}
	if got := hex.EncodeToString(out.TransactionId); got != msg.TxHash().String() {
		t.Fatalf("txid = %s, want %s", got, msg.TxHash().String())
	}
}

// btcOracleResign deserializes our signed tx, strips witnesses, re-signs every
// (P2WPKH) input with btcd's txscript, and returns the resulting hex plus the
// parsed message.
func btcOracleResign(t *testing.T, w *HDWallet, encoded []byte, utxos []*txbtc.UnspentTransaction) (string, *wire.MsgTx) {
	t.Helper()
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(encoded)); err != nil {
		t.Fatalf("wire deserialize: %v", err)
	}

	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for _, u := range utxos {
		var h chainhash.Hash
		copy(h[:], u.GetOutPointHash())
		prevOuts[wire.OutPoint{Hash: h, Index: u.GetOutPointIndex()}] = wire.NewTxOut(u.GetAmount(), u.GetScript())
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(&msg, fetcher)

	var privKey *btcec.PrivateKey
	if err := w.WithPrivateKey(BTC, 0, func(raw []byte) error {
		privKey, _ = btcec.PrivKeyFromBytes(raw)
		return nil
	}); err != nil {
		t.Fatalf("WithPrivateKey: %v", err)
	}

	for i := range msg.TxIn {
		prevOut := prevOuts[msg.TxIn[i].PreviousOutPoint]
		wit, err := txscript.WitnessSignature(&msg, sigHashes, i, prevOut.Value, prevOut.PkScript, txscript.SigHashAll, privKey, true)
		if err != nil {
			t.Fatalf("oracle WitnessSignature: %v", err)
		}
		msg.TxIn[i].Witness = wit
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("oracle serialize: %v", err)
	}
	return hex.EncodeToString(buf.Bytes()), &msg
}

// TestSignTxBitcoinTaproot verifies that our Taproot key-path signature is made
// over the same sighash btcd computes and validates under BIP-340 against the
// BIP-86 output key. (Schnorr aux randomness makes byte-equality impossible, so
// we verify rather than compare the signature.)
func TestSignTxBitcoinTaproot(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	internal, err := btcec.ParsePubKey(pub)
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}
	outKey := txscript.ComputeTaprootKeyNoScript(internal)
	utxoScript := append([]byte{0x51, 0x20}, schnorr.SerializePubKey(outKey)...)

	to, _ := w.BitcoinAddress(BTC, P2TR, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2TR, 0, 1, 0)

	in := &txbtc.SigningInput{
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
		t.Fatalf("wire deserialize: %v", err)
	}

	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for _, u := range in.Utxo {
		var h chainhash.Hash
		copy(h[:], u.GetOutPointHash())
		prevOuts[wire.OutPoint{Hash: h, Index: u.GetOutPointIndex()}] = wire.NewTxOut(u.GetAmount(), u.GetScript())
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(&msg, fetcher)

	for i := range msg.TxIn {
		wit := msg.TxIn[i].Witness
		if len(wit) != 1 || len(wit[0]) != 64 {
			t.Fatalf("input %d witness shape = %d items; want one 64-byte sig", i, len(wit))
		}
		oracleHash, err := txscript.CalcTaprootSignatureHash(sigHashes, txscript.SigHashDefault, &msg, i, fetcher)
		if err != nil {
			t.Fatalf("oracle CalcTaprootSignatureHash: %v", err)
		}
		sig, err := schnorr.ParseSignature(wit[0])
		if err != nil {
			t.Fatalf("parse schnorr sig: %v", err)
		}
		if !sig.Verify(oracleHash, outKey) {
			t.Fatalf("input %d schnorr signature does not verify against btcd taproot sighash", i)
		}
	}
}

// TestBIP143SighashSpecVector pins bip143Sighash to the worked example in BIP-143
// (native P2WPKH, input index 1).
func TestBIP143SighashSpecVector(t *testing.T) {
	inputs := []btcInput{
		{txid: mustHex(t, "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"), vout: 0, sequence: 0xffffffee, amount: 0},
		{txid: mustHex(t, "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"), vout: 1, sequence: 0xffffffff, amount: 600000000},
	}
	outputs := []btcOutput{
		{value: 112340000, script: mustHex(t, "76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac")},
		{value: 223450000, script: mustHex(t, "76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac")},
	}
	scriptCode := mustHex(t, "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")

	got := bip143Sighash(inputs, outputs, 1, scriptCode, 1, 17, 1)
	want := "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
	if hex.EncodeToString(got) != want {
		t.Fatalf("BIP-143 sighash = %s, want %s", hex.EncodeToString(got), want)
	}
}

// TestSignTxBitcoinErrors covers the rejected-input paths.
func TestSignTxBitcoinErrors(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(BTC, 0)
	p2wpkh := append([]byte{0x00, 0x14}, btcutil.Hash160(pub)...)
	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)

	// Unsupported input script (legacy P2PKH input not signable here).
	legacyScript := append(append([]byte{0x76, 0xa9, 0x14}, btcutil.Hash160(pub)...), 0x88, 0xac)
	_, err = w.SignTransaction(BTC, 0, &txbtc.SigningInput{
		Amount: 1000, ByteFee: 1, ToAddress: to,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 5000, Script: legacyScript, OutPointSequence: 0xffffffff}},
	})
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("unsupported script error = %v, want ErrTxInput", err)
	}

	// Insufficient funds.
	_, err = w.SignTransaction(BTC, 0, &txbtc.SigningInput{
		Amount: 1_000_000, ByteFee: 1, ToAddress: to,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 5000, Script: p2wpkh, OutPointSequence: 0xffffffff}},
	})
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("insufficient-funds error = %v, want ErrTxInput", err)
	}
}
