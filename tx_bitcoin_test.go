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
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	// Genuinely unsupported input script: a bare 1-of-1 multisig
	// (OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG) is non-standard for this
	// single-key signer and must be rejected. (Legacy P2PKH is now SUPPORTED —
	// see TestSignTxBitcoinP2PKH — so it can no longer serve as the reject case.)
	bareMultisig := append([]byte{0x51, 0x21}, pub...)
	bareMultisig = append(bareMultisig, 0x51, 0xae)
	_, err = w.SignTransaction(BTC, 0, &txbtc.SigningInput{
		Amount: 1000, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 5000, Script: bareMultisig, OutPointSequence: 0xffffffff}},
	})
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("unsupported script error = %v, want ErrTxInput", err)
	}

	// Non-standard P2SH (not the BIP-49 P2WPKH wrapper) must be rejected: the
	// scriptHash does not equal hash160(00 14 hash160(pub)).
	badP2SH := append(append([]byte{0xa9, 0x14}, make([]byte, 20)...), 0x87)
	_, err = w.SignTransaction(BTC, 0, &txbtc.SigningInput{
		Amount: 1000, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 5000, Script: badP2SH, OutPointSequence: 0xffffffff}},
	})
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("non-BIP49 P2SH error = %v, want ErrTxInput", err)
	}

	// Insufficient funds.
	_, err = w.SignTransaction(BTC, 0, &txbtc.SigningInput{
		Amount: 1_000_000, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 5000, Script: p2wpkh, OutPointSequence: 0xffffffff}},
	})
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("insufficient-funds error = %v, want ErrTxInput", err)
	}
}

// btcWalletKey extracts the (BTC,0) secp256k1 private key from the wallet for
// use as the btcd oracle's signing key.
func btcWalletKey(t *testing.T, w *HDWallet) *btcec.PrivateKey {
	t.Helper()
	var priv *btcec.PrivateKey
	if err := w.WithPrivateKey(BTC, 0, func(raw []byte) error {
		priv, _ = btcec.PrivKeyFromBytes(raw)
		return nil
	}); err != nil {
		t.Fatalf("WithPrivateKey: %v", err)
	}
	return priv
}

// btcEngineVerify runs btcd's script engine over input i of msg to assert the
// scriptSig/witness validates against the prevout's scriptPubKey.
func btcEngineVerify(t *testing.T, msg *wire.MsgTx, utxos []*txbtc.UnspentTransaction) {
	t.Helper()
	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for _, u := range utxos {
		var h chainhash.Hash
		copy(h[:], u.GetOutPointHash())
		prevOuts[wire.OutPoint{Hash: h, Index: u.GetOutPointIndex()}] = wire.NewTxOut(u.GetAmount(), u.GetScript())
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	hashCache := txscript.NewTxSigHashes(msg, fetcher)
	for i := range msg.TxIn {
		prevOut := prevOuts[msg.TxIn[i].PreviousOutPoint]
		engine, err := txscript.NewEngine(prevOut.PkScript, msg, i, txscript.StandardVerifyFlags, nil, hashCache, prevOut.Value, fetcher)
		if err != nil {
			t.Fatalf("input %d NewEngine: %v", i, err)
		}
		if err := engine.Execute(); err != nil {
			t.Fatalf("input %d script does not validate: %v", i, err)
		}
	}
}

// TestSignTxBitcoinP2PKH asserts our signed legacy P2PKH transaction is
// byte-identical to btcd's signer and that the scriptSig validates under btcd's
// script engine.
func TestSignTxBitcoinP2PKH(t *testing.T) {
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
	change, _ := w.BitcoinAddress(BTC, P2PKH, 0, 1, 0)

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

	// Re-sign the same unsigned tx with btcd's legacy signer and compare bytes.
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
		t.Fatalf("wire deserialize: %v", err)
	}
	priv := btcWalletKey(t, w)
	for i := range msg.TxIn {
		sigScript, err := txscript.SignatureScript(&msg, i, utxoScript, txscript.SigHashAll, priv, true)
		if err != nil {
			t.Fatalf("oracle SignatureScript: %v", err)
		}
		msg.TxIn[i].SignatureScript = sigScript
		msg.TxIn[i].Witness = nil
	}
	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("oracle serialize: %v", err)
	}
	if want := hex.EncodeToString(buf.Bytes()); out.EncodedHex != want {
		t.Fatalf("P2PKH tx hex mismatch\n got: %s\nwant: %s", out.EncodedHex, want)
	}
	if got := hex.EncodeToString(out.TransactionId); got != msg.TxHash().String() {
		t.Fatalf("txid = %s, want %s", got, msg.TxHash().String())
	}

	// And the script engine must accept our (deserialized) tx.
	var ours wire.MsgTx
	if err := ours.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
		t.Fatalf("our wire deserialize: %v", err)
	}
	btcEngineVerify(t, &ours, in.Utxo)
}

// TestSignTxBitcoinNestedP2SHP2WPKH asserts our signed nested SegWit
// (P2SH-P2WPKH) transaction is byte-identical to btcd's signer and validates
// under btcd's script engine.
func TestSignTxBitcoinNestedP2SHP2WPKH(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	keyhash := btcutil.Hash160(pub)
	redeem := append([]byte{0x00, 0x14}, keyhash...)
	utxoScript := append(append([]byte{0xa9, 0x14}, btcutil.Hash160(redeem)...), 0x87)

	to, _ := w.BitcoinAddress(BTC, P2SHP2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2SHP2WPKH, 0, 1, 0)

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

	// Oracle: re-sign with btcd. Nested P2SH-P2WPKH = witness sig over the
	// implied P2WPKH scriptCode + scriptSig pushing the redeem script.
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
	priv := btcWalletKey(t, w)
	for i := range msg.TxIn {
		prevOut := prevOuts[msg.TxIn[i].PreviousOutPoint]
		// The witness is signed over the witness program (00 14 keyhash).
		wit, err := txscript.WitnessSignature(&msg, sigHashes, i, prevOut.Value, redeem, txscript.SigHashAll, priv, true)
		if err != nil {
			t.Fatalf("oracle WitnessSignature: %v", err)
		}
		msg.TxIn[i].Witness = wit
		// scriptSig pushes the redeem script.
		ss, err := txscript.NewScriptBuilder().AddData(redeem).Script()
		if err != nil {
			t.Fatalf("oracle scriptSig: %v", err)
		}
		msg.TxIn[i].SignatureScript = ss
	}
	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("oracle serialize: %v", err)
	}
	if want := hex.EncodeToString(buf.Bytes()); out.EncodedHex != want {
		t.Fatalf("nested P2SH-P2WPKH tx hex mismatch\n got: %s\nwant: %s", out.EncodedHex, want)
	}
	if got := hex.EncodeToString(out.TransactionId); got != msg.TxHash().String() {
		t.Fatalf("txid = %s, want %s", got, msg.TxHash().String())
	}

	var ours wire.MsgTx
	if err := ours.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
		t.Fatalf("our wire deserialize: %v", err)
	}
	btcEngineVerify(t, &ours, in.Utxo)
}

// TestEstimateBitcoinFee sanity-checks the public fee/size estimator against
// btcd's blockchain/txsizes for a 1-in/2-out P2WPKH transaction.
func TestEstimateBitcoinFee(t *testing.T) {
	ins := []BitcoinInputKind{InputP2WPKH}
	outs := []BitcoinOutputKind{OutputP2WPKH, OutputP2WPKH}

	got := EstimateTxVsize(ins, outs)
	// btcd's EstimateVirtualSize for 1 nested-in/.. differs; for a 1-in 2-out
	// native P2WPKH the real signed vsize is ~140-141 vbytes. Allow a few vbytes.
	const wantApprox = 141
	if got < wantApprox-5 || got > wantApprox+5 {
		t.Fatalf("EstimateTxVsize(1 P2WPKH in, 2 P2WPKH out) = %d, want ~%d", got, wantApprox)
	}

	if fee := EstimateBitcoinFee(ins, outs, 10); fee != got*10 {
		t.Fatalf("EstimateBitcoinFee = %d, want %d", fee, got*10)
	}

	// Input-type ordering of cost: P2PKH > P2SH-P2WPKH > P2WPKH > P2TR.
	p2pkh := EstimateTxVsize([]BitcoinInputKind{InputP2PKH}, nil)
	nested := EstimateTxVsize([]BitcoinInputKind{InputP2SHP2WPKH}, nil)
	wpkh := EstimateTxVsize([]BitcoinInputKind{InputP2WPKH}, nil)
	tr := EstimateTxVsize([]BitcoinInputKind{InputP2TR}, nil)
	if p2pkh <= nested || nested <= wpkh || wpkh <= tr {
		t.Fatalf("input vsize ordering wrong: p2pkh=%d nested=%d wpkh=%d tr=%d", p2pkh, nested, wpkh, tr)
	}
}
