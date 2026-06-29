package hdwallet

// Tests for the BIP-341/342 Taproot script-path primitives in
// tx_bitcoin_taproot_script.go.
//
// Four tests cover the four public/exported helpers:
//  1. tapLeafHash    — agree with btcd's NewBaseTapLeaf.TapHash()
//  2. taprootOutputKey + taprootControlBlock — round-trip against btcd
//  3. tapscriptSighash — agree with btcd's CalcTapscriptSignaturehash
//  4. signTaprootScriptPath — BIP-340 Schnorr verifies under the INTERNAL key,
//                             NOT the tweaked output key

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// buildTestLeafScript constructs a standard <pubkey> OP_CHECKSIG tapscript for
// the given 33-byte compressed public key (strips the prefix to get the x-only
// key, then appends OP_CHECKSIG 0xac).
func buildTestLeafScript(pub33 []byte) []byte {
	xonly := pub33[1:] // strip 0x02/0x03 prefix → 32-byte x-only
	script := make([]byte, 0, 1+32+1)
	script = append(script, 0x20)     // OP_DATA_32
	script = append(script, xonly...) // 32-byte x-only pubkey
	script = append(script, 0xac)     // OP_CHECKSIG
	return script
}

// TestTapLeafHash asserts our tapLeafHash equals btcd's NewBaseTapLeaf.TapHash().
func TestTapLeafHash(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub33, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}

	leafScript := buildTestLeafScript(pub33)

	ourHash := tapLeafHash(leafScript)
	btcdLeafHash := txscript.NewBaseTapLeaf(leafScript).TapHash()
	btcdHash := btcdLeafHash.CloneBytes()

	if !bytes.Equal(ourHash, btcdHash) {
		t.Fatalf("tapLeafHash mismatch\n got:  %x\nwant: %x", ourHash, btcdHash)
	}
}

// TestTaprootOutputKeyAndControlBlock verifies the round-trip:
//  1. taprootOutputKey produces the same xonly key as btcd's ComputeTaprootOutputKey.
//  2. taprootControlBlock produces a correctly shaped control block.
func TestTaprootOutputKeyAndControlBlock(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub33, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}

	leafScript := buildTestLeafScript(pub33)

	// Build the tap tree and compute the merkle root via btcd.
	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(leafScript))
	rootHash := tree.RootNode.TapHash()
	merkleRoot := rootHash.CloneBytes()

	// --- taprootOutputKey ---
	xonly, parity, err := taprootOutputKey(pub33, merkleRoot)
	if err != nil {
		t.Fatalf("taprootOutputKey: %v", err)
	}

	internalPub, err := btcec.ParsePubKey(pub33)
	if err != nil {
		t.Fatalf("btcec.ParsePubKey: %v", err)
	}
	wantKey := txscript.ComputeTaprootOutputKey(internalPub, merkleRoot)
	wantCompressed := wantKey.SerializeCompressed()
	wantXonly := wantCompressed[1:]
	wantParity := wantCompressed[0] & 1

	if !bytes.Equal(xonly, wantXonly) {
		t.Fatalf("xonly key mismatch\n got:  %x\nwant: %x", xonly, wantXonly)
	}
	if parity != wantParity {
		t.Fatalf("parity mismatch: got %d, want %d", parity, wantParity)
	}

	// --- taprootControlBlock ---
	// For a single-leaf tree there are no sibling hashes in the proof.
	cb := taprootControlBlock(pub33, parity, nil, 0xc0)

	// Control block must be exactly 33 bytes: 1 control byte + 32 x-only key.
	if len(cb) != 33 {
		t.Fatalf("control block length = %d, want 33", len(cb))
	}
	if cb[0] != 0xc0|parity {
		t.Fatalf("control block byte 0 = 0x%02x, want 0x%02x", cb[0], 0xc0|parity)
	}
	xonlyInternal := pub33[1:] // strip prefix
	if !bytes.Equal(cb[1:33], xonlyInternal) {
		t.Fatalf("control block internal key mismatch\n got:  %x\nwant: %x", cb[1:33], xonlyInternal)
	}
}

// TestTapscriptSighashVsBtcd verifies that our tapscriptSighash agrees with
// btcd's CalcTapscriptSignaturehash for the same transaction and leaf script.
func TestTapscriptSighashVsBtcd(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub33, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}

	leafScript := buildTestLeafScript(pub33)

	// Build a tap tree and derive the P2TR output scriptPubKey.
	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(leafScript))
	rootHash := tree.RootNode.TapHash()
	merkleRoot := rootHash.CloneBytes()
	internalPub, _ := btcec.ParsePubKey(pub33)
	outputKey := txscript.ComputeTaprootOutputKey(internalPub, merkleRoot)
	utxoScript, err := txscript.PayToTaprootScript(outputKey)
	if err != nil {
		t.Fatalf("PayToTaprootScript: %v", err)
	}

	const (
		version  uint32 = 2
		locktime uint32 = 0
		amount   int64  = 100_000
	)

	inputs := []btcInput{{
		txid:     mustHex(t, dummyPrevTxid),
		vout:     0,
		sequence: 0xffffffff,
		amount:   amount,
		script:   utxoScript,
	}}
	outputs := []btcOutput{{
		value:  90_000,
		script: utxoScript, // send to same address type for simplicity
	}}

	ourHash, err := tapscriptSighash(inputs, outputs, 0, leafScript, version, locktime)
	if err != nil {
		t.Fatalf("tapscriptSighash: %v", err)
	}

	// Build the equivalent wire.MsgTx for btcd's oracle.
	wireTx := buildWireTx(t, inputs, outputs, version, locktime)

	prevOuts := buildPrevOutMap(inputs)
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(wireTx, fetcher)

	btcdHash, err := txscript.CalcTapscriptSignaturehash(
		sigHashes,
		txscript.SigHashDefault,
		wireTx,
		0,
		fetcher,
		txscript.NewBaseTapLeaf(leafScript),
	)
	if err != nil {
		t.Fatalf("btcd CalcTapscriptSignaturehash: %v", err)
	}

	if !bytes.Equal(ourHash, btcdHash) {
		t.Fatalf("sighash mismatch\n got:  %x\nwant: %x", ourHash, btcdHash)
	}
}

// TestSignTaprootScriptPath verifies BIP-340 Schnorr signature produced by
// signTaprootScriptPath:
//  1. It verifies under the INTERNAL (untweaked) key.
//  2. It does NOT verify under the TWEAKED output key, proving the internal
//     key is used for script-path signing.
func TestSignTaprootScriptPath(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub33, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}

	leafScript := buildTestLeafScript(pub33)

	// Build the P2TR output key (tweaked) and its scriptPubKey.
	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(leafScript))
	rootHash := tree.RootNode.TapHash()
	merkleRoot := rootHash.CloneBytes()
	internalPub, _ := btcec.ParsePubKey(pub33)
	outputKey := txscript.ComputeTaprootOutputKey(internalPub, merkleRoot)
	utxoScript, err := txscript.PayToTaprootScript(outputKey)
	if err != nil {
		t.Fatalf("PayToTaprootScript: %v", err)
	}

	const (
		version  uint32 = 2
		locktime uint32 = 0
		amount   int64  = 100_000
	)

	inputs := []btcInput{{
		txid:     mustHex(t, dummyPrevTxid),
		vout:     0,
		sequence: 0xffffffff,
		amount:   amount,
		script:   utxoScript,
	}}
	outputs := []btcOutput{{
		value:  90_000,
		script: utxoScript,
	}}

	sighash, err := tapscriptSighash(inputs, outputs, 0, leafScript, version, locktime)
	if err != nil {
		t.Fatalf("tapscriptSighash: %v", err)
	}

	sig64, err := w.signTaprootScriptPath(BTC, 0, sighash)
	if err != nil {
		t.Fatalf("signTaprootScriptPath: %v", err)
	}
	if len(sig64) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sig64))
	}

	schnorrSig, err := schnorr.ParseSignature(sig64)
	if err != nil {
		t.Fatalf("schnorr.ParseSignature: %v", err)
	}

	// 1. Must verify under the INTERNAL key.
	if !schnorrSig.Verify(sighash, internalPub) {
		t.Fatal("signature does not verify under internal (untweaked) key — FAIL")
	}

	// 2. Must NOT verify under the TWEAKED output key (proves internal key used).
	if schnorrSig.Verify(sighash, outputKey) {
		t.Fatal("signature unexpectedly verifies under tweaked output key — sign is using wrong key")
	}
}

// ---- helpers ----------------------------------------------------------------

// buildWireTx constructs a wire.MsgTx from our internal btcInput/btcOutput types.
func buildWireTx(t *testing.T, inputs []btcInput, outputs []btcOutput, version, locktime uint32) *wire.MsgTx {
	t.Helper()
	tx := &wire.MsgTx{
		Version:  int32(version), // #nosec G115
		LockTime: locktime,
	}
	for _, in := range inputs {
		var h [32]byte
		copy(h[:], in.txid)
		txIn := wire.NewTxIn(&wire.OutPoint{Hash: h, Index: in.vout}, nil, nil)
		txIn.Sequence = in.sequence
		tx.TxIn = append(tx.TxIn, txIn)
	}
	for _, out := range outputs {
		tx.TxOut = append(tx.TxOut, wire.NewTxOut(out.value, out.script))
	}
	return tx
}

// buildPrevOutMap builds the map[wire.OutPoint]*wire.TxOut used by MultiPrevOutFetcher.
func buildPrevOutMap(inputs []btcInput) map[wire.OutPoint]*wire.TxOut {
	m := make(map[wire.OutPoint]*wire.TxOut, len(inputs))
	for _, in := range inputs {
		var h [32]byte
		copy(h[:], in.txid)
		op := wire.OutPoint{Hash: h, Index: in.vout}
		m[op] = wire.NewTxOut(in.amount, in.script)
	}
	return m
}
