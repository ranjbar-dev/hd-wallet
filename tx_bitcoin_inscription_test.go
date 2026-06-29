package hdwallet

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// TestBuildInscriptionScript verifies the structural layout of the generated
// tapscript leaf without touching any key material.
func TestBuildInscriptionScript(t *testing.T) {
	xonly := make([]byte, 32) // 32 zero bytes

	script, err := BuildInscriptionScript(xonly, "text/plain;charset=utf-8", []byte("hello"))
	if err != nil {
		t.Fatalf("BuildInscriptionScript: %v", err)
	}

	// Byte 0: 0x20 = push 32 bytes
	if script[0] != 0x20 {
		t.Errorf("script[0] = 0x%02x, want 0x20 (32-byte push opcode)", script[0])
	}
	// Bytes 1-32: the 32-byte xonly key (all zeros)
	if !bytes.Equal(script[1:33], xonly) {
		t.Error("script[1:33] is not all-zero xonly key")
	}
	// Byte 33: OP_CHECKSIG
	if script[33] != 0xac {
		t.Errorf("script[33] = 0x%02x, want 0xac (OP_CHECKSIG)", script[33])
	}
	// Bytes 34,35: OP_0 OP_IF (0x00, 0x63)
	if script[34] != 0x00 || script[35] != 0x63 {
		t.Errorf("script[34:36] = [0x%02x, 0x%02x], want [0x00, 0x63] (OP_FALSE OP_IF)", script[34], script[35])
	}
	// Last byte: OP_ENDIF (0x68)
	if script[len(script)-1] != 0x68 {
		t.Errorf("last byte = 0x%02x, want 0x68 (OP_ENDIF)", script[len(script)-1])
	}

	// Short xonly key must fail.
	_, errShort := BuildInscriptionScript(make([]byte, 31), "text/plain;charset=utf-8", []byte("hello"))
	if errShort == nil {
		t.Error("BuildInscriptionScript with 31-byte xonly key: expected ErrTxInput, got nil")
	}
}

// TestBRC20TransferBody verifies the exact JSON encoding used by indexers.
func TestBRC20TransferBody(t *testing.T) {
	result := BuildBRC20TransferBody("ordi", "100")
	want := `{"p":"brc-20","op":"transfer","tick":"ordi","amt":"100"}`
	if string(result) != want {
		t.Errorf("BRC20TransferBody = %q, want %q", result, want)
	}
}

// TestBuildBRC20CommitStructure derives the commit address and control block
// from the canonical mnemonic without signing a commit transaction.
func TestBuildBRC20CommitStructure(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub33, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	xonly := pub33[1:]

	body := BuildBRC20TransferBody("ordi", "100")
	leaf, err := BuildInscriptionScript(xonly, "text/plain;charset=utf-8", body)
	if err != nil {
		t.Fatalf("BuildInscriptionScript: %v", err)
	}

	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(leaf))
	rootHash := tree.RootNode.TapHash()
	merkleRoot := rootHash.CloneBytes()

	xonlyOut, parity, err := taprootOutputKey(pub33, merkleRoot)
	if err != nil {
		t.Fatalf("taprootOutputKey: %v", err)
	}
	if len(xonlyOut) != 32 {
		t.Fatalf("xonlyOut length = %d, want 32", len(xonlyOut))
	}

	prefix := byte(0x02)
	if parity == 1 {
		prefix = 0x03
	}
	outputPubKey, err := btcec.ParsePubKey(append([]byte{prefix}, xonlyOut...))
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}

	commitScript, err := txscript.PayToTaprootScript(outputPubKey)
	if err != nil {
		t.Fatalf("PayToTaprootScript: %v", err)
	}
	if commitScript[0] != 0x51 {
		t.Errorf("commitScript[0] = 0x%02x, want 0x51 (OP_1)", commitScript[0])
	}
	if len(commitScript) != 34 {
		t.Errorf("len(commitScript) = %d, want 34", len(commitScript))
	}

	proof := tree.LeafMerkleProofs[0]
	proofBytes := proof.InclusionProof
	merkleProofHashes := make([][]byte, 0, len(proofBytes)/32)
	for len(proofBytes) >= 32 {
		h := make([]byte, 32)
		copy(h, proofBytes[:32])
		merkleProofHashes = append(merkleProofHashes, h)
		proofBytes = proofBytes[32:]
	}
	cb := taprootControlBlock(pub33, parity, merkleProofHashes, 0xc0)

	// Single-leaf tree: no siblings, so control block = 1 version byte + 32-byte internal key.
	if len(cb) != 33 {
		t.Errorf("len(controlBlock) = %d, want 33 (single-leaf tree)", len(cb))
	}
	if cb[0] != 0xc0|parity {
		t.Errorf("cb[0] = 0x%02x, want 0x%02x (version|parity)", cb[0], 0xc0|parity)
	}
	// cb[1:33] must be the x-only internal key (pub33 without the prefix byte).
	if !bytes.Equal(cb[1:33], pub33[1:]) {
		t.Error("cb[1:33] != x-only internal key")
	}
}

// TestSignBRC20Reveal performs a full reveal round-trip: build the reveal tx,
// decode it with the wire package, verify the witness stack structure, and
// verify the embedded Schnorr signature against the internal (untweaked) key.
func TestSignBRC20Reveal(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub33, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	xonly := pub33[1:]

	body := BuildBRC20TransferBody("ordi", "100")
	leaf, err := BuildInscriptionScript(xonly, "text/plain;charset=utf-8", body)
	if err != nil {
		t.Fatalf("BuildInscriptionScript: %v", err)
	}

	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(leaf))
	rootHash2 := tree.RootNode.TapHash()
	merkleRoot := rootHash2.CloneBytes()

	xonlyOut, parity, err := taprootOutputKey(pub33, merkleRoot)
	if err != nil {
		t.Fatalf("taprootOutputKey: %v", err)
	}

	prefix := byte(0x02)
	if parity == 1 {
		prefix = 0x03
	}
	outputPubKey, err := btcec.ParsePubKey(append([]byte{prefix}, xonlyOut...))
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}

	commitScript, err := txscript.PayToTaprootScript(outputPubKey)
	if err != nil {
		t.Fatalf("PayToTaprootScript: %v", err)
	}

	proof := tree.LeafMerkleProofs[0]
	proofBytes2 := proof.InclusionProof
	merkleProofHashes := make([][]byte, 0, len(proofBytes2)/32)
	for len(proofBytes2) >= 32 {
		h := make([]byte, 32)
		copy(h, proofBytes2[:32])
		merkleProofHashes = append(merkleProofHashes, h)
		proofBytes2 = proofBytes2[32:]
	}
	cb := taprootControlBlock(pub33, parity, merkleProofHashes, 0xc0)

	reveal := &InscriptionCommit{
		LeafScript:   leaf,
		ControlBlock: cb,
		CommitScript: commitScript,
		InternalKey:  pub33,
	}

	commitTxID := bytes.Repeat([]byte{0x11}, 32)
	toAddr, err := w.Address(BTC)
	if err != nil {
		t.Fatalf("Address(BTC): %v", err)
	}

	const commitAmount = int64(10000)
	const feeRate = int64(5)

	revealHex, err := w.SignBRC20Reveal(BTC, 0, reveal, commitTxID, 0, commitAmount, toAddr, feeRate)
	if err != nil {
		t.Fatalf("SignBRC20Reveal: %v", err)
	}

	// Decode the raw transaction and verify its structure.
	rawBytes, err := hex.DecodeString(revealHex)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	var msgTx wire.MsgTx
	if err := msgTx.Deserialize(bytes.NewReader(rawBytes)); err != nil {
		t.Fatalf("wire.MsgTx.Deserialize: %v", err)
	}

	if len(msgTx.TxIn) != 1 {
		t.Fatalf("TxIn count = %d, want 1", len(msgTx.TxIn))
	}
	if len(msgTx.TxIn[0].Witness) != 3 {
		t.Fatalf("witness stack depth = %d, want 3", len(msgTx.TxIn[0].Witness))
	}
	// Witness[0]: 64-byte Schnorr signature.
	if len(msgTx.TxIn[0].Witness[0]) != 64 {
		t.Errorf("witness[0] length = %d, want 64 (Schnorr sig)", len(msgTx.TxIn[0].Witness[0]))
	}
	// Witness[1]: the inscription leaf script.
	if !reflect.DeepEqual(msgTx.TxIn[0].Witness[1], leaf) {
		t.Error("witness[1] != leaf script")
	}
	// Witness[2]: the control block.
	if !reflect.DeepEqual(msgTx.TxIn[0].Witness[2], cb) {
		t.Error("witness[2] != control block")
	}

	// Recompute the sighash and verify the Schnorr signature under the internal
	// (untweaked) key.
	inp := btcInput{
		txid:     commitTxID,
		vout:     0,
		sequence: btcDefaultSequence,
		amount:   commitAmount,
		script:   commitScript,
	}
	toScript, err := bitcoinDecodeScript(BTC, toAddr)
	if err != nil {
		t.Fatalf("bitcoinDecodeScript: %v", err)
	}
	outputs := []btcOutput{{value: commitAmount - feeRate*200, script: toScript}}
	sighash, err := tapscriptSighash([]btcInput{inp}, outputs, 0, leaf, 2, 0)
	if err != nil {
		t.Fatalf("tapscriptSighash: %v", err)
	}

	sig, err := schnorr.ParseSignature(msgTx.TxIn[0].Witness[0])
	if err != nil {
		t.Fatalf("schnorr.ParseSignature: %v", err)
	}
	internalPub, err := btcec.ParsePubKey(pub33)
	if err != nil {
		t.Fatalf("btcec.ParsePubKey: %v", err)
	}
	if !sig.Verify(sighash, internalPub) {
		t.Error("Schnorr signature does not verify against the internal (untweaked) key")
	}
}
