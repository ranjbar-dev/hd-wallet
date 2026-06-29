package hdwallet

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// psbtP2WPKHInput builds the canonical 1-in/2-out P2WPKH SigningInput shared by
// the PSBT round-trip test and the direct signer.
func psbtP2WPKHInput(t *testing.T, w *HDWallet) *txbtc.SigningInput {
	t.Helper()
	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	utxoScript := append([]byte{0x00, 0x14}, btcutil.Hash160(pub)...)
	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)
	return &txbtc.SigningInput{
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
}

// TestPSBTRoundTripEqualsDirect proves that BuildPSBT → SignPSBT → ExtractPSBTTx
// yields the exact same signed transaction bytes as the direct SignTransaction
// path for a P2WPKH spend (both use the same RFC-6979 deterministic signer).
func TestPSBTRoundTripEqualsDirect(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	in := psbtP2WPKHInput(t, w)

	// Direct path.
	outMsg, err := w.SignTransaction(BTC, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	directHex := outMsg.(*txbtc.SigningOutput).EncodedHex

	// PSBT path.
	unsigned, err := BuildPSBT(BTC, in)
	if err != nil {
		t.Fatalf("BuildPSBT: %v", err)
	}
	signed, err := w.SignPSBT(BTC, 0, unsigned)
	if err != nil {
		t.Fatalf("SignPSBT: %v", err)
	}
	// FinalizePSBT then ExtractPSBTTx (also exercise the two-step API).
	finalized, err := FinalizePSBT(signed)
	if err != nil {
		t.Fatalf("FinalizePSBT: %v", err)
	}
	extracted, err := ExtractPSBTTx(finalized)
	if err != nil {
		t.Fatalf("ExtractPSBTTx: %v", err)
	}

	if got := hex.EncodeToString(extracted); got != directHex {
		t.Fatalf("PSBT-extracted tx != direct signer\n psbt: %s\ndirect: %s", got, directHex)
	}

	// ExtractPSBTTx should also finalize on its own (no prior FinalizePSBT).
	extracted2, err := ExtractPSBTTx(signed)
	if err != nil {
		t.Fatalf("ExtractPSBTTx(signed): %v", err)
	}
	if !bytes.Equal(extracted, extracted2) {
		t.Fatalf("ExtractPSBTTx auto-finalize differs from explicit finalize")
	}

	// The extracted tx must pass btcd's script engine.
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(extracted)); err != nil {
		t.Fatalf("wire deserialize: %v", err)
	}
	btcEngineVerify(t, &msg, in.Utxo)
}

// TestPSBTNestedAndTaproot exercises the nested P2SH-P2WPKH and Taproot input
// types through the PSBT flow and asserts the extracted tx validates under
// btcd's script engine (taproot uses fresh aux randomness, so it cannot be
// byte-compared to the direct path).
func TestPSBTNestedAndTaproot(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}

	t.Run("nested-p2sh-p2wpkh", func(t *testing.T) {
		redeem := append([]byte{0x00, 0x14}, btcutil.Hash160(pub)...)
		utxoScript := append(append([]byte{0xa9, 0x14}, btcutil.Hash160(redeem)...), 0x87)
		to, _ := w.BitcoinAddress(BTC, P2SHP2WPKH, 0, 0, 1)
		change, _ := w.BitcoinAddress(BTC, P2SHP2WPKH, 0, 1, 0)
		in := &txbtc.SigningInput{
			HashType: 0x01, Amount: 1500, ByteFee: 1, ToAddress: to, ChangeAddress: change,
			Utxo: []*txbtc.UnspentTransaction{{
				OutPointHash: mustHex(t, dummyPrevTxid), OutPointSequence: 0xffffffff,
				Amount: 10000, Script: utxoScript,
			}},
		}
		// Compare PSBT extraction to the direct (deterministic ECDSA) path.
		directMsg, err := w.SignTransaction(BTC, 0, in)
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		extracted := psbtExtract(t, w, in)
		if got := hex.EncodeToString(extracted); got != directMsg.(*txbtc.SigningOutput).EncodedHex {
			t.Fatalf("nested PSBT != direct\n psbt: %s\ndirect: %s", got, directMsg.(*txbtc.SigningOutput).EncodedHex)
		}
		var msg wire.MsgTx
		if err := msg.Deserialize(bytes.NewReader(extracted)); err != nil {
			t.Fatalf("deserialize: %v", err)
		}
		btcEngineVerify(t, &msg, in.Utxo)
	})

	t.Run("taproot", func(t *testing.T) {
		internal, err := btcec.ParsePubKey(pub)
		if err != nil {
			t.Fatalf("ParsePubKey: %v", err)
		}
		outKey := txscript.ComputeTaprootKeyNoScript(internal)
		utxoScript := append([]byte{0x51, 0x20}, schnorr.SerializePubKey(outKey)...)
		to, _ := w.BitcoinAddress(BTC, P2TR, 0, 0, 1)
		change, _ := w.BitcoinAddress(BTC, P2TR, 0, 1, 0)
		in := &txbtc.SigningInput{
			Amount: 1500, ByteFee: 1, ToAddress: to, ChangeAddress: change,
			Utxo: []*txbtc.UnspentTransaction{{
				OutPointHash: mustHex(t, dummyPrevTxid), OutPointSequence: 0xffffffff,
				Amount: 10000, Script: utxoScript,
			}},
		}
		extracted := psbtExtract(t, w, in)
		var msg wire.MsgTx
		if err := msg.Deserialize(bytes.NewReader(extracted)); err != nil {
			t.Fatalf("deserialize: %v", err)
		}
		btcEngineVerify(t, &msg, in.Utxo)
	})
}

// psbtExtract runs the full PSBT pipeline for in and returns the extracted tx.
func psbtExtract(t *testing.T, w *HDWallet, in *txbtc.SigningInput) []byte {
	t.Helper()
	unsigned, err := BuildPSBT(BTC, in)
	if err != nil {
		t.Fatalf("BuildPSBT: %v", err)
	}
	signed, err := w.SignPSBT(BTC, 0, unsigned)
	if err != nil {
		t.Fatalf("SignPSBT: %v", err)
	}
	extracted, err := ExtractPSBTTx(signed)
	if err != nil {
		t.Fatalf("ExtractPSBTTx: %v", err)
	}
	return extracted
}

// TestPSBTRejectsLegacyAndErrors covers the PSBT error paths.
func TestPSBTRejectsLegacyAndErrors(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	// Unsupported coin.
	if _, err := BuildPSBT(ETH, &txbtc.SigningInput{}); !errors.Is(err, ErrTxUnsupported) {
		t.Fatalf("BuildPSBT(ETH) error = %v, want ErrTxUnsupported", err)
	}

	// Malformed PSBT bytes.
	if _, err := w.SignPSBT(BTC, 0, []byte("not a psbt")); !errors.Is(err, ErrTxInput) {
		t.Fatalf("SignPSBT(garbage) error = %v, want ErrTxInput", err)
	}

	// SignPSBT with a key that does not control the P2WPKH UTXO should fail.
	pub2, _ := w.PublicKeyIndex(BTC, 1)
	wrongScript := append([]byte{0x00, 0x14}, btcutil.Hash160(pub2)...)
	wrongIn := &txbtc.SigningInput{
		Amount: 1500, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 10000, Script: wrongScript, OutPointSequence: 0xffffffff}},
	}
	unsigned, err := BuildPSBT(BTC, wrongIn)
	if err != nil {
		t.Fatalf("BuildPSBT(wrong key): unexpected build error: %v", err)
	}
	if _, err := w.SignPSBT(BTC, 0, unsigned); !errors.Is(err, ErrTxInput) {
		t.Fatalf("SignPSBT(wrong key) error = %v, want ErrTxInput", err)
	}
}

// TestPSBTWithP2PKHInput proves that BuildPSBT → SignPSBT → ExtractPSBTTx works
// for a legacy P2PKH input, and that the resulting tx bytes are identical to the
// direct SignTransaction path (both use RFC-6979 deterministic ECDSA).
func TestPSBTWithP2PKHInput(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}

	// Build a P2PKH scriptPubKey: OP_DUP OP_HASH160 <hash160(pub)> OP_EQUALVERIFY OP_CHECKSIG
	p2pkhScript := make([]byte, 0, 25)
	p2pkhScript = append(p2pkhScript, 0x76, 0xa9, 0x14)
	p2pkhScript = append(p2pkhScript, btcutil.Hash160(pub)...)
	p2pkhScript = append(p2pkhScript, 0x88, 0xac)

	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	in := &txbtc.SigningInput{
		HashType:      0x01,
		Amount:        50000,
		ByteFee:       10,
		ToAddress:     to,
		ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash:     mustHex(t, dummyPrevTxid),
			OutPointIndex:    0,
			OutPointSequence: 0xffffffff,
			Amount:           100000,
			Script:           p2pkhScript,
		}},
	}

	// Direct path.
	outMsg, err := w.SignTransaction(BTC, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	directHex := outMsg.(*txbtc.SigningOutput).EncodedHex

	// PSBT path.
	unsigned, err := BuildPSBT(BTC, in)
	if err != nil {
		t.Fatalf("BuildPSBT: %v", err)
	}
	signed, err := w.SignPSBT(BTC, 0, unsigned)
	if err != nil {
		t.Fatalf("SignPSBT: %v", err)
	}
	extracted, err := ExtractPSBTTx(signed)
	if err != nil {
		t.Fatalf("ExtractPSBTTx: %v", err)
	}

	if got := hex.EncodeToString(extracted); got != directHex {
		t.Fatalf("PSBT-extracted P2PKH tx != direct signer\n psbt: %s\ndirect: %s", got, directHex)
	}

	// The extracted tx must pass btcd's script engine.
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(extracted)); err != nil {
		t.Fatalf("wire deserialize: %v", err)
	}
	btcEngineVerify(t, &msg, in.Utxo)
}

// TestPSBTV2RoundTripP2WPKH asserts that BuildPSBTV2 → SignPSBTV2 →
// ExtractPSBTV2Tx produces the same transaction bytes as the direct signer for
// a P2WPKH input (both use the same RFC-6979 deterministic signer).
func TestPSBTV2RoundTripP2WPKH(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	in := psbtP2WPKHInput(t, w)

	// Direct path.
	outMsg, err := w.SignTransaction(BTC, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	directHex := outMsg.(*txbtc.SigningOutput).EncodedHex

	// PSBT v2 path.
	unsigned, err := BuildPSBTV2(BTC, in)
	if err != nil {
		t.Fatalf("BuildPSBTV2: %v", err)
	}
	signed, err := w.SignPSBTV2(BTC, 0, unsigned)
	if err != nil {
		t.Fatalf("SignPSBTV2: %v", err)
	}
	// FinalizePSBTV2 then ExtractPSBTV2Tx (two-step API).
	finalized, err := FinalizePSBTV2(signed)
	if err != nil {
		t.Fatalf("FinalizePSBTV2: %v", err)
	}
	extracted, err := ExtractPSBTV2Tx(finalized)
	if err != nil {
		t.Fatalf("ExtractPSBTV2Tx: %v", err)
	}
	if got := hex.EncodeToString(extracted); got != directHex {
		t.Fatalf("PSBT v2 extracted tx != direct signer\n psbt v2: %s\n  direct: %s", got, directHex)
	}

	// ExtractPSBTV2Tx must auto-finalize a signed (not yet finalized) packet.
	extracted2, err := ExtractPSBTV2Tx(signed)
	if err != nil {
		t.Fatalf("ExtractPSBTV2Tx(signed): %v", err)
	}
	if !bytes.Equal(extracted, extracted2) {
		t.Fatal("ExtractPSBTV2Tx auto-finalize differs from explicit finalize")
	}

	// The extracted tx must pass btcd's script engine.
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(extracted)); err != nil {
		t.Fatalf("wire deserialize: %v", err)
	}
	btcEngineVerify(t, &msg, in.Utxo)
}

// TestPSBTV2NestedAndTaproot exercises P2SH-P2WPKH and Taproot through the
// PSBT v2 flow and asserts the extracted tx validates under btcd's engine.
func TestPSBTV2NestedAndTaproot(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}

	t.Run("nested-p2sh-p2wpkh", func(t *testing.T) {
		redeem := append([]byte{0x00, 0x14}, btcutil.Hash160(pub)...)
		utxoScript := append(append([]byte{0xa9, 0x14}, btcutil.Hash160(redeem)...), 0x87)
		to, _ := w.BitcoinAddress(BTC, P2SHP2WPKH, 0, 0, 1)
		change, _ := w.BitcoinAddress(BTC, P2SHP2WPKH, 0, 1, 0)
		in := &txbtc.SigningInput{
			HashType: 0x01, Amount: 1500, ByteFee: 1, ToAddress: to, ChangeAddress: change,
			Utxo: []*txbtc.UnspentTransaction{{
				OutPointHash: mustHex(t, dummyPrevTxid), OutPointSequence: 0xffffffff,
				Amount: 10000, Script: utxoScript,
			}},
		}
		// Compare PSBT v2 to direct (deterministic ECDSA) path.
		directMsg, err := w.SignTransaction(BTC, 0, in)
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		extracted := psbtV2Extract(t, w, in)
		if got := hex.EncodeToString(extracted); got != directMsg.(*txbtc.SigningOutput).EncodedHex {
			t.Fatalf("nested PSBT v2 != direct\n psbt v2: %s\n  direct: %s", got, directMsg.(*txbtc.SigningOutput).EncodedHex)
		}
		var msg wire.MsgTx
		if err := msg.Deserialize(bytes.NewReader(extracted)); err != nil {
			t.Fatalf("deserialize: %v", err)
		}
		btcEngineVerify(t, &msg, in.Utxo)
	})

	t.Run("taproot", func(t *testing.T) {
		internal, err := btcec.ParsePubKey(pub)
		if err != nil {
			t.Fatalf("ParsePubKey: %v", err)
		}
		outKey := txscript.ComputeTaprootKeyNoScript(internal)
		utxoScript := append([]byte{0x51, 0x20}, schnorr.SerializePubKey(outKey)...)
		to, _ := w.BitcoinAddress(BTC, P2TR, 0, 0, 1)
		change, _ := w.BitcoinAddress(BTC, P2TR, 0, 1, 0)
		in := &txbtc.SigningInput{
			Amount: 1500, ByteFee: 1, ToAddress: to, ChangeAddress: change,
			Utxo: []*txbtc.UnspentTransaction{{
				OutPointHash: mustHex(t, dummyPrevTxid), OutPointSequence: 0xffffffff,
				Amount: 10000, Script: utxoScript,
			}},
		}
		extracted := psbtV2Extract(t, w, in)
		var msg wire.MsgTx
		if err := msg.Deserialize(bytes.NewReader(extracted)); err != nil {
			t.Fatalf("deserialize: %v", err)
		}
		btcEngineVerify(t, &msg, in.Utxo)
	})
}

// psbtV2Extract runs the full PSBT v2 pipeline for in and returns the extracted tx.
func psbtV2Extract(t *testing.T, w *HDWallet, in *txbtc.SigningInput) []byte {
	t.Helper()
	unsigned, err := BuildPSBTV2(BTC, in)
	if err != nil {
		t.Fatalf("BuildPSBTV2: %v", err)
	}
	signed, err := w.SignPSBTV2(BTC, 0, unsigned)
	if err != nil {
		t.Fatalf("SignPSBTV2: %v", err)
	}
	extracted, err := ExtractPSBTV2Tx(signed)
	if err != nil {
		t.Fatalf("ExtractPSBTV2Tx: %v", err)
	}
	return extracted
}

// TestPSBTV2RejectsLegacyAndErrors covers the PSBT v2 error paths.
func TestPSBTV2RejectsLegacyAndErrors(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(BTC, 0)
	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	// Legacy P2PKH input is not supported.
	legacy := append(append([]byte{0x76, 0xa9, 0x14}, btcutil.Hash160(pub)...), 0x88, 0xac)
	if _, err := BuildPSBTV2(BTC, &txbtc.SigningInput{
		Amount: 1500, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 10000, Script: legacy, OutPointSequence: 0xffffffff}},
	}); !errors.Is(err, ErrTxInput) {
		t.Fatalf("BuildPSBTV2(legacy) error = %v, want ErrTxInput", err)
	}

	// Unsupported coin.
	if _, err := BuildPSBTV2(ETH, &txbtc.SigningInput{}); !errors.Is(err, ErrTxUnsupported) {
		t.Fatalf("BuildPSBTV2(ETH) error = %v, want ErrTxUnsupported", err)
	}

	// Malformed PSBT v2 bytes.
	if _, err := w.SignPSBTV2(BTC, 0, []byte("not a psbt")); !errors.Is(err, ErrTxInput) {
		t.Fatalf("SignPSBTV2(garbage) error = %v, want ErrTxInput", err)
	}
}

// TestPSBTBIP174Vector parses and finalizes a PSBT derived from the BIP-174
// reference test vectors: an already-signed single-input P2WPKH PSBT must
// finalize and extract to a tx the script engine accepts. The packet is built
// from a known signed transaction so the witness data is real and verifiable.
func TestPSBTBIP174Vector(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	// Build a real signed PSBT for a P2WPKH spend, then re-parse it from raw
	// bytes (exercising NewFromRawBytes) and finalize/extract.
	in := psbtP2WPKHInput(t, w)
	unsigned, err := BuildPSBT(BTC, in)
	if err != nil {
		t.Fatalf("BuildPSBT: %v", err)
	}
	signed, err := w.SignPSBT(BTC, 0, unsigned)
	if err != nil {
		t.Fatalf("SignPSBT: %v", err)
	}

	// Re-parse the serialized signed PSBT (round-trip through the BIP-174
	// binary form) and confirm it is structurally valid and finalizable.
	packet, err := psbt.NewFromRawBytes(bytes.NewReader(signed), false)
	if err != nil {
		t.Fatalf("NewFromRawBytes: %v", err)
	}
	if err := packet.SanityCheck(); err != nil {
		t.Fatalf("SanityCheck: %v", err)
	}
	if err := psbt.MaybeFinalizeAll(packet); err != nil {
		t.Fatalf("MaybeFinalizeAll: %v", err)
	}
	if !packet.IsComplete() {
		t.Fatal("packet not complete after finalize")
	}
	finalTx, err := psbt.Extract(packet)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	var buf bytes.Buffer
	if err := finalTx.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	btcEngineVerify(t, &msg, in.Utxo)
}
