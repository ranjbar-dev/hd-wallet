package hdwallet

// Tests for the output-flexibility extensions to signBitcoinTx:
//   - extra_outputs: multiple recipient outputs beyond the primary to_address
//   - P2WSH destination: native SegWit v0 pay-to-witness-script-hash output
//   - output_op_return: zero-value OP_RETURN carrier output
//
// Each signing path is pinned to the btcd oracle (byte-identical for P2WPKH
// inputs because ECDSA RFC-6979 is deterministic) or to a known-good script
// pattern; see tx_bitcoin_test.go for the oracle helper and conventions.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// TestSignTxBitcoinExtraOutput verifies that a P2WPKH spend with one extra_output
// beyond to_address produces two recipient outputs in the correct order and is
// byte-identical to the btcd oracle re-sign.
func TestSignTxBitcoinExtraOutput(t *testing.T) {
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
	extra, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 2)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	in := &txbtc.SigningInput{
		HashType:      0x01,
		Amount:        1500,
		ByteFee:       1,
		ToAddress:     to,
		ChangeAddress: change,
		ExtraOutputs:  []*txbtc.OutputAddress{{ToAddress: extra, Amount: 2000}},
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

	// Deserialize and verify the first two outputs carry the expected values.
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
		t.Fatalf("wire.Deserialize: %v", err)
	}
	if len(msg.TxOut) < 2 {
		t.Fatalf("expected at least 2 outputs, got %d", len(msg.TxOut))
	}
	if msg.TxOut[0].Value != 1500 {
		t.Fatalf("output[0].Value = %d, want 1500", msg.TxOut[0].Value)
	}
	if msg.TxOut[1].Value != 2000 {
		t.Fatalf("output[1].Value = %d, want 2000", msg.TxOut[1].Value)
	}

	// Oracle byte-match: btcd re-signs the same P2WPKH input with the same
	// sighash (BIP-143 hashes ALL outputs, including extra_outputs), so the
	// resulting witnesses are deterministically identical.
	want, _ := btcOracleResign(t, w, out.Encoded, in.Utxo)
	if out.EncodedHex != want {
		t.Fatalf("tx hex mismatch\n got: %s\nwant: %s", out.EncodedHex, want)
	}
}

// TestSignTxBitcoinP2WSHOutput verifies that paying to a native P2WSH destination
// (bc1q… bech32 v0 32-byte program) decodes correctly through the updated
// decodeBitcoinSegwit and produces a 0x00 0x20 <sha256> output scriptPubKey.
// The signed tx is byte-identical to the btcd oracle.
func TestSignTxBitcoinP2WSHOutput(t *testing.T) {
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

	// Build a synthetic P2WSH address: 1-of-1 multisig witness script using
	// the key at index 1 as the locked key. The address is the bech32 v0
	// encoding of sha256(witnessScript).
	pub2, err := w.PublicKeyIndex(BTC, 1)
	if err != nil {
		t.Fatalf("PublicKeyIndex(BTC,1): %v", err)
	}
	witnessScript := append([]byte{0x51, 0x21}, pub2...) // OP_1 OP_DATA33 <pub>
	witnessScript = append(witnessScript, 0x51, 0xae)    // OP_1 OP_CHECKMULTISIG
	wscriptHash := sha256.Sum256(witnessScript)
	wantP2WSHScript := append([]byte{0x00, 0x20}, wscriptHash[:]...) // OP_0 <32-byte hash>

	// Encode as a standard bech32 (v0) address: "bc1q…" with 32-byte program.
	conv, err := bech32.ConvertBits(wscriptHash[:], 8, 5, true)
	if err != nil {
		t.Fatalf("bech32.ConvertBits: %v", err)
	}
	p2wshAddr, err := bech32.Encode("bc", append([]byte{0x00}, conv...))
	if err != nil {
		t.Fatalf("bech32.Encode: %v", err)
	}

	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	in := &txbtc.SigningInput{
		HashType:      0x01,
		Amount:        1500,
		ByteFee:       1,
		ToAddress:     p2wshAddr,
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

	// The first output must carry the P2WSH scriptPubKey (00 20 <hash>).
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
		t.Fatalf("wire.Deserialize: %v", err)
	}
	if !bytes.Equal(msg.TxOut[0].PkScript, wantP2WSHScript) {
		t.Fatalf("P2WSH output script\n got:  %x\nwant: %x", msg.TxOut[0].PkScript, wantP2WSHScript)
	}

	// Oracle byte-match: the input is P2WPKH; the P2WSH destination is just an
	// output, so btcd's WitnessSignature signs the same BIP-143 sighash.
	want, _ := btcOracleResign(t, w, out.Encoded, in.Utxo)
	if out.EncodedHex != want {
		t.Fatalf("tx hex mismatch\n got: %s\nwant: %s", out.EncodedHex, want)
	}
}

// TestSignTxBitcoinOpReturn verifies OP_RETURN output handling:
//   - The OP_RETURN output has value == 0 and script 0x6a <len> <payload>.
//   - The signed tx is byte-identical to the btcd oracle.
//   - A payload > 80 bytes is rejected with ErrTxInput.
func TestSignTxBitcoinOpReturn(t *testing.T) {
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

	payload := []byte("hello world") // 11 bytes — uses the simple <len> push (< 76)

	in := &txbtc.SigningInput{
		HashType:       0x01,
		Amount:         1500,
		ByteFee:        1,
		ToAddress:      to,
		ChangeAddress:  change,
		OutputOpReturn: payload,
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

	// Deserialize and find the OP_RETURN output.
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
		t.Fatalf("wire.Deserialize: %v", err)
	}
	wantScript := append([]byte{0x6a, 0x0b}, payload...) // 0x6a OP_RETURN, 0x0b = 11
	found := false
	for _, txOut := range msg.TxOut {
		if txOut.Value == 0 && len(txOut.PkScript) > 0 && txOut.PkScript[0] == 0x6a {
			if !bytes.Equal(txOut.PkScript, wantScript) {
				t.Fatalf("OP_RETURN script\n got:  %x\nwant: %x", txOut.PkScript, wantScript)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no OP_RETURN output (value=0, script[0]=0x6a) found in tx")
	}

	// Oracle byte-match: the BIP-143 sighash covers ALL outputs, including the
	// OP_RETURN. Since btcd's WitnessSignature uses the same sighash algorithm
	// with the same tx, the ECDSA RFC-6979 signatures are deterministically equal.
	wantHex, _ := btcOracleResign(t, w, out.Encoded, in.Utxo)
	if out.EncodedHex != wantHex {
		t.Fatalf("tx hex mismatch\n got: %s\nwant: %s", out.EncodedHex, wantHex)
	}

	// Reject payload > 80 bytes.
	_, err = w.SignTransaction(BTC, 0, &txbtc.SigningInput{
		HashType:       0x01,
		Amount:         1500,
		ByteFee:        1,
		ToAddress:      to,
		ChangeAddress:  change,
		OutputOpReturn: make([]byte, 81),
		Utxo:           in.Utxo,
	})
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("oversized OP_RETURN error = %v, want ErrTxInput", err)
	}
}
