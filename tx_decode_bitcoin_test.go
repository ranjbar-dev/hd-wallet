package hdwallet

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// "What am I signing?" Bitcoin decoder, proven three ways:
//   - round-trip: sign a tx with the EXISTING signer (SignTransaction) and assert
//     DecodeBitcoinTx returns the same vin prevouts/sequence and vout
//     values+addresses the SigningInput produced;
//   - external vector: decode a btcd-produced (wire/txscript) raw tx and assert
//     vin/vout/addresses, covering P2WPKH and P2PKH outputs;
//   - malformed: truncated/garbage bytes return ErrTxDecode, never a panic.

// TestDecodeBitcoinRoundTripP2WPKH signs a P2WPKH spend with the real signer and
// asserts the decoder recovers the same inputs and outputs (incl. rendered
// addresses).
func TestDecodeBitcoinRoundTripP2WPKH(t *testing.T) {
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
	out, err := w.SignTransaction(BTC, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	encoded := out.(*txbtc.SigningOutput).GetEncoded()

	f, err := DecodeBitcoinTx(BTC, encoded)
	if err != nil {
		t.Fatalf("DecodeBitcoinTx: %v", err)
	}
	if !f.HasWitness {
		t.Fatalf("expected witness flag on a P2WPKH spend")
	}
	if f.Version != 2 {
		t.Fatalf("version = %d, want 2", f.Version)
	}
	if len(f.Vin) != 1 {
		t.Fatalf("vin len = %d, want 1", len(f.Vin))
	}
	// The prevout txid is rendered big-endian (reversed from internal order).
	wantTxID := bytesToHex(reverseBytes(mustHex(t, dummyPrevTxid)))
	if f.Vin[0].TxID != wantTxID {
		t.Fatalf("vin txid = %s, want %s", f.Vin[0].TxID, wantTxID)
	}
	if f.Vin[0].Vout != 0 || f.Vin[0].Sequence != 0xffffffff {
		t.Fatalf("vin vout/seq = %d/%x", f.Vin[0].Vout, f.Vin[0].Sequence)
	}
	// Recipient + change outputs, each P2WPKH, addresses re-rendered.
	if len(f.Vout) != 2 {
		t.Fatalf("vout len = %d, want 2", len(f.Vout))
	}
	if f.Vout[0].Address != to || f.Vout[0].Type != "p2wpkh" {
		t.Fatalf("vout[0] addr/type = %s/%s, want %s/p2wpkh", f.Vout[0].Address, f.Vout[0].Type, to)
	}
	if f.Vout[0].Value != 1500 {
		t.Fatalf("vout[0] value = %d, want 1500", f.Vout[0].Value)
	}
	if f.Vout[1].Address != change || f.Vout[1].Type != "p2wpkh" {
		t.Fatalf("vout[1] addr/type = %s/%s, want %s/p2wpkh", f.Vout[1].Address, f.Vout[1].Type, change)
	}
}

// TestDecodeBitcoinRoundTripTaproot signs a Taproot spend and checks the decoder
// renders the P2TR (bech32m) output addresses.
func TestDecodeBitcoinRoundTripTaproot(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(BTC, 0)
	internal, err := btcec.ParsePubKey(pub)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
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
	out, err := w.SignTransaction(BTC, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	f, err := DecodeBitcoinTx(BTC, out.(*txbtc.SigningOutput).GetEncoded())
	if err != nil {
		t.Fatalf("DecodeBitcoinTx: %v", err)
	}
	if len(f.Vout) == 0 || f.Vout[0].Type != "p2tr" || f.Vout[0].Address != to {
		t.Fatalf("vout[0] = %+v, want p2tr to %s", f.Vout[0], to)
	}
}

// TestDecodeBitcoinVectorBtcd builds a transaction with btcd's wire/txscript
// (P2WPKH input, one P2WPKH output and one P2PKH output) and asserts our decoder
// recovers the exact vin/vout it constructed, including the rendered addresses.
func TestDecodeBitcoinVectorBtcd(t *testing.T) {
	// Build two destination scripts with btcd: a P2WPKH and a legacy P2PKH.
	h20a := bytes.Repeat([]byte{0xab}, 20)
	h20b := bytes.Repeat([]byte{0xcd}, 20)

	wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(h20a, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("NewAddressWitnessPubKeyHash: %v", err)
	}
	wpkhScript, err := txscript.PayToAddrScript(wpkhAddr)
	if err != nil {
		t.Fatalf("PayToAddrScript wpkh: %v", err)
	}
	pkhAddr, err := btcutil.NewAddressPubKeyHash(h20b, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash: %v", err)
	}
	pkhScript, err := txscript.PayToAddrScript(pkhAddr)
	if err != nil {
		t.Fatalf("PayToAddrScript pkh: %v", err)
	}

	msg := wire.NewMsgTx(2)
	var prevHash chainhash.Hash
	copy(prevHash[:], mustHex(t, dummyPrevTxid))
	txIn := wire.NewTxIn(wire.NewOutPoint(&prevHash, 3), nil, nil)
	txIn.Sequence = 0xfffffffe
	msg.AddTxIn(txIn)
	msg.AddTxOut(wire.NewTxOut(2000, wpkhScript))
	msg.AddTxOut(wire.NewTxOut(3000, pkhScript))
	msg.LockTime = 500000

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("btcd serialize: %v", err)
	}

	f, err := DecodeBitcoinTx(BTC, buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeBitcoinTx: %v", err)
	}
	if f.Version != 2 || f.LockTime != 500000 || f.HasWitness {
		t.Fatalf("header mismatch: version=%d locktime=%d witness=%v", f.Version, f.LockTime, f.HasWitness)
	}
	if len(f.Vin) != 1 || f.Vin[0].Vout != 3 || f.Vin[0].Sequence != 0xfffffffe {
		t.Fatalf("vin mismatch: %+v", f.Vin)
	}
	// btcd's MsgTx.TxHash and our decoder both display the txid big-endian.
	if f.Vin[0].TxID != prevHash.String() {
		t.Fatalf("vin txid = %s, want %s", f.Vin[0].TxID, prevHash.String())
	}
	if len(f.Vout) != 2 {
		t.Fatalf("vout len = %d, want 2", len(f.Vout))
	}
	if f.Vout[0].Type != "p2wpkh" || f.Vout[0].Address != wpkhAddr.EncodeAddress() || f.Vout[0].Value != 2000 {
		t.Fatalf("vout[0] = %+v, want p2wpkh %s 2000", f.Vout[0], wpkhAddr.EncodeAddress())
	}
	if f.Vout[1].Type != "p2pkh" || f.Vout[1].Address != pkhAddr.EncodeAddress() || f.Vout[1].Value != 3000 {
		t.Fatalf("vout[1] = %+v, want p2pkh %s 3000", f.Vout[1], pkhAddr.EncodeAddress())
	}
}

// TestDecodeBitcoinNonstandard asserts an unrecognised output script is reported
// as nonstandard with an empty address rather than failing the decode.
func TestDecodeBitcoinNonstandard(t *testing.T) {
	msg := wire.NewMsgTx(2)
	var prevHash chainhash.Hash
	copy(prevHash[:], mustHex(t, dummyPrevTxid))
	msg.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevHash, 0), nil, nil))
	// OP_RETURN <data> — a standard but non-address (nonstandard for our renderer).
	msg.AddTxOut(wire.NewTxOut(0, append([]byte{0x6a, 0x04}, 0xde, 0xad, 0xbe, 0xef)))
	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	f, err := DecodeBitcoinTx(BTC, buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeBitcoinTx: %v", err)
	}
	if f.Vout[0].Type != "nonstandard" || f.Vout[0].Address != "" {
		t.Fatalf("vout[0] = %+v, want nonstandard empty address", f.Vout[0])
	}
}

// TestDecodeBitcoinUnsupportedSymbol asserts a non-Bitcoin symbol is rejected.
func TestDecodeBitcoinUnsupportedSymbol(t *testing.T) {
	if _, err := DecodeBitcoinTx(ETH, []byte{0x02, 0x00, 0x00, 0x00}); err == nil {
		t.Fatalf("expected error for unsupported symbol")
	}
}

// TestDecodeBitcoinMalformed asserts truncated / garbage input returns an error
// (never a panic).
func TestDecodeBitcoinMalformed(t *testing.T) {
	// A valid baseline tx to truncate.
	msg := wire.NewMsgTx(2)
	var prevHash chainhash.Hash
	copy(prevHash[:], mustHex(t, dummyPrevTxid))
	msg.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevHash, 0), nil, nil))
	msg.AddTxOut(wire.NewTxOut(1000, append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x11}, 20)...)))
	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	full := buf.Bytes()

	cases := map[string][]byte{
		"empty":                 {},
		"version only":          full[:4],
		"truncated mid-input":   full[:10],
		"truncated before vout": full[:41],
		"trailing garbage":      append(append([]byte(nil), full...), 0xff),
		"huge input count":      {0x02, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBitcoinTx(BTC, b); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}
