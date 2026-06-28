package hdwallet

// Bitcoin multisig tests (P2SH and P2WSH, 2-of-3).
//
// Correctness anchor: each partial signature produced by SignMultisigPSBT is
// compared byte-for-byte with the output of btcd's txscript.RawTxInWitness-
// Signature / RawTxInSignature (RFC 6979 deterministic).  The final extracted
// transaction is then validated under btcd's script engine (NewEngine /
// Execute).
//
// Vectors source: btcd txscript oracle on the canonical BIP-39 mnemonic
// ("abandon … about") — the same mnemonic used by all other signing tests in
// this package.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// multisig3rdPubKey is a valid compressed secp256k1 pubkey used as a static
// "third signer" whose private key is NOT held by the test wallet.  It is the
// secp256k1 generator point G in compressed form (private key = 1), which
// holds no funds on any mainnet.  It is used only to construct 2-of-3
// multisig scripts where the third slot is intentionally uncontrolled.
var multisig3rdPubKey, _ = hex.DecodeString(
	"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
)

// btcWalletKeyAt extracts the secp256k1 private key at (BTC, index) via
// WithPrivateKey — the only internal path that makes the raw key available.
// The returned *btcec.PrivateKey is for test-only btcd oracle comparisons and
// must not be logged or persisted.
func btcWalletKeyAt(t *testing.T, w *HDWallet, index uint32) *btcec.PrivateKey {
	t.Helper()
	var priv *btcec.PrivateKey
	if err := w.WithPrivateKey(BTC, index, func(raw []byte) error {
		priv, _ = btcec.PrivKeyFromBytes(raw)
		return nil
	}); err != nil {
		t.Fatalf("WithPrivateKey(%d): %v", index, err)
	}
	return priv
}

// multisigPrevFetcher builds a PrevOutputFetcher from a btcd PSBT packet's
// WitnessUtxo fields, for use with CalcWitnessSigHash.
func multisigPrevFetcher(packet *psbt.Packet) txscript.PrevOutputFetcher {
	m := make(map[wire.OutPoint]*wire.TxOut, len(packet.Inputs))
	for i, inp := range packet.Inputs {
		if inp.WitnessUtxo != nil {
			m[packet.UnsignedTx.TxIn[i].PreviousOutPoint] = inp.WitnessUtxo
		}
	}
	return txscript.NewMultiPrevOutFetcher(m)
}

// partialSigFor extracts the DER+hashtype signature for the given pubkey from
// a btcd PSBT packet's PartialSigs of input 0.
func partialSigFor(t *testing.T, packet *psbt.Packet, pub []byte) []byte {
	t.Helper()
	for _, ps := range packet.Inputs[0].PartialSigs {
		if bytes.Equal(ps.PubKey, pub) {
			return ps.Signature
		}
	}
	t.Fatalf("partial sig not found for pubkey %x", pub)
	return nil
}

// ---- BIP-67 script building tests ----

// TestBuildMultisigRedeemScriptBIP67 verifies that BuildMultisigRedeemScript:
//   - sorts pubkeys lexicographically (BIP-67)
//   - emits the correct OP_m <keys> OP_n OP_CHECKMULTISIG byte structure
//   - rejects out-of-range m/n and wrong-sized pubkeys
func TestBuildMultisigRedeemScriptBIP67(t *testing.T) {
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
	pub2 := multisig3rdPubKey

	t.Run("bip67-sorted", func(t *testing.T) {
		// Build with keys in one order; build again in a different order.
		// BIP-67 sorts lexicographically, so both must produce the same script.
		s1, err := BuildMultisigRedeemScript(2, [][]byte{pub0, pub1, pub2})
		if err != nil {
			t.Fatalf("BuildMultisigRedeemScript: %v", err)
		}
		s2, err := BuildMultisigRedeemScript(2, [][]byte{pub2, pub0, pub1})
		if err != nil {
			t.Fatalf("BuildMultisigRedeemScript (reversed): %v", err)
		}
		if !bytes.Equal(s1, s2) {
			t.Fatalf("BIP-67 sorting did not produce identical scripts:\n s1=%x\n s2=%x", s1, s2)
		}
	})

	t.Run("script-structure", func(t *testing.T) {
		// 2-of-3: OP_2 <33-byte key> <33-byte key> <33-byte key> OP_3 OP_CHECKMULTISIG
		// OP_m = 0x52, OP_n = 0x53, OP_CHECKMULTISIG = 0xae
		// Each key push: 0x21 <33 bytes> = 34 bytes
		s, err := BuildMultisigRedeemScript(2, [][]byte{pub0, pub1, pub2})
		if err != nil {
			t.Fatalf("BuildMultisigRedeemScript: %v", err)
		}
		// Expected length: 1 (OP_2) + 3*(1+33) (key pushes) + 1 (OP_3) + 1 (OP_CHECKMULTISIG)
		if want := 1 + 3*34 + 1 + 1; len(s) != want {
			t.Fatalf("script length: got %d, want %d", len(s), want)
		}
		if s[0] != 0x52 { // OP_2
			t.Fatalf("script[0]: got 0x%02x, want 0x52 (OP_2)", s[0])
		}
		if s[len(s)-2] != 0x53 { // OP_3
			t.Fatalf("script[-2]: got 0x%02x, want 0x53 (OP_3)", s[len(s)-2])
		}
		if s[len(s)-1] != 0xae { // OP_CHECKMULTISIG
			t.Fatalf("script[-1]: got 0x%02x, want 0xae (OP_CHECKMULTISIG)", s[len(s)-1])
		}
		// Verify push-33 opcode for each key slot
		for i, off := range []int{1, 35, 69} {
			if s[off] != 0x21 {
				t.Fatalf("key %d push opcode: got 0x%02x, want 0x21", i, s[off])
			}
		}
	})

	t.Run("1-of-1", func(t *testing.T) {
		s, err := BuildMultisigRedeemScript(1, [][]byte{pub0})
		if err != nil {
			t.Fatalf("1-of-1: %v", err)
		}
		if s[0] != 0x51 { // OP_1
			t.Fatalf("OP_1 expected, got 0x%02x", s[0])
		}
	})

	t.Run("error-m-zero", func(t *testing.T) {
		_, err := BuildMultisigRedeemScript(0, [][]byte{pub0})
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("m=0: want ErrTxInput, got %v", err)
		}
	})
	t.Run("error-m-gt-n", func(t *testing.T) {
		_, err := BuildMultisigRedeemScript(3, [][]byte{pub0, pub1})
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("m>n: want ErrTxInput, got %v", err)
		}
	})
	t.Run("error-n-gt-16", func(t *testing.T) {
		keys := make([][]byte, 17)
		for i := range keys {
			keys[i] = pub0
		}
		_, err := BuildMultisigRedeemScript(1, keys)
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("n=17: want ErrTxInput, got %v", err)
		}
	})
	t.Run("error-wrong-pubkey-length", func(t *testing.T) {
		_, err := BuildMultisigRedeemScript(1, [][]byte{pub0[:31]})
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("short pubkey: want ErrTxInput, got %v", err)
		}
	})
}

// ---- address derivation tests ----

// TestMultisigAddresses verifies MultisigP2SHAddress and MultisigP2WSHAddress
// produce the correct prefix and length for BTC.
func TestMultisigAddresses(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub0, _ := w.PublicKeyIndex(BTC, 0)
	pub1, _ := w.PublicKeyIndex(BTC, 1)

	script, err := BuildMultisigRedeemScript(2, [][]byte{pub0, pub1, multisig3rdPubKey})
	if err != nil {
		t.Fatalf("BuildMultisigRedeemScript: %v", err)
	}

	t.Run("P2SH-address", func(t *testing.T) {
		addr, err := MultisigP2SHAddress(BTC, script)
		if err != nil {
			t.Fatalf("MultisigP2SHAddress: %v", err)
		}
		// BTC P2SH addresses begin with '3'
		if addr[0] != '3' {
			t.Fatalf("P2SH address should start with '3', got %q", addr)
		}
		if len(addr) < 30 || len(addr) > 35 {
			t.Fatalf("P2SH address length %d out of expected range", len(addr))
		}
		// Re-derive must be stable
		addr2, _ := MultisigP2SHAddress(BTC, script)
		if addr != addr2 {
			t.Fatalf("P2SH address not stable: %q vs %q", addr, addr2)
		}
	})

	t.Run("P2WSH-address", func(t *testing.T) {
		addr, err := MultisigP2WSHAddress(BTC, script)
		if err != nil {
			t.Fatalf("MultisigP2WSHAddress: %v", err)
		}
		// Native SegWit BTC addresses start with "bc1q"
		if len(addr) < 4 || addr[:4] != "bc1q" {
			t.Fatalf("P2WSH address should start with 'bc1q', got %q", addr)
		}
		addr2, _ := MultisigP2WSHAddress(BTC, script)
		if addr != addr2 {
			t.Fatalf("P2WSH address not stable: %q vs %q", addr, addr2)
		}
	})

	t.Run("unsupported-coin", func(t *testing.T) {
		_, err1 := MultisigP2SHAddress(ETH, script)
		_, err2 := MultisigP2WSHAddress(ETH, script)
		if !errors.Is(err1, ErrUnsupportedCoin) {
			t.Fatalf("P2SH(ETH): want ErrUnsupportedCoin, got %v", err1)
		}
		if !errors.Is(err2, ErrUnsupportedCoin) {
			t.Fatalf("P2WSH(ETH): want ErrUnsupportedCoin, got %v", err2)
		}
	})
}

// ---- P2WSH round-trip with btcd oracle ----

// TestMultisigP2WSHBtcdOracle builds a 2-of-3 P2WSH PSBT, signs it with the
// wallet's index-0 and index-1 keys, and:
//   - pins each partial signature byte-for-byte against btcd's
//     txscript.RawTxInWitnessSignature (RFC 6979 deterministic)
//   - verifies the extracted transaction via btcd's script engine
//
// Vector source: btcd txscript oracle on "abandon … about" (canonical mnemonic)
// commit github.com/btcsuite/btcd v0.24.2 / btcutil/psbt v1.1.5.
func TestMultisigP2WSHBtcdOracle(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	// Derive the two controlled public keys and add a static third.
	pub0, err := w.PublicKeyIndex(BTC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex(0): %v", err)
	}
	pub1, err := w.PublicKeyIndex(BTC, 1)
	if err != nil {
		t.Fatalf("PublicKeyIndex(1): %v", err)
	}

	// Build the 2-of-3 witnessScript (BIP-67 sorted internally).
	witnessScript, err := BuildMultisigRedeemScript(2, [][]byte{pub0, pub1, multisig3rdPubKey})
	if err != nil {
		t.Fatalf("BuildMultisigRedeemScript: %v", err)
	}

	// Construct the P2WSH scriptPubKey: OP_0 <sha256(witnessScript)>
	h := sha256.Sum256(witnessScript)
	utxoScript := append([]byte{0x00, 0x20}, h[:]...)
	const utxoAmount = int64(50_000)

	// Recipient and change addresses.
	to, err := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 2)
	if err != nil {
		t.Fatalf("BitcoinAddress(to): %v", err)
	}
	change, err := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)
	if err != nil {
		t.Fatalf("BitcoinAddress(change): %v", err)
	}

	in := &txbtc.SigningInput{
		Amount:        20_000,
		ByteFee:       1,
		ToAddress:     to,
		ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash:     mustHex(t, dummyPrevTxid),
			OutPointIndex:    0,
			OutPointSequence: 0xffffffff,
			Amount:           utxoAmount,
			Script:           utxoScript,
		}},
	}

	// Build unsigned PSBT.
	unsigned, err := BuildMultisigPSBT(BTC, in, witnessScript)
	if err != nil {
		t.Fatalf("BuildMultisigPSBT: %v", err)
	}

	// ----- Signer 0 (wallet index 0) -----
	signed1, err := w.SignMultisigPSBT(BTC, 0, unsigned)
	if err != nil {
		t.Fatalf("SignMultisigPSBT(0): %v", err)
	}

	// Parse the PSBT to extract the partial sig and compare to the oracle.
	packet1, err := psbt.NewFromRawBytes(bytes.NewReader(signed1), false)
	if err != nil {
		t.Fatalf("psbt parse after signer 0: %v", err)
	}

	// Confirm exactly one partial sig is present.
	if got := len(packet1.Inputs[0].PartialSigs); got != 1 {
		t.Fatalf("expected 1 partial sig after signer 0, got %d", got)
	}

	// Oracle: compute the expected sig via btcd's deterministic signer.
	prevFetcher := multisigPrevFetcher(packet1)
	sigHashes := txscript.NewTxSigHashes(packet1.UnsignedTx, prevFetcher)

	priv0 := btcWalletKeyAt(t, w, 0)
	wantSig0, err := txscript.RawTxInWitnessSignature(
		packet1.UnsignedTx, sigHashes, 0, utxoAmount, witnessScript,
		txscript.SigHashAll, priv0,
	)
	if err != nil {
		t.Fatalf("btcd oracle signer 0: %v", err)
	}

	gotSig0 := partialSigFor(t, packet1, pub0)
	if !bytes.Equal(gotSig0, wantSig0) {
		t.Fatalf("signer 0 partial sig mismatch:\n got: %x\nwant: %x", gotSig0, wantSig0)
	}

	// ----- Signer 1 (wallet index 1) -----
	signed2, err := w.SignMultisigPSBT(BTC, 1, signed1)
	if err != nil {
		t.Fatalf("SignMultisigPSBT(1): %v", err)
	}

	packet2, err := psbt.NewFromRawBytes(bytes.NewReader(signed2), false)
	if err != nil {
		t.Fatalf("psbt parse after signer 1: %v", err)
	}

	// Confirm two partial sigs are now present.
	if got := len(packet2.Inputs[0].PartialSigs); got != 2 {
		t.Fatalf("expected 2 partial sigs after signer 1, got %d", got)
	}

	priv1 := btcWalletKeyAt(t, w, 1)
	wantSig1, err := txscript.RawTxInWitnessSignature(
		packet2.UnsignedTx, sigHashes, 0, utxoAmount, witnessScript,
		txscript.SigHashAll, priv1,
	)
	if err != nil {
		t.Fatalf("btcd oracle signer 1: %v", err)
	}

	gotSig1 := partialSigFor(t, packet2, pub1)
	if !bytes.Equal(gotSig1, wantSig1) {
		t.Fatalf("signer 1 partial sig mismatch:\n got: %x\nwant: %x", gotSig1, wantSig1)
	}

	// ----- Finalize + Extract -----
	// FinalizeMultisigPSBT assembles the witness stack.
	finalized, err := FinalizeMultisigPSBT(signed2)
	if err != nil {
		t.Fatalf("FinalizeMultisigPSBT: %v", err)
	}
	txBytes, err := ExtractMultisigTx(finalized)
	if err != nil {
		t.Fatalf("ExtractMultisigTx: %v", err)
	}

	// Deserialize and run btcd's script engine.
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(txBytes)); err != nil {
		t.Fatalf("tx deserialize: %v", err)
	}
	btcEngineVerify(t, &msg, in.Utxo)

	// ExtractMultisigTx should also auto-finalize a non-finalized PSBT.
	txBytes2, err := ExtractMultisigTx(signed2) // signed2 is not yet finalized
	if err != nil {
		t.Fatalf("ExtractMultisigTx(auto-finalize): %v", err)
	}
	if !bytes.Equal(txBytes, txBytes2) {
		t.Fatalf("auto-finalized tx differs from explicitly finalized tx")
	}
}

// ---- P2SH round-trip with btcd oracle ----

// TestMultisigP2SHBtcdOracle builds a 2-of-3 P2SH PSBT, signs it with the
// wallet's index-0 and index-1 keys, and:
//   - pins each partial signature byte-for-byte against btcd's
//     txscript.RawTxInSignature (legacy, RFC 6979 deterministic)
//   - verifies the extracted transaction via btcd's script engine
//
// Vector source: btcd txscript oracle on "abandon … about" (canonical mnemonic).
func TestMultisigP2SHBtcdOracle(t *testing.T) {
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

	// Build the 2-of-3 redeemScript (BIP-67 sorted).
	redeemScript, err := BuildMultisigRedeemScript(2, [][]byte{pub0, pub1, multisig3rdPubKey})
	if err != nil {
		t.Fatalf("BuildMultisigRedeemScript: %v", err)
	}

	// Construct the P2SH scriptPubKey: OP_HASH160 <hash160(redeemScript)> OP_EQUAL
	rsh160 := hash160(redeemScript)
	utxoScript := append(append([]byte{0xa9, 0x14}, rsh160...), 0x87)
	const utxoAmount = int64(50_000)

	to, err := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 2)
	if err != nil {
		t.Fatalf("BitcoinAddress(to): %v", err)
	}
	change, err := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)
	if err != nil {
		t.Fatalf("BitcoinAddress(change): %v", err)
	}

	in := &txbtc.SigningInput{
		Amount:        20_000,
		ByteFee:       1,
		ToAddress:     to,
		ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash:     mustHex(t, dummyPrevTxid),
			OutPointIndex:    0,
			OutPointSequence: 0xffffffff,
			Amount:           utxoAmount,
			Script:           utxoScript,
		}},
	}

	// Build unsigned PSBT.
	unsigned, err := BuildMultisigPSBT(BTC, in, redeemScript)
	if err != nil {
		t.Fatalf("BuildMultisigPSBT: %v", err)
	}

	// ----- Signer 0 -----
	signed1, err := w.SignMultisigPSBT(BTC, 0, unsigned)
	if err != nil {
		t.Fatalf("SignMultisigPSBT(0): %v", err)
	}

	packet1, err := psbt.NewFromRawBytes(bytes.NewReader(signed1), false)
	if err != nil {
		t.Fatalf("psbt parse after signer 0: %v", err)
	}
	if got := len(packet1.Inputs[0].PartialSigs); got != 1 {
		t.Fatalf("expected 1 partial sig after signer 0, got %d", got)
	}

	// Oracle: compute expected sig via btcd's legacy signer.
	priv0 := btcWalletKeyAt(t, w, 0)
	wantSig0, err := txscript.RawTxInSignature(
		packet1.UnsignedTx, 0, redeemScript, txscript.SigHashAll, priv0,
	)
	if err != nil {
		t.Fatalf("btcd oracle signer 0: %v", err)
	}

	gotSig0 := partialSigFor(t, packet1, pub0)
	if !bytes.Equal(gotSig0, wantSig0) {
		t.Fatalf("signer 0 partial sig mismatch:\n got: %x\nwant: %x", gotSig0, wantSig0)
	}

	// ----- Signer 1 -----
	signed2, err := w.SignMultisigPSBT(BTC, 1, signed1)
	if err != nil {
		t.Fatalf("SignMultisigPSBT(1): %v", err)
	}

	packet2, err := psbt.NewFromRawBytes(bytes.NewReader(signed2), false)
	if err != nil {
		t.Fatalf("psbt parse after signer 1: %v", err)
	}
	if got := len(packet2.Inputs[0].PartialSigs); got != 2 {
		t.Fatalf("expected 2 partial sigs after signer 1, got %d", got)
	}

	priv1 := btcWalletKeyAt(t, w, 1)
	wantSig1, err := txscript.RawTxInSignature(
		packet2.UnsignedTx, 0, redeemScript, txscript.SigHashAll, priv1,
	)
	if err != nil {
		t.Fatalf("btcd oracle signer 1: %v", err)
	}

	gotSig1 := partialSigFor(t, packet2, pub1)
	if !bytes.Equal(gotSig1, wantSig1) {
		t.Fatalf("signer 1 partial sig mismatch:\n got: %x\nwant: %x", gotSig1, wantSig1)
	}

	// ----- Finalize + Extract -----
	finalized, err := FinalizeMultisigPSBT(signed2)
	if err != nil {
		t.Fatalf("FinalizeMultisigPSBT: %v", err)
	}
	txBytes, err := ExtractMultisigTx(finalized)
	if err != nil {
		t.Fatalf("ExtractMultisigTx: %v", err)
	}

	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(txBytes)); err != nil {
		t.Fatalf("tx deserialize: %v", err)
	}

	// The UTXO for btcEngineVerify must carry the P2SH scriptPubKey.
	btcEngineVerify(t, &msg, in.Utxo)

	// ExtractMultisigTx auto-finalize test.
	txBytes2, err := ExtractMultisigTx(signed2)
	if err != nil {
		t.Fatalf("ExtractMultisigTx(auto-finalize): %v", err)
	}
	if !bytes.Equal(txBytes, txBytes2) {
		t.Fatalf("auto-finalized tx differs from explicitly finalized tx")
	}
}

// ---- signer-not-in-script is skipped ----

// TestMultisigSkipNonParticipant verifies that SignMultisigPSBT silently skips
// inputs whose redeemScript/witnessScript does not contain the signing key
// (the co-signer flow).
func TestMultisigSkipNonParticipant(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub0, _ := w.PublicKeyIndex(BTC, 0)
	pub1, _ := w.PublicKeyIndex(BTC, 1)

	// 1-of-2 script that does NOT contain key at index 5.
	witnessScript, err := BuildMultisigRedeemScript(1, [][]byte{pub0, pub1})
	if err != nil {
		t.Fatalf("BuildMultisigRedeemScript: %v", err)
	}

	h := sha256.Sum256(witnessScript)
	utxoScript := append([]byte{0x00, 0x20}, h[:]...)

	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 2)
	chg, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)
	in := &txbtc.SigningInput{
		Amount:        20_000,
		ByteFee:       1,
		ToAddress:     to,
		ChangeAddress: chg,
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash:     mustHex(t, dummyPrevTxid),
			OutPointIndex:    0,
			OutPointSequence: 0xffffffff,
			Amount:           50_000,
			Script:           utxoScript,
		}},
	}

	unsigned, err := BuildMultisigPSBT(BTC, in, witnessScript)
	if err != nil {
		t.Fatalf("BuildMultisigPSBT: %v", err)
	}

	// Key at index 5 is NOT in the script; signing should succeed but skip the input.
	result, err := w.SignMultisigPSBT(BTC, 5, unsigned)
	if err != nil {
		t.Fatalf("SignMultisigPSBT(non-participant): %v", err)
	}

	// Parse and confirm no partial sigs were added.
	packet, err := psbt.NewFromRawBytes(bytes.NewReader(result), false)
	if err != nil {
		t.Fatalf("psbt parse: %v", err)
	}
	if got := len(packet.Inputs[0].PartialSigs); got != 0 {
		t.Fatalf("expected 0 partial sigs for non-participant, got %d", got)
	}
}

// ---- error paths ----

// TestMultisigErrors verifies the error-path behavior of the multisig API.
func TestMultisigErrors(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub0, _ := w.PublicKeyIndex(BTC, 0)
	witnessScript, _ := BuildMultisigRedeemScript(1, [][]byte{pub0, multisig3rdPubKey})
	h := sha256.Sum256(witnessScript)
	utxoScript := append([]byte{0x00, 0x20}, h[:]...)
	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 2)

	chg, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)
	goodInput := func() *txbtc.SigningInput {
		return &txbtc.SigningInput{
			Amount:        20_000,
			ByteFee:       1,
			ToAddress:     to,
			ChangeAddress: chg,
			Utxo: []*txbtc.UnspentTransaction{{
				OutPointHash:     mustHex(t, dummyPrevTxid),
				OutPointIndex:    0,
				OutPointSequence: 0xffffffff,
				Amount:           50_000,
				Script:           utxoScript,
			}},
		}
	}

	t.Run("unsupported-coin", func(t *testing.T) {
		_, err := BuildMultisigPSBT(ETH, goodInput(), witnessScript)
		if !errors.Is(err, ErrTxUnsupported) {
			t.Fatalf("BuildMultisigPSBT(ETH): want ErrTxUnsupported, got %v", err)
		}
	})

	t.Run("empty-utxo", func(t *testing.T) {
		in := goodInput()
		in.Utxo = nil
		_, err := BuildMultisigPSBT(BTC, in, witnessScript)
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("empty utxo: want ErrTxInput, got %v", err)
		}
	})

	t.Run("missing-to-address", func(t *testing.T) {
		in := goodInput()
		in.ToAddress = ""
		_, err := BuildMultisigPSBT(BTC, in, witnessScript)
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("missing to_address: want ErrTxInput, got %v", err)
		}
	})

	t.Run("empty-redeem-script", func(t *testing.T) {
		_, err := BuildMultisigPSBT(BTC, goodInput(), nil)
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("empty redeemScript: want ErrTxInput, got %v", err)
		}
	})

	t.Run("p2pkh-input-rejected", func(t *testing.T) {
		// P2PKH inputs are not allowed in multisig PSBTs.
		p2pkhScript := append(append([]byte{0x76, 0xa9, 0x14}, hash160(pub0)...), 0x88, 0xac)
		in := &txbtc.SigningInput{
			Amount:    20_000,
			ByteFee:   1,
			ToAddress: to,
			Utxo: []*txbtc.UnspentTransaction{{
				OutPointHash:     mustHex(t, dummyPrevTxid),
				OutPointIndex:    0,
				OutPointSequence: 0xffffffff,
				Amount:           50_000,
				Script:           p2pkhScript,
			}},
		}
		_, err := BuildMultisigPSBT(BTC, in, witnessScript)
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("P2PKH input: want ErrTxInput, got %v", err)
		}
	})

	t.Run("malformed-psbt", func(t *testing.T) {
		_, err := w.SignMultisigPSBT(BTC, 0, []byte("not a psbt"))
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("malformed PSBT: want ErrTxInput, got %v", err)
		}
	})

	t.Run("finalize-malformed", func(t *testing.T) {
		_, err := FinalizeMultisigPSBT([]byte("not a psbt"))
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("FinalizeMultisigPSBT(bad): want ErrTxInput, got %v", err)
		}
	})

	t.Run("extract-malformed", func(t *testing.T) {
		_, err := ExtractMultisigTx([]byte("not a psbt"))
		if !errors.Is(err, ErrTxInput) {
			t.Fatalf("ExtractMultisigTx(bad): want ErrTxInput, got %v", err)
		}
	})

	t.Run("finalize-unsigned", func(t *testing.T) {
		unsigned, err := BuildMultisigPSBT(BTC, goodInput(), witnessScript)
		if err != nil {
			t.Fatalf("BuildMultisigPSBT: %v", err)
		}
		// An unsigned PSBT (no partial sigs) must not finalize.
		_, err = FinalizeMultisigPSBT(unsigned)
		if err == nil {
			t.Fatal("FinalizeMultisigPSBT(unsigned): expected error, got nil")
		}
	})
}

// ---- BIP-174 multisig PSBT vector ----

// TestMultisigBIP174PSBTVector builds a fully-signed P2WSH PSBT, re-parses it
// from its binary form (as a BIP-174 interoperability round-trip), finalizes
// via btcd's MaybeFinalizeAll, and verifies the extracted tx under btcd's
// script engine.  This is the BIP-174 multisig "combine/finalize" workflow.
func TestMultisigBIP174PSBTVector(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub0, _ := w.PublicKeyIndex(BTC, 0)
	pub1, _ := w.PublicKeyIndex(BTC, 1)

	witnessScript, _ := BuildMultisigRedeemScript(2, [][]byte{pub0, pub1, multisig3rdPubKey})
	h := sha256.Sum256(witnessScript)
	utxoScript := append([]byte{0x00, 0x20}, h[:]...)

	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 2)
	chg, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)
	in := &txbtc.SigningInput{
		Amount:        20_000,
		ByteFee:       1,
		ToAddress:     to,
		ChangeAddress: chg,
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash:     mustHex(t, dummyPrevTxid),
			OutPointIndex:    0,
			OutPointSequence: 0xffffffff,
			Amount:           50_000,
			Script:           utxoScript,
		}},
	}

	unsigned, _ := BuildMultisigPSBT(BTC, in, witnessScript)
	signed1, _ := w.SignMultisigPSBT(BTC, 0, unsigned)
	signed2, _ := w.SignMultisigPSBT(BTC, 1, signed1)

	// Round-trip: re-parse from raw bytes (simulates receiving the PSBT from another participant).
	packet, err := psbt.NewFromRawBytes(bytes.NewReader(signed2), false)
	if err != nil {
		t.Fatalf("BIP-174 NewFromRawBytes: %v", err)
	}
	if err := packet.SanityCheck(); err != nil {
		t.Fatalf("BIP-174 SanityCheck: %v", err)
	}

	// Finalize via btcd's own MaybeFinalizeAll.
	if err := psbt.MaybeFinalizeAll(packet); err != nil {
		t.Fatalf("BIP-174 MaybeFinalizeAll: %v", err)
	}
	if !packet.IsComplete() {
		t.Fatal("BIP-174 packet not complete after finalize")
	}

	// Extract and run the engine.
	finalTx, err := psbt.Extract(packet)
	if err != nil {
		t.Fatalf("BIP-174 Extract: %v", err)
	}
	var buf bytes.Buffer
	if err := finalTx.Serialize(&buf); err != nil {
		t.Fatalf("BIP-174 serialize: %v", err)
	}
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("wire deserialize: %v", err)
	}
	btcEngineVerify(t, &msg, in.Utxo)
}

// ---- P2SH mismatched hash rejected ----

// TestMultisigP2SHHashMismatch verifies that BuildMultisigPSBT rejects a P2SH
// input whose scriptPubKey hash does not match hash160(redeemScript).
func TestMultisigP2SHHashMismatch(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub0, _ := w.PublicKeyIndex(BTC, 0)
	pub1, _ := w.PublicKeyIndex(BTC, 1)

	redeemScript, _ := BuildMultisigRedeemScript(2, [][]byte{pub0, pub1, multisig3rdPubKey})

	// Construct a P2SH scriptPubKey whose hash is WRONG (all zeros).
	wrongScript := make([]byte, 23)
	wrongScript[0] = 0xa9
	wrongScript[1] = 0x14
	// bytes 2..21 are zero (wrong hash)
	wrongScript[22] = 0x87

	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 2)
	chg, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)
	in := &txbtc.SigningInput{
		Amount:        20_000,
		ByteFee:       1,
		ToAddress:     to,
		ChangeAddress: chg,
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash:     mustHex(t, dummyPrevTxid),
			OutPointIndex:    0,
			OutPointSequence: 0xffffffff,
			Amount:           50_000,
			Script:           wrongScript,
		}},
	}

	_, err = BuildMultisigPSBT(BTC, in, redeemScript)
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("P2SH hash mismatch: want ErrTxInput, got %v", err)
	}
}

// ---- helpers (local to this file) ----
