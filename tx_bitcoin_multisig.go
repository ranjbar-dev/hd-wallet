package hdwallet

// Bitcoin m-of-n multisig — P2SH (legacy) and P2WSH (native SegWit) spend.
//
// This file provides the building blocks for multi-signature Bitcoin workflows
// layered on top of the BIP-174 PSBT machinery (tx_bitcoin_psbt.go).  The
// public surface is:
//
//   BuildMultisigRedeemScript  – OP_m <BIP-67 sorted pubkeys> OP_n OP_CHECKMULTISIG
//   MultisigP2SHAddress        – P2SH (3…) address for a redeem script
//   MultisigP2WSHAddress       – native-SegWit P2WSH (bc1q…) address
//   BuildMultisigPSBT          – unsigned BIP-174 PSBT for a multisig spend
//   SignMultisigPSBT           – adds this signer's partial sig to the PSBT
//   FinalizeMultisigPSBT       – assembles scriptSig/witness once m sigs present
//   ExtractMultisigTx          – extracts the network-serialized signed transaction
//
// Supported input types (detected from the UTXO scriptPubKey):
//   P2SH  (23-byte a9 14 … 87) – legacy pre-SegWit; signed with CalcSignatureHash
//   P2WSH (34-byte 00 20 …)    – native SegWit v0; signed with CalcWitnessSigHash
//
// Roadmap: P2SH-P2WSH nested (redeem = OP_0 sha256(witnessScript) wrapped in
// P2SH) is deferred — it needs a third classification branch and no authoritative
// TWC vector is available yet.
//
// Correctness: tx_bitcoin_multisig_test.go pins the P2WSH and P2SH paths
// against btcd's txscript signer (RawTxInWitnessSignature /
// RawTxInSignature — both RFC 6979 deterministic) and asserts byte-identical
// DER signatures once finalized.  BIP-67 sorting is verified against a
// known reference vector.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// isP2WSH reports whether script is a 34-byte native SegWit v0 P2WSH program:
// OP_0 <32-byte sha256>.
func isP2WSH(script []byte) bool {
	return len(script) == 34 && script[0] == 0x00 && script[1] == 0x20
}

// ---- script building ----

// BuildMultisigRedeemScript returns an OP_m <pubkeys> OP_n OP_CHECKMULTISIG
// script with the pubkeys sorted lexicographically (BIP-67). It is used both
// as the redeemScript for P2SH and as the witnessScript for P2WSH.
//
// Constraints: 1 ≤ m ≤ n ≤ 16; every pubkey must be a 33-byte compressed point.
func BuildMultisigRedeemScript(m int, pubkeys [][]byte) ([]byte, error) {
	n := len(pubkeys)
	if m < 1 || n < 1 || m > n || n > 16 {
		return nil, fmt.Errorf("%w: bitcoin: multisig: m=%d n=%d: require 1 ≤ m ≤ n ≤ 16", ErrTxInput, m, n)
	}
	for i, pk := range pubkeys {
		if len(pk) != 33 {
			return nil, fmt.Errorf("%w: bitcoin: multisig: pubkey %d must be 33-byte compressed", ErrTxInput, i)
		}
	}

	// BIP-67: sort pubkeys lexicographically (bytes.Compare on compressed form).
	sorted := make([][]byte, n)
	copy(sorted, pubkeys)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i], sorted[j]) < 0
	})

	// OP_m <key1> <key2> ... <keyN> OP_n OP_CHECKMULTISIG
	// OP_m: 0x50 + m (OP_1=0x51, OP_2=0x52, …, OP_16=0x60)
	script := []byte{byte(0x50 + m)} // #nosec G115 -- m validated 1..16
	for _, pk := range sorted {
		script = append(script, btcPush(pk)...)
	}
	script = append(script, byte(0x50+n)) // #nosec G115 -- n validated 1..16
	script = append(script, 0xae)         // OP_CHECKMULTISIG
	return script, nil
}

// ---- address derivation ----

// MultisigP2SHAddress returns the P2SH address for redeemScript on symbol.
// Only chains in btcAddrParams (BTC, LTC, DGB, SYS, VIA, STRAX) are supported.
func MultisigP2SHAddress(symbol Symbol, redeemScript []byte) (string, error) {
	p, ok := btcAddrParams[symbol]
	if !ok {
		return "", fmt.Errorf("%w: %s has no P2SH multisig address support", ErrUnsupportedCoin, symbol)
	}
	return base58.CheckEncode(hash160(redeemScript), p.p2shVer), nil
}

// MultisigP2WSHAddress returns the native-SegWit P2WSH bech32 address for
// witnessScript on symbol (the same script as the redeemScript — just the name
// changes to match BIP-141 terminology). Only chains in btcAddrParams are
// supported.
func MultisigP2WSHAddress(symbol Symbol, witnessScript []byte) (string, error) {
	p, ok := btcAddrParams[symbol]
	if !ok {
		return "", fmt.Errorf("%w: %s has no P2WSH multisig address support", ErrUnsupportedCoin, symbol)
	}
	h := sha256.Sum256(witnessScript)
	conv, err := bech32.ConvertBits(h[:], 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("hdwallet: bitcoin: multisig: bech32 convert: %w", err)
	}
	// Witness version 0 → bech32 (not bech32m)
	addr, err := bech32.Encode(p.hrp, append([]byte{0x00}, conv...))
	if err != nil {
		return "", fmt.Errorf("hdwallet: bitcoin: multisig: bech32 encode: %w", err)
	}
	return addr, nil
}

// ---- PSBT build ----

// BuildMultisigPSBT constructs an unsigned BIP-174 PSBT for spending a
// multisig UTXO. redeemScript is the m-of-n script produced by
// BuildMultisigRedeemScript (for P2SH it is also the redeemScript; for P2WSH
// it becomes the witnessScript). The type (P2SH or P2WSH) is inferred from
// each UTXO's scriptPubKey in in.
//
// Coin selection uses the same planBitcoinTx logic as the single-key path.
// Fee estimation is approximate — it assumes P2SH/P2WSH per-type overhead and
// does not model the extra witness bytes of multisig scripts; callers should
// add headroom if byte-exact fees matter.
//
// Only chains in btcAddrParams (BTC, LTC, and the native-SegWit altcoins) are
// accepted. Legacy P2PKH inputs in in.Utxo are rejected (same reason as the
// single-key PSBT path: no full prev-tx in the proto).
func BuildMultisigPSBT(symbol Symbol, in *txbtc.SigningInput, redeemScript []byte) ([]byte, error) {
	if _, ok := btcAddrParams[symbol]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrTxUnsupported, symbol)
	}
	if len(in.GetUtxo()) == 0 {
		return nil, fmt.Errorf("%w: bitcoin: multisig: no utxo provided", ErrTxInput)
	}
	if in.GetToAddress() == "" {
		return nil, fmt.Errorf("%w: bitcoin: multisig: missing to_address", ErrTxInput)
	}
	if len(redeemScript) == 0 {
		return nil, fmt.Errorf("%w: bitcoin: multisig: redeemScript is empty", ErrTxInput)
	}

	toScript, err := bitcoinDecodeScript(symbol, in.GetToAddress())
	if err != nil {
		return nil, fmt.Errorf("%w: bitcoin: multisig: to_address: %v", ErrTxInput, err)
	}
	plan, err := planBitcoinTx(symbol, in, toScript)
	if err != nil {
		return nil, err
	}

	// Build the unsigned wire tx.
	outpoints := make([]*wire.OutPoint, len(plan.inputs))
	sequences := make([]uint32, len(plan.inputs))
	for i, bi := range plan.inputs {
		var h chainhash.Hash
		copy(h[:], bi.txid)
		outpoints[i] = &wire.OutPoint{Hash: h, Index: bi.vout}
		sequences[i] = bi.sequence
	}
	txouts := make([]*wire.TxOut, len(plan.outputs))
	for i, o := range plan.outputs {
		txouts[i] = wire.NewTxOut(o.value, o.script)
	}
	const version int32 = 2
	packet, err := psbt.New(outpoints, txouts, version, in.GetLockTime(), sequences)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: multisig: psbt create: %w", err)
	}

	updater, err := psbt.NewUpdater(packet)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: multisig: psbt updater: %w", err)
	}

	for i, bi := range plan.inputs {
		switch {
		case isP2PKH(bi.script):
			// Legacy P2PKH cannot be used in a multisig PSBT without the full
			// previous transaction; reject it the same way newUnsignedPacket does.
			return nil, fmt.Errorf("%w: bitcoin: multisig: input %d is P2PKH; only P2SH or P2WSH multisig inputs are supported here", ErrTxInput, i)

		case isP2WSH(bi.script):
			// Native SegWit P2WSH: attach witness UTXO and the witness script.
			if err := updater.AddInWitnessUtxo(wire.NewTxOut(bi.amount, bi.script), i); err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: multisig: input %d: witness utxo: %w", i, err)
			}
			if err := updater.AddInWitnessScript(redeemScript, i); err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: multisig: input %d: witness script: %w", i, err)
			}

		case isP2SHP2WPKH(bi.script): // 23-byte P2SH — check it wraps our redeemScript
			if !bytesEqual(hash160(redeemScript), bi.script[2:22]) {
				return nil, fmt.Errorf("%w: bitcoin: multisig: input %d: P2SH scriptPubKey does not match hash160(redeemScript)", ErrTxInput, i)
			}
			// Legacy P2SH multisig: the BIP-174 finalizer needs a NonWitnessUtxo.
			// We construct a minimal fake previous tx that has the right output at
			// the right index. The sighash (CalcSignatureHash) does not depend on
			// the previous-tx content — only the unsigned tx and the subscript
			// (redeemScript) enter the preimage — so the fake tx is safe.
			fakePrevTx := multisigFakePrevTx(bi.vout, bi.amount, bi.script)
			if err := updater.AddInNonWitnessUtxo(fakePrevTx, i); err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: multisig: input %d: non-witness utxo: %w", i, err)
			}
			if err := updater.AddInRedeemScript(redeemScript, i); err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: multisig: input %d: redeem script: %w", i, err)
			}

		default:
			return nil, fmt.Errorf("%w: bitcoin: multisig: input %d: scriptPubKey is not P2SH or P2WSH", ErrTxInput, i)
		}
	}
	return serializePacket(packet)
}

// ---- PSBT signing ----

// SignMultisigPSBT signs every multisig input in psbtBytes that is controlled
// by the (symbol, index) key and attaches the partial signature. If an input
// does not contain this wallet's pubkey in its redeemScript/witnessScript the
// input is silently skipped (another co-signer owns it). The updated PSBT is
// returned.
//
// The leaf private key is derived under the package's wiped-on-return
// discipline; no raw key bytes leave the package.
func (w *HDWallet) SignMultisigPSBT(symbol Symbol, index uint32, psbtBytes []byte) ([]byte, error) {
	if _, ok := btcAddrParams[symbol]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrTxUnsupported, symbol)
	}
	packet, err := parsePacket(psbtBytes)
	if err != nil {
		return nil, err
	}
	pub, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(pub) != 33 {
		return nil, fmt.Errorf("%w: bitcoin: multisig: expected 33-byte compressed key", ErrTxInput)
	}

	// Build a prevout fetcher from all WitnessUtxo fields (needed for
	// CalcWitnessSigHash / NewTxSigHashes). P2SH inputs that use NonWitnessUtxo
	// are signed via CalcSignatureHash, which does not touch the fetcher.
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(packet.Inputs))
	for i := range packet.Inputs {
		inp := &packet.Inputs[i]
		if inp.WitnessUtxo != nil {
			prevOuts[packet.UnsignedTx.TxIn[i].PreviousOutPoint] = inp.WitnessUtxo
		} else if inp.NonWitnessUtxo != nil {
			// Expose the prevout from the fake NonWitnessUtxo so that
			// NewTxSigHashes does not panic when iterating.
			outIdx := packet.UnsignedTx.TxIn[i].PreviousOutPoint.Index
			if int(outIdx) < len(inp.NonWitnessUtxo.TxOut) { // #nosec G115 -- bounded by wire.MsgTx output count
				prevOuts[packet.UnsignedTx.TxIn[i].PreviousOutPoint] = inp.NonWitnessUtxo.TxOut[outIdx]
			}
		}
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(packet.UnsignedTx, fetcher)

	updater, err := psbt.NewUpdater(packet)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: multisig: psbt updater: %w", err)
	}

	hashType := uint32(txscript.SigHashAll)

	for i := range packet.Inputs {
		inp := &packet.Inputs[i]

		// Already finalized?
		if len(inp.FinalScriptSig) > 0 || len(inp.FinalScriptWitness) > 0 {
			continue
		}

		// Determine the redeemScript / witnessScript and sign accordingly.
		switch {

		case inp.WitnessScript != nil:
			// P2WSH multisig input.
			if !multisigContainsPubkey(inp.WitnessScript, pub) {
				continue // our key is not a participant; skip
			}
			// BIP-143 sighash with the witnessScript as the scriptCode.
			digest, err := txscript.CalcWitnessSigHash(
				inp.WitnessScript, sigHashes, txscript.SigHashAll,
				packet.UnsignedTx, i, inp.WitnessUtxo.Value,
			)
			if err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: multisig: input %d: p2wsh sighash: %w", i, err)
			}
			sig, err := w.btcDERSig(symbol, index, digest, hashType)
			if err != nil {
				return nil, err
			}
			outcome, err := updater.Sign(i, sig, pub, nil, inp.WitnessScript)
			if err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: multisig: input %d: sign: %w", i, err)
			}
			if outcome == psbt.SignInvalid {
				return nil, fmt.Errorf("%w: bitcoin: multisig: input %d: sign outcome invalid", ErrTxInput, i)
			}

		case inp.RedeemScript != nil && !txscript.IsWitnessProgram(inp.RedeemScript):
			// Legacy P2SH multisig input.
			if !multisigContainsPubkey(inp.RedeemScript, pub) {
				continue // not a participant
			}

			// Security: verify the redeemScript's hash160 matches the pkScript
			// of the output being spent.  We cannot use updater.Sign here because
			// it additionally checks NonWitnessUtxo.TxHash() == PreviousOutPoint.Hash —
			// a check that a synthetic (fake) prev tx cannot satisfy.  We bypass
			// updater.Sign and directly append the PartialSig after doing our own
			// script-hash verification, which is the fund-critical invariant.
			outIdx := packet.UnsignedTx.TxIn[i].PreviousOutPoint.Index
			if inp.NonWitnessUtxo == nil || int(outIdx) >= len(inp.NonWitnessUtxo.TxOut) { // #nosec G115
				return nil, fmt.Errorf("%w: bitcoin: multisig: input %d: NonWitnessUtxo missing or outIdx out of range", ErrTxInput, i)
			}
			wantPkScript := inp.NonWitnessUtxo.TxOut[outIdx].PkScript
			wantScriptHash := hash160(inp.RedeemScript)
			gotPkScript, scriptErr := txscript.NewScriptBuilder().
				AddOp(txscript.OP_HASH160).
				AddData(wantScriptHash).
				AddOp(txscript.OP_EQUAL).
				Script()
			if scriptErr != nil || !bytes.Equal(gotPkScript, wantPkScript) {
				return nil, fmt.Errorf("%w: bitcoin: multisig: input %d: redeemScript hash mismatch", ErrTxInput, i)
			}

			// Legacy sighash: the subscript for P2SH is the redeemScript.
			digest, err := txscript.CalcSignatureHash(
				inp.RedeemScript, txscript.SigHashAll, packet.UnsignedTx, i,
			)
			if err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: multisig: input %d: p2sh sighash: %w", i, err)
			}
			sig, err := w.btcDERSig(symbol, index, digest, hashType)
			if err != nil {
				return nil, err
			}
			// Append partial sig directly — the updater's Sign path is
			// bypassed because it cannot verify a synthetic NonWitnessUtxo.
			packet.Inputs[i].PartialSigs = append(packet.Inputs[i].PartialSigs,
				&psbt.PartialSig{PubKey: pub, Signature: sig})

		default:
			return nil, fmt.Errorf("%w: bitcoin: multisig: input %d: no redeemScript or witnessScript found; BuildMultisigPSBT must be called first", ErrTxInput, i)
		}
	}
	return serializePacket(packet)
}

// ---- PSBT finalize / extract ----

// FinalizeMultisigPSBT runs the BIP-174 finalizer over a signed multisig PSBT
// and returns the finalized packet bytes.  The finalizer assembles:
//   - P2SH:  OP_FALSE <ordered-sigs...> <redeemScript>  as the scriptSig
//   - P2WSH: <nil> <ordered-sigs...> <witnessScript>    as the witness stack
//
// btcd's finalizer orders signatures by the position of the corresponding
// pubkey in the redeemScript/witnessScript (required for multisig validation).
// It returns an error if fewer than m signatures are present.
func FinalizeMultisigPSBT(psbtBytes []byte) ([]byte, error) {
	packet, err := parsePacket(psbtBytes)
	if err != nil {
		return nil, err
	}
	if err := psbt.MaybeFinalizeAll(packet); err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: multisig: finalize: %w", err)
	}
	return serializePacket(packet)
}

// ExtractMultisigTx finalizes (if needed) a signed multisig PSBT and returns
// the network-serialized signed transaction ready for broadcast.
func ExtractMultisigTx(psbtBytes []byte) ([]byte, error) {
	packet, err := parsePacket(psbtBytes)
	if err != nil {
		return nil, err
	}
	if !packet.IsComplete() {
		if err := psbt.MaybeFinalizeAll(packet); err != nil {
			return nil, fmt.Errorf("hdwallet: bitcoin: multisig: finalize: %w", err)
		}
	}
	finalTx, err := psbt.Extract(packet)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: multisig: extract: %w", err)
	}
	var buf bytes.Buffer
	if err := finalTx.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: multisig: tx serialize: %w", err)
	}
	return buf.Bytes(), nil
}

// ---- internal helpers ----

// multisigContainsPubkey returns true if the 33-byte compressed pubkey appears
// as a pushed data element in script (e.g. a multisig redeemScript).
// It searches for the literal 34-byte sequence: 0x21 <33-byte pubkey>.
func multisigContainsPubkey(script, pub []byte) bool {
	if len(pub) != 33 {
		return false
	}
	needle := append([]byte{0x21}, pub...) // push-33 + pubkey
	return bytes.Contains(script, needle)
}

// multisigFakePrevTx constructs a minimal wire.MsgTx to serve as the
// NonWitnessUtxo for a legacy P2SH input in a BIP-174 PSBT.  The BIP-174
// finalizer only reads TxOut[vout].PkScript; the sighash (CalcSignatureHash)
// does not inspect the previous transaction at all, so the fake tx is safe.
func multisigFakePrevTx(vout uint32, amount int64, pkScript []byte) *wire.MsgTx {
	tx := wire.NewMsgTx(1)
	// A tx with zero inputs serializes as version|0x00|... which is ambiguous
	// with the SegWit marker byte (0x00) + flag byte (0x01); btcd's parser
	// then mis-classifies the format and returns "unexpected EOF".  Add one
	// dummy input so the input-count varint is non-zero.
	tx.TxIn = append(tx.TxIn, wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	// Pad with dummy outputs so that TxOut[vout] is in range.
	for i := uint32(0); i < vout; i++ { // #nosec G115 -- vout is a transaction output index, bounded by the wire format
		tx.TxOut = append(tx.TxOut, wire.NewTxOut(0, nil))
	}
	tx.TxOut = append(tx.TxOut, wire.NewTxOut(amount, pkScript))
	return tx
}
