package hdwallet

// Bitcoin PSBT (BIP-174) build / sign / finalize / extract.
//
// This is a thin, fund-safe wrapper over github.com/btcsuite/btcd/btcutil/psbt
// (the reference Go BIP-174 implementation, already part of the required btcd
// module) — the BIP-174 key/value serialization is NEVER hand-rolled here.
//
//   - BuildPSBT     constructs an unsigned psbt.Packet from a bitcoin.SigningInput
//                   (its already-selected UTXOs as inputs, to/change as outputs)
//                   and returns the serialized packet.
//   - SignPSBT      derives the (symbol,index) leaf key under the package's usual
//                   wiped-on-return discipline, signs every input with the same
//                   sighash/curve primitives as the direct signer, attaches the
//                   results to the packet and returns the updated serialization.
//   - FinalizePSBT  runs the BIP-174 Finalizer over a (fully signed) packet.
//   - ExtractPSBTTx extracts the network-serialized signed transaction.
//
// Because the partial signatures are produced with the identical RFC-6979
// deterministic low-S secp256k1 signer (and BIP-340 Schnorr for taproot) used by
// the direct signBitcoinTx path, a finalize+extract of a P2WPKH PSBT yields the
// exact same raw transaction bytes as SignTransaction — proven in
// tx_bitcoin_psbt_test.go.
//
// Supported input types: native P2WPKH, nested P2SH-P2WPKH, Taproot key-path,
// and legacy P2PKH. For P2PKH, BIP-174 requires a NonWitnessUtxo (the full
// previous transaction); since the SigningInput proto does not carry one, a
// synthetic prev-tx is constructed using the same multisigFakePrevTx pattern as
// the multisig flow. The legacy sighash (CalcSignatureHash) does not inspect the
// previous-transaction content — only the unsigned tx and the subscript (the
// P2PKH scriptPubKey) enter the preimage — so the synthetic tx is safe.

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// BuildPSBT builds an unsigned PSBT (BIP-174) for symbol from in, returning the
// serialized packet. Coin selection (planBitcoinTx) chooses which UTXOs become
// inputs and computes the recipient/change outputs exactly as the direct signer
// would, so a subsequent SignPSBT/FinalizePSBT/ExtractPSBTTx produces the same
// transaction. Supported input types: P2WPKH, P2SH-P2WPKH, P2TR, and legacy
// P2PKH (via a synthetic NonWitnessUtxo using multisigFakePrevTx).
func BuildPSBT(symbol Symbol, in *txbtc.SigningInput) ([]byte, error) {
	if _, ok := btcAddrParams[symbol]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrTxUnsupported, symbol)
	}
	if len(in.GetUtxo()) == 0 {
		return nil, fmt.Errorf("%w: bitcoin: no utxo provided", ErrTxInput)
	}
	if in.GetToAddress() == "" {
		return nil, fmt.Errorf("%w: bitcoin: missing to_address", ErrTxInput)
	}

	toScript, err := bitcoinDecodeScript(symbol, in.GetToAddress())
	if err != nil {
		return nil, fmt.Errorf("%w: bitcoin: to_address: %v", ErrTxInput, err)
	}
	plan, err := planBitcoinTx(symbol, in, toScript)
	if err != nil {
		return nil, err
	}

	packet, err := newUnsignedPacket(plan)
	if err != nil {
		return nil, err
	}
	return serializePacket(packet)
}

// newUnsignedPacket turns a coin-selection plan into an unsigned psbt.Packet with
// a WitnessUtxo set on every input.
func newUnsignedPacket(plan *btcPlan) (*psbt.Packet, error) {
	outpoints := make([]*wire.OutPoint, len(plan.inputs))
	sequences := make([]uint32, len(plan.inputs))
	for i, in := range plan.inputs {
		var h chainhash.Hash
		copy(h[:], in.txid)
		outpoints[i] = &wire.OutPoint{Hash: h, Index: in.vout}
		sequences[i] = in.sequence
	}
	txouts := make([]*wire.TxOut, len(plan.outputs))
	for i, o := range plan.outputs {
		txouts[i] = wire.NewTxOut(o.value, o.script)
	}

	const version int32 = 2
	packet, err := psbt.New(outpoints, txouts, version, 0, sequences)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: psbt create: %w", err)
	}

	updater, err := psbt.NewUpdater(packet)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: psbt updater: %w", err)
	}
	for i, in := range plan.inputs {
		if isP2PKH(in.script) {
			// BIP-174 requires a NonWitnessUtxo for legacy (non-witness) inputs.
			// The proto does not carry the full previous transaction, so we build a
			// synthetic one using the same pattern as the multisig P2SH path.
			// CalcSignatureHash does not inspect the previous-tx content; only the
			// unsigned tx and the P2PKH subscript enter the sighash preimage.
			// We pass in.vout so TxOut[in.vout] holds our script (the btcd finalizer
			// reads NonWitnessUtxo.TxOut[PreviousOutPoint.Index]).
			fakePrevTx := multisigFakePrevTx(in.vout, in.amount, in.script)
			if err := updater.AddInNonWitnessUtxo(fakePrevTx, i); err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: psbt non-witness utxo: %w", err)
			}
			continue
		}
		if err := updater.AddInWitnessUtxo(wire.NewTxOut(in.amount, in.script), i); err != nil {
			return nil, fmt.Errorf("hdwallet: bitcoin: psbt witness utxo: %w", err)
		}
	}
	return packet, nil
}

// SignPSBT parses psbtBytes, signs every input controlled by the (symbol,index)
// key, attaches the signatures, and returns the updated serialized PSBT. The leaf
// key is derived under the package's seed discipline and wiped on return.
func (w *HDWallet) SignPSBT(symbol Symbol, index uint32, psbtBytes []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("%w: bitcoin: expected 33-byte compressed key", ErrTxInput)
	}

	if err := w.signPacketInputs(symbol, index, packet, pub); err != nil {
		return nil, err
	}
	return serializePacket(packet)
}

// signPacketInputs signs each input of packet per its scriptPubKey type, using
// btcd's sighash primitives over our derived key so the partial signatures match
// the direct signer byte-for-byte.
func (w *HDWallet) signPacketInputs(symbol Symbol, index uint32, packet *psbt.Packet, pub []byte) error {
	prevFetcher, err := psbtPrevOutFetcher(packet)
	if err != nil {
		return err
	}
	sigHashes := txscript.NewTxSigHashes(packet.UnsignedTx, prevFetcher)
	updater, err := psbt.NewUpdater(packet)
	if err != nil {
		return fmt.Errorf("hdwallet: bitcoin: psbt updater: %w", err)
	}

	for i := range packet.Inputs {
		pIn := &packet.Inputs[i]

		// Resolve the scriptPubKey. For witness inputs it comes from WitnessUtxo;
		// for legacy P2PKH inputs it comes from the NonWitnessUtxo.
		var script []byte
		var amount int64
		if pIn.WitnessUtxo != nil {
			script = pIn.WitnessUtxo.PkScript
			amount = pIn.WitnessUtxo.Value
		} else if pIn.NonWitnessUtxo != nil {
			outIdx := packet.UnsignedTx.TxIn[i].PreviousOutPoint.Index
			if int(outIdx) >= len(pIn.NonWitnessUtxo.TxOut) { // #nosec G115 -- bounded by wire.MsgTx output count
				return fmt.Errorf("%w: bitcoin: psbt input %d NonWitnessUtxo outIdx out of range", ErrTxInput, i)
			}
			script = pIn.NonWitnessUtxo.TxOut[outIdx].PkScript
			amount = pIn.NonWitnessUtxo.TxOut[outIdx].Value
		} else {
			return fmt.Errorf("%w: bitcoin: psbt input %d missing both WitnessUtxo and NonWitnessUtxo", ErrTxInput, i)
		}
		_ = amount // used below for segwit branches

		switch {
		case isP2PKH(script):
			keyhash := script[3:23] // 76 a9 14 <20-byte hash> 88 ac
			if !bytesEqual(hash160(pub), keyhash) {
				return fmt.Errorf("%w: bitcoin: psbt input %d not controlled by key", ErrTxInput, i)
			}
			// Legacy sighash: the P2PKH scriptPubKey is the subscript.
			// CalcSignatureHash operates on the wire tx directly without
			// inspecting the NonWitnessUtxo content, so the synthetic prev-tx is safe.
			legacyHash, err := txscript.CalcSignatureHash(script, txscript.SigHashAll, packet.UnsignedTx, i)
			if err != nil {
				return fmt.Errorf("hdwallet: bitcoin: psbt p2pkh sighash: %w", err)
			}
			derSig, err := w.btcDERSig(symbol, index, legacyHash, SigHashAll)
			if err != nil {
				return err
			}
			// Bypass updater.Sign (it verifies NonWitnessUtxo.TxHash() == PreviousOutPoint.Hash,
			// a check the synthetic fake-prev-tx cannot satisfy). Append the
			// PartialSig directly — the same bypass used for P2SH multisig.
			pIn.PartialSigs = append(pIn.PartialSigs, &psbt.PartialSig{PubKey: pub, Signature: derSig})

		case isP2WPKH(script):
			if !bytesEqual(hash160(pub), script[2:]) {
				return fmt.Errorf("%w: bitcoin: psbt input %d not controlled by key", ErrTxInput, i)
			}
			if err := w.psbtSignWitnessV0(symbol, index, updater, sigHashes, packet.UnsignedTx, i, pIn.WitnessUtxo.Value, nil, pub); err != nil {
				return err
			}
		case isP2SHP2WPKH(script):
			redeem := append([]byte{0x00, 0x14}, hash160(pub)...)
			if !bytesEqual(hash160(redeem), script[2:22]) {
				return fmt.Errorf("%w: bitcoin: psbt input %d is not a standard P2SH-P2WPKH for key", ErrTxInput, i)
			}
			if err := w.psbtSignWitnessV0(symbol, index, updater, sigHashes, packet.UnsignedTx, i, pIn.WitnessUtxo.Value, redeem, pub); err != nil {
				return err
			}
		case isP2TR(script):
			if err := checkTaprootKey(pub, script[2:], i); err != nil {
				return err
			}
			if err := w.psbtSignTaproot(symbol, index, packet, sigHashes, prevFetcher, i); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: bitcoin: psbt input %d has unsupported script type", ErrTxInput, i)
		}
	}
	return nil
}

// psbtSignWitnessV0 produces a BIP-143 witness-v0 (P2WPKH / nested P2SH-P2WPKH)
// signature for input i and attaches it as a partial signature. For the nested
// case the redeem script (00 14 <keyhash>) is passed so the Updater records it.
func (w *HDWallet) psbtSignWitnessV0(symbol Symbol, index uint32, updater *psbt.Updater, sigHashes *txscript.TxSigHashes, tx *wire.MsgTx, i int, amount int64, redeem, pub []byte) error {
	pkScript := scriptForSighash(updater.Upsbt.Inputs[i].WitnessUtxo.PkScript, redeem)
	digest, err := txscript.CalcWitnessSigHash(pkScript, sigHashes, txscript.SigHashAll, tx, i, amount)
	if err != nil {
		return fmt.Errorf("hdwallet: bitcoin: psbt witness sighash: %w", err)
	}
	sigWithType, err := w.btcDERSig(symbol, index, digest, uint32(txscript.SigHashAll))
	if err != nil {
		return err
	}
	if redeem != nil {
		if err := updater.AddInRedeemScript(redeem, i); err != nil {
			return fmt.Errorf("hdwallet: bitcoin: psbt redeem: %w", err)
		}
	}
	outcome, err := updater.Sign(i, sigWithType, pub, redeem, nil)
	if err != nil {
		return fmt.Errorf("hdwallet: bitcoin: psbt sign input %d: %w", i, err)
	}
	if outcome != psbt.SignSuccesful {
		return fmt.Errorf("%w: bitcoin: psbt sign input %d outcome %d", ErrTxInput, i, outcome)
	}
	return nil
}

// scriptForSighash returns the script over which the BIP-143 witness sighash is
// computed: the implied P2WPKH scriptCode for both native and nested inputs.
// For native P2WPKH pkScript is already 00 14 <keyhash>; for nested it is the
// redeem script 00 14 <keyhash>. Either way the witness program's 20-byte key
// hash drives the scriptCode (CalcWitnessSigHash builds the P2WPKH scriptCode
// internally from the v0 program).
func scriptForSighash(pkScript, redeem []byte) []byte {
	if redeem != nil {
		return redeem
	}
	return pkScript
}

// psbtSignTaproot produces a BIP-341 key-path Schnorr signature for input i and
// records it as the taproot key-spend signature.
func (w *HDWallet) psbtSignTaproot(symbol Symbol, index uint32, packet *psbt.Packet, sigHashes *txscript.TxSigHashes, fetcher txscript.PrevOutputFetcher, i int) error {
	digest, err := txscript.CalcTaprootSignatureHash(sigHashes, txscript.SigHashDefault, packet.UnsignedTx, i, fetcher)
	if err != nil {
		return fmt.Errorf("hdwallet: bitcoin: psbt taproot sighash: %w", err)
	}
	sig, err := w.signTaprootKeyPath(symbol, index, digest)
	if err != nil {
		return err
	}
	packet.Inputs[i].TaprootKeySpendSig = sig
	if err := packet.SanityCheck(); err != nil {
		return fmt.Errorf("hdwallet: bitcoin: psbt taproot sanity: %w", err)
	}
	return nil
}

// psbtPrevOutFetcher builds the prevout fetcher every BIP-143/341 sighash needs.
// For witness inputs the WitnessUtxo is used directly; for legacy P2PKH inputs
// the prevout is taken from the NonWitnessUtxo at the appropriate output index.
// P2PKH inputs are not signed by CalcWitnessSigHash, but NewTxSigHashes still
// needs a fetcher that covers all inputs, so non-witness prevouts are also added.
func psbtPrevOutFetcher(packet *psbt.Packet) (txscript.PrevOutputFetcher, error) {
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(packet.Inputs))
	for i := range packet.Inputs {
		pIn := &packet.Inputs[i]
		outPoint := packet.UnsignedTx.TxIn[i].PreviousOutPoint
		if pIn.WitnessUtxo != nil {
			prevOuts[outPoint] = pIn.WitnessUtxo
		} else if pIn.NonWitnessUtxo != nil {
			outIdx := outPoint.Index
			if int(outIdx) >= len(pIn.NonWitnessUtxo.TxOut) { // #nosec G115 -- bounded by wire.MsgTx output count
				return nil, fmt.Errorf("%w: bitcoin: psbt input %d NonWitnessUtxo outIdx out of range", ErrTxInput, i)
			}
			prevOuts[outPoint] = pIn.NonWitnessUtxo.TxOut[outIdx]
		} else {
			return nil, fmt.Errorf("%w: bitcoin: psbt input %d missing both WitnessUtxo and NonWitnessUtxo", ErrTxInput, i)
		}
	}
	return txscript.NewMultiPrevOutFetcher(prevOuts), nil
}

// FinalizePSBT runs the BIP-174 Finalizer over a fully signed packet and returns
// the finalized serialized PSBT.
func FinalizePSBT(psbtBytes []byte) ([]byte, error) {
	packet, err := parsePacket(psbtBytes)
	if err != nil {
		return nil, err
	}
	if err := psbt.MaybeFinalizeAll(packet); err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: psbt finalize: %w", err)
	}
	return serializePacket(packet)
}

// ExtractPSBTTx finalizes (if needed) and extracts the network-serialized signed
// transaction from a signed PSBT.
func ExtractPSBTTx(psbtBytes []byte) ([]byte, error) {
	packet, err := parsePacket(psbtBytes)
	if err != nil {
		return nil, err
	}
	if !packet.IsComplete() {
		if err := psbt.MaybeFinalizeAll(packet); err != nil {
			return nil, fmt.Errorf("hdwallet: bitcoin: psbt finalize: %w", err)
		}
	}
	finalTx, err := psbt.Extract(packet)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: psbt extract: %w", err)
	}
	var buf bytes.Buffer
	if err := finalTx.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: psbt tx serialize: %w", err)
	}
	return buf.Bytes(), nil
}

// parsePacket deserializes a binary PSBT.
func parsePacket(b []byte) (*psbt.Packet, error) {
	packet, err := psbt.NewFromRawBytes(bytes.NewReader(b), false)
	if err != nil {
		return nil, fmt.Errorf("%w: bitcoin: psbt parse: %v", ErrTxInput, err)
	}
	return packet, nil
}

// serializePacket serializes a PSBT to its binary form.
func serializePacket(packet *psbt.Packet) ([]byte, error) {
	var buf bytes.Buffer
	if err := packet.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: psbt serialize: %w", err)
	}
	return buf.Bytes(), nil
}
