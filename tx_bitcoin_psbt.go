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
// PSBT inputs carry only a witness UTXO (BIP-143 sufficient), so the segwit input
// types are supported: native P2WPKH, nested P2SH-P2WPKH and Taproot key-path.
// Legacy P2PKH is intentionally not offered through the PSBT flow because BIP-174
// requires the full previous transaction (NonWitnessUtxo) for a non-witness
// input, which the SigningInput proto does not carry; spend legacy inputs via the
// direct SignTransaction path instead.

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
// transaction. Every chosen input must be a segwit type (P2WPKH, P2SH-P2WPKH or
// P2TR); a legacy P2PKH input returns ErrTxInput.
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
			return nil, fmt.Errorf("%w: bitcoin: psbt does not support legacy P2PKH input %d (no prev tx in proto); use SignTransaction", ErrTxInput, i)
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
		script := packet.Inputs[i].WitnessUtxo.PkScript
		amount := packet.Inputs[i].WitnessUtxo.Value
		switch {
		case isP2WPKH(script):
			if !bytesEqual(hash160(pub), script[2:]) {
				return fmt.Errorf("%w: bitcoin: psbt input %d not controlled by key", ErrTxInput, i)
			}
			if err := w.psbtSignWitnessV0(symbol, index, updater, sigHashes, packet.UnsignedTx, i, amount, nil, pub); err != nil {
				return err
			}
		case isP2SHP2WPKH(script):
			redeem := append([]byte{0x00, 0x14}, hash160(pub)...)
			if !bytesEqual(hash160(redeem), script[2:22]) {
				return fmt.Errorf("%w: bitcoin: psbt input %d is not a standard P2SH-P2WPKH for key", ErrTxInput, i)
			}
			if err := w.psbtSignWitnessV0(symbol, index, updater, sigHashes, packet.UnsignedTx, i, amount, redeem, pub); err != nil {
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

// psbtPrevOutFetcher builds the prevout fetcher every BIP-143/341 sighash needs,
// from each input's WitnessUtxo.
func psbtPrevOutFetcher(packet *psbt.Packet) (txscript.PrevOutputFetcher, error) {
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(packet.Inputs))
	for i := range packet.Inputs {
		wu := packet.Inputs[i].WitnessUtxo
		if wu == nil {
			return nil, fmt.Errorf("%w: bitcoin: psbt input %d missing witness utxo", ErrTxInput, i)
		}
		prevOuts[packet.UnsignedTx.TxIn[i].PreviousOutPoint] = wu
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
