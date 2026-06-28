package hdwallet

// PSBT v2 (BIP-370) build / sign / finalize / extract.
//
// BIP-370 differs from BIP-174 in that inputs and outputs are described by
// per-element key-value maps rather than an embedded unsigned transaction.
// Required global keys: PSBT_GLOBAL_VERSION (0xFB = 2),
// PSBT_GLOBAL_TX_VERSION (0x02), PSBT_GLOBAL_INPUT_COUNT (0x04),
// PSBT_GLOBAL_OUTPUT_COUNT (0x05). Per-input required keys: prev txid (0x0E)
// and output index (0x0F). Per-output required keys: amount (0x03) and script
// (0x04).
//
// The btcd psbt library only implements BIP-174, so the binary format is
// serialized and parsed here directly. Signing reuses the same btcd sighash
// primitives (CalcWitnessSigHash / CalcTaprootSignatureHash) as the BIP-174
// path, so signatures are byte-identical for deterministic inputs.
//
// Legacy P2PKH inputs are not supported (no full prev-tx in the proto).

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// BIP-370 global key types
const (
	psbtV2KeyTxVersion   = 0x02
	psbtV2KeyFallbackLT  = 0x03
	psbtV2KeyInputCount  = 0x04
	psbtV2KeyOutputCount = 0x05
	psbtV2KeyGlobalVer   = 0xFB
)

// BIP-174 / BIP-370 per-input key types
const (
	psbtInWitnessUtxo  = 0x01
	psbtInPartialSig   = 0x02 // key includes 33-byte pubkey suffix
	psbtInRedeemScript = 0x04
	psbtInFinalSig     = 0x07
	psbtInFinalWit     = 0x08
	psbtV2InPrevTxid   = 0x0E
	psbtV2InOutIndex   = 0x0F
	psbtV2InSequence   = 0x10
	psbtInTaprootKSig  = 0x13
)

// BIP-370 per-output key types
const (
	psbtV2OutAmount = 0x03
	psbtV2OutScript = 0x04
)

// psbtV2Packet is an in-memory BIP-370 PSBT.
type psbtV2Packet struct {
	txVersion uint32
	locktime  uint32
	inputs    []psbtV2In
	outputs   []psbtV2Out
}

type psbtV2In struct {
	prevTxid       []byte // 32 bytes, internal order
	prevIndex      uint32
	sequence       uint32 // 0xffffffff if unset
	witnessUtxo    *wire.TxOut
	partialSigs    []psbtPartialSig
	redeemScript   []byte
	taprootKeySig  []byte
	finalScriptSig []byte
	finalWitness   [][]byte
}

type psbtPartialSig struct {
	pubkey []byte // 33 bytes
	sig    []byte // DER + sighash type byte
}

type psbtV2Out struct {
	amount int64
	script []byte
}

// BuildPSBTV2 constructs an unsigned BIP-370 PSBT for symbol from in. Coin
// selection runs the same planBitcoinTx as the direct signer. Only segwit
// input types (P2WPKH, P2SH-P2WPKH, P2TR) are accepted; P2PKH returns
// ErrTxInput because the proto does not carry the full previous transaction.
func BuildPSBTV2(symbol Symbol, in *txbtc.SigningInput) ([]byte, error) {
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
	p := &psbtV2Packet{
		txVersion: btcTxVersion(symbol),
		locktime:  in.GetLockTime(),
	}
	for i, bi := range plan.inputs {
		if isP2PKH(bi.script) {
			return nil, fmt.Errorf("%w: bitcoin: psbt v2 does not support legacy P2PKH input %d (no prev tx in proto); use SignTransaction", ErrTxInput, i)
		}
		seq := bi.sequence
		if seq == 0 {
			seq = 0xffffffff
		}
		p.inputs = append(p.inputs, psbtV2In{
			prevTxid:    bi.txid,
			prevIndex:   bi.vout,
			sequence:    seq,
			witnessUtxo: wire.NewTxOut(bi.amount, bi.script),
		})
	}
	for _, bo := range plan.outputs {
		p.outputs = append(p.outputs, psbtV2Out{amount: bo.value, script: bo.script})
	}
	return serializePSBTV2(p), nil
}

// SignPSBTV2 parses psbtBytes, signs every input controlled by the
// (symbol,index) key and returns the updated BIP-370 PSBT. The leaf key is
// derived under the package's wiped-on-return discipline.
func (w *HDWallet) SignPSBTV2(symbol Symbol, index uint32, psbtBytes []byte) ([]byte, error) {
	if _, ok := btcAddrParams[symbol]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrTxUnsupported, symbol)
	}
	p, err := parsePSBTV2(psbtBytes)
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
	tx := p.toWireTx()
	fetcher := p.prevOutFetcher()
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	for i := range p.inputs {
		inp := &p.inputs[i]
		if inp.witnessUtxo == nil {
			return nil, fmt.Errorf("%w: bitcoin: psbt v2 input %d missing witness utxo", ErrTxInput, i)
		}
		script := inp.witnessUtxo.PkScript
		switch {
		case isP2WPKH(script):
			if !bytesEqual(hash160(pub), script[2:]) {
				return nil, fmt.Errorf("%w: bitcoin: psbt v2 input %d not controlled by key", ErrTxInput, i)
			}
			digest, err := txscript.CalcWitnessSigHash(script, sigHashes, txscript.SigHashAll, tx, i, inp.witnessUtxo.Value)
			if err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: psbt v2 sighash: %w", err)
			}
			sig, err := w.btcDERSig(symbol, index, digest, uint32(txscript.SigHashAll))
			if err != nil {
				return nil, err
			}
			inp.partialSigs = []psbtPartialSig{{pubkey: pub, sig: sig}}
		case isP2SHP2WPKH(script):
			redeem := append([]byte{0x00, 0x14}, hash160(pub)...)
			if !bytesEqual(hash160(redeem), script[2:22]) {
				return nil, fmt.Errorf("%w: bitcoin: psbt v2 input %d not controlled by key", ErrTxInput, i)
			}
			inp.redeemScript = redeem
			digest, err := txscript.CalcWitnessSigHash(redeem, sigHashes, txscript.SigHashAll, tx, i, inp.witnessUtxo.Value)
			if err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: psbt v2 sighash: %w", err)
			}
			sig, err := w.btcDERSig(symbol, index, digest, uint32(txscript.SigHashAll))
			if err != nil {
				return nil, err
			}
			inp.partialSigs = []psbtPartialSig{{pubkey: pub, sig: sig}}
		case isP2TR(script):
			if err := checkTaprootKey(pub, script[2:], i); err != nil {
				return nil, err
			}
			digest, err := txscript.CalcTaprootSignatureHash(sigHashes, txscript.SigHashDefault, tx, i, fetcher)
			if err != nil {
				return nil, fmt.Errorf("hdwallet: bitcoin: psbt v2 taproot sighash: %w", err)
			}
			sig, err := w.signTaprootKeyPath(symbol, index, digest)
			if err != nil {
				return nil, err
			}
			inp.taprootKeySig = sig
		default:
			return nil, fmt.Errorf("%w: bitcoin: psbt v2 input %d unsupported script type", ErrTxInput, i)
		}
	}
	return serializePSBTV2(p), nil
}

// FinalizePSBTV2 runs the BIP-370 finalizer over a signed packet: it moves
// partial signatures into the final scriptSig / witness fields.
func FinalizePSBTV2(psbtBytes []byte) ([]byte, error) {
	p, err := parsePSBTV2(psbtBytes)
	if err != nil {
		return nil, err
	}
	if err := psbt2FinalizeAll(p); err != nil {
		return nil, err
	}
	return serializePSBTV2(p), nil
}

// ExtractPSBTV2Tx finalizes (if needed) and extracts the network-serialized
// signed transaction from a BIP-370 PSBT.
func ExtractPSBTV2Tx(psbtBytes []byte) ([]byte, error) {
	p, err := parsePSBTV2(psbtBytes)
	if err != nil {
		return nil, err
	}
	if !psbt2IsComplete(p) {
		if err := psbt2FinalizeAll(p); err != nil {
			return nil, err
		}
	}
	tx := p.toWireTx()
	for i := range p.inputs {
		inp := &p.inputs[i]
		tx.TxIn[i].SignatureScript = inp.finalScriptSig
		if len(inp.finalWitness) > 0 {
			tx.TxIn[i].Witness = inp.finalWitness
		}
	}
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("hdwallet: bitcoin: psbt v2 extract: %w", err)
	}
	return buf.Bytes(), nil
}

// ---- internals ----

func (p *psbtV2Packet) toWireTx() *wire.MsgTx {
	tx := wire.NewMsgTx(int32(p.txVersion)) // #nosec G115 -- tx version is 1 or 2
	tx.LockTime = p.locktime
	for _, inp := range p.inputs {
		var h chainhash.Hash
		copy(h[:], inp.prevTxid)
		txIn := wire.NewTxIn(&wire.OutPoint{Hash: h, Index: inp.prevIndex}, nil, nil)
		txIn.Sequence = inp.sequence
		tx.TxIn = append(tx.TxIn, txIn)
	}
	for _, out := range p.outputs {
		tx.TxOut = append(tx.TxOut, wire.NewTxOut(out.amount, out.script))
	}
	return tx
}

func (p *psbtV2Packet) prevOutFetcher() txscript.PrevOutputFetcher {
	m := make(map[wire.OutPoint]*wire.TxOut, len(p.inputs))
	for _, inp := range p.inputs {
		var h chainhash.Hash
		copy(h[:], inp.prevTxid)
		if inp.witnessUtxo != nil {
			m[wire.OutPoint{Hash: h, Index: inp.prevIndex}] = inp.witnessUtxo
		}
	}
	return txscript.NewMultiPrevOutFetcher(m)
}

func psbt2FinalizeAll(p *psbtV2Packet) error {
	for i := range p.inputs {
		inp := &p.inputs[i]
		if len(inp.finalWitness) > 0 || len(inp.finalScriptSig) > 0 {
			continue // already finalized
		}
		if inp.witnessUtxo == nil {
			return fmt.Errorf("%w: bitcoin: psbt v2 input %d missing witness utxo for finalization", ErrTxInput, i)
		}
		script := inp.witnessUtxo.PkScript
		switch {
		case isP2WPKH(script):
			if len(inp.partialSigs) != 1 {
				return fmt.Errorf("%w: bitcoin: psbt v2 input %d: need 1 partial sig for P2WPKH, got %d", ErrTxInput, i, len(inp.partialSigs))
			}
			ps := inp.partialSigs[0]
			inp.finalWitness = [][]byte{ps.sig, ps.pubkey}
			inp.partialSigs = nil
		case isP2SHP2WPKH(script):
			if len(inp.partialSigs) != 1 || len(inp.redeemScript) == 0 {
				return fmt.Errorf("%w: bitcoin: psbt v2 input %d: need 1 partial sig + redeem script for P2SH-P2WPKH", ErrTxInput, i)
			}
			ps := inp.partialSigs[0]
			inp.finalWitness = [][]byte{ps.sig, ps.pubkey}
			inp.finalScriptSig = btcPush(inp.redeemScript)
			inp.partialSigs = nil
		case isP2TR(script):
			if len(inp.taprootKeySig) == 0 {
				return fmt.Errorf("%w: bitcoin: psbt v2 input %d: missing taproot key sig", ErrTxInput, i)
			}
			inp.finalWitness = [][]byte{inp.taprootKeySig}
			inp.taprootKeySig = nil
		default:
			return fmt.Errorf("%w: bitcoin: psbt v2 input %d: unsupported script type for finalization", ErrTxInput, i)
		}
	}
	return nil
}

func psbt2IsComplete(p *psbtV2Packet) bool {
	for _, inp := range p.inputs {
		if len(inp.finalWitness) == 0 && len(inp.finalScriptSig) == 0 {
			return false
		}
	}
	return true
}

// ---- serialization ----

func serializePSBTV2(p *psbtV2Packet) []byte {
	var b []byte
	b = append(b, 0x70, 0x73, 0x62, 0x74, 0xff) // magic
	// global map
	b = psbt2KV(b, []byte{psbtV2KeyGlobalVer}, btcLE32(2))
	b = psbt2KV(b, []byte{psbtV2KeyTxVersion}, btcLE32(p.txVersion))
	b = psbt2KV(b, []byte{psbtV2KeyInputCount}, btcVarInt(uint64(len(p.inputs))))
	b = psbt2KV(b, []byte{psbtV2KeyOutputCount}, btcVarInt(uint64(len(p.outputs))))
	if p.locktime != 0 {
		b = psbt2KV(b, []byte{psbtV2KeyFallbackLT}, btcLE32(p.locktime))
	}
	b = append(b, 0x00)
	// per-input maps
	for i := range p.inputs {
		inp := &p.inputs[i]
		b = psbt2KV(b, []byte{psbtV2InPrevTxid}, inp.prevTxid)
		b = psbt2KV(b, []byte{psbtV2InOutIndex}, btcLE32(inp.prevIndex))
		if inp.sequence != 0xffffffff {
			b = psbt2KV(b, []byte{psbtV2InSequence}, btcLE32(inp.sequence))
		}
		if inp.witnessUtxo != nil {
			b = psbt2KV(b, []byte{psbtInWitnessUtxo}, psbt2TxOut(inp.witnessUtxo))
		}
		if len(inp.redeemScript) > 0 {
			b = psbt2KV(b, []byte{psbtInRedeemScript}, inp.redeemScript)
		}
		for _, ps := range inp.partialSigs {
			b = psbt2KV(b, append([]byte{psbtInPartialSig}, ps.pubkey...), ps.sig)
		}
		if len(inp.taprootKeySig) > 0 {
			b = psbt2KV(b, []byte{psbtInTaprootKSig}, inp.taprootKeySig)
		}
		if len(inp.finalScriptSig) > 0 {
			b = psbt2KV(b, []byte{psbtInFinalSig}, inp.finalScriptSig)
		}
		if len(inp.finalWitness) > 0 {
			b = psbt2KV(b, []byte{psbtInFinalWit}, psbt2Witness(inp.finalWitness))
		}
		b = append(b, 0x00)
	}
	// per-output maps
	for i := range p.outputs {
		out := &p.outputs[i]
		b = psbt2KV(b, []byte{psbtV2OutAmount}, btcLE64(i64AsU64(out.amount)))
		b = psbt2KV(b, []byte{psbtV2OutScript}, out.script)
		b = append(b, 0x00)
	}
	return b
}

func psbt2KV(b, key, value []byte) []byte {
	b = append(b, btcVarInt(uint64(len(key)))...)
	b = append(b, key...)
	b = append(b, btcVarInt(uint64(len(value)))...)
	b = append(b, value...)
	return b
}

func psbt2TxOut(out *wire.TxOut) []byte {
	b := make([]byte, 0, 8+9+len(out.PkScript)) // value(8) + varint(≤9) + script
	b = append(b, btcLE64(i64AsU64(out.Value))...)
	b = append(b, btcVarInt(uint64(len(out.PkScript)))...)
	b = append(b, out.PkScript...)
	return b
}

func psbt2Witness(stack [][]byte) []byte {
	var b []byte
	b = append(b, btcVarInt(uint64(len(stack)))...)
	for _, item := range stack {
		b = append(b, btcVarInt(uint64(len(item)))...)
		b = append(b, item...)
	}
	return b
}

// ---- parsing ----

func parsePSBTV2(data []byte) (*psbtV2Packet, error) {
	if len(data) < 5 || data[0] != 0x70 || data[1] != 0x73 || data[2] != 0x62 || data[3] != 0x74 || data[4] != 0xff {
		return nil, fmt.Errorf("%w: psbt v2: invalid magic", ErrTxInput)
	}
	pos := 5
	p := &psbtV2Packet{}
	var nIn, nOut int
	hasTxVer := false

	// global map
	for {
		key, val, next, err := psbt2ReadKV(data, pos)
		if err != nil {
			return nil, fmt.Errorf("%w: psbt v2 global: %v", ErrTxInput, err)
		}
		pos = next
		if key == nil {
			break
		}
		if len(key) != 1 {
			continue // skip unknown multi-byte keys
		}
		switch key[0] {
		case psbtV2KeyGlobalVer:
			if len(val) != 4 || binary.LittleEndian.Uint32(val) != 2 {
				return nil, fmt.Errorf("%w: psbt v2: global version must be 2", ErrTxInput)
			}
		case psbtV2KeyTxVersion:
			if len(val) != 4 {
				return nil, fmt.Errorf("%w: psbt v2: invalid tx version length", ErrTxInput)
			}
			p.txVersion = binary.LittleEndian.Uint32(val)
			hasTxVer = true
		case psbtV2KeyInputCount:
			n, _, e := psbt2CompactSize(val)
			if e != nil {
				return nil, fmt.Errorf("%w: psbt v2: input count: %v", ErrTxInput, e)
			}
			nIn = int(n) // #nosec G115 -- PSBT can't have 2^31+ inputs; data size bounds this
		case psbtV2KeyOutputCount:
			n, _, e := psbt2CompactSize(val)
			if e != nil {
				return nil, fmt.Errorf("%w: psbt v2: output count: %v", ErrTxInput, e)
			}
			nOut = int(n) // #nosec G115 -- same as nIn above
		case psbtV2KeyFallbackLT:
			if len(val) == 4 {
				p.locktime = binary.LittleEndian.Uint32(val)
			}
		}
	}
	if !hasTxVer {
		return nil, fmt.Errorf("%w: psbt v2: missing PSBT_GLOBAL_TX_VERSION", ErrTxInput)
	}
	if nIn == 0 && nOut == 0 {
		return nil, fmt.Errorf("%w: psbt v2: missing input/output counts", ErrTxInput)
	}

	// per-input maps
	p.inputs = make([]psbtV2In, nIn)
	for i := range p.inputs {
		inp := &p.inputs[i]
		inp.sequence = 0xffffffff
		for {
			key, val, next, err := psbt2ReadKV(data, pos)
			if err != nil {
				return nil, fmt.Errorf("%w: psbt v2 input %d: %v", ErrTxInput, i, err)
			}
			pos = next
			if key == nil {
				break
			}
			switch {
			case len(key) == 1 && key[0] == psbtV2InPrevTxid:
				if len(val) != 32 {
					return nil, fmt.Errorf("%w: psbt v2 input %d: prev txid must be 32 bytes", ErrTxInput, i)
				}
				inp.prevTxid = append([]byte(nil), val...)
			case len(key) == 1 && key[0] == psbtV2InOutIndex:
				if len(val) != 4 {
					return nil, fmt.Errorf("%w: psbt v2 input %d: output index must be 4 bytes", ErrTxInput, i)
				}
				inp.prevIndex = binary.LittleEndian.Uint32(val)
			case len(key) == 1 && key[0] == psbtV2InSequence:
				if len(val) != 4 {
					return nil, fmt.Errorf("%w: psbt v2 input %d: sequence must be 4 bytes", ErrTxInput, i)
				}
				inp.sequence = binary.LittleEndian.Uint32(val)
			case len(key) == 1 && key[0] == psbtInWitnessUtxo:
				txout, e := psbt2ParseTxOut(val)
				if e != nil {
					return nil, fmt.Errorf("%w: psbt v2 input %d: witness utxo: %v", ErrTxInput, i, e)
				}
				inp.witnessUtxo = txout
			case len(key) == 34 && key[0] == psbtInPartialSig:
				inp.partialSigs = append(inp.partialSigs, psbtPartialSig{
					pubkey: append([]byte(nil), key[1:]...),
					sig:    append([]byte(nil), val...),
				})
			case len(key) == 1 && key[0] == psbtInRedeemScript:
				inp.redeemScript = append([]byte(nil), val...)
			case len(key) == 1 && key[0] == psbtInTaprootKSig:
				inp.taprootKeySig = append([]byte(nil), val...)
			case len(key) == 1 && key[0] == psbtInFinalSig:
				inp.finalScriptSig = append([]byte(nil), val...)
			case len(key) == 1 && key[0] == psbtInFinalWit:
				stack, e := psbt2ParseWitness(val)
				if e != nil {
					return nil, fmt.Errorf("%w: psbt v2 input %d: final witness: %v", ErrTxInput, i, e)
				}
				inp.finalWitness = stack
			}
		}
	}

	// per-output maps
	p.outputs = make([]psbtV2Out, nOut)
	for i := range p.outputs {
		out := &p.outputs[i]
		for {
			key, val, next, err := psbt2ReadKV(data, pos)
			if err != nil {
				return nil, fmt.Errorf("%w: psbt v2 output %d: %v", ErrTxInput, i, err)
			}
			pos = next
			if key == nil {
				break
			}
			if len(key) != 1 {
				continue
			}
			switch key[0] {
			case psbtV2OutAmount:
				if len(val) != 8 {
					return nil, fmt.Errorf("%w: psbt v2 output %d: amount must be 8 bytes", ErrTxInput, i)
				}
				out.amount = int64(binary.LittleEndian.Uint64(val)) // #nosec G115 -- BTC amounts are int64 satoshi; max supply ≪ int64 max
			case psbtV2OutScript:
				out.script = append([]byte(nil), val...)
			}
		}
	}
	return p, nil
}

// psbt2ReadKV reads one PSBT key-value entry from data[pos:].
// Returns (nil, nil, pos_after_separator, nil) at a map separator (0x00 key).
func psbt2ReadKV(data []byte, pos int) (key, val []byte, next int, err error) {
	if pos >= len(data) {
		return nil, nil, pos, fmt.Errorf("unexpected end of data")
	}
	kLen, n, e := psbt2CompactSize(data[pos:])
	if e != nil {
		return nil, nil, pos, fmt.Errorf("key length: %v", e)
	}
	pos += n
	if kLen == 0 {
		return nil, nil, pos, nil // separator
	}
	if int(kLen) > len(data)-pos { // #nosec G115 -- kLen bounded by data slice length (≤ max int)
		return nil, nil, pos, fmt.Errorf("key truncated")
	}
	key = data[pos : pos+int(kLen)] // #nosec G115 -- bounded by the check above
	pos += int(kLen)                // #nosec G115 -- same

	vLen, n, e := psbt2CompactSize(data[pos:])
	if e != nil {
		return nil, nil, pos, fmt.Errorf("value length: %v", e)
	}
	pos += n
	if int(vLen) > len(data)-pos { // #nosec G115 -- vLen bounded by data slice length (≤ max int)
		return nil, nil, pos, fmt.Errorf("value truncated")
	}
	val = data[pos : pos+int(vLen)] // #nosec G115 -- bounded by the check above
	pos += int(vLen)                // #nosec G115 -- same
	return key, val, pos, nil
}

// psbt2CompactSize reads a Bitcoin compactSize integer from data.
func psbt2CompactSize(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("empty")
	}
	switch data[0] {
	case 0xfd:
		if len(data) < 3 {
			return 0, 0, fmt.Errorf("0xfd truncated")
		}
		return uint64(binary.LittleEndian.Uint16(data[1:])), 3, nil
	case 0xfe:
		if len(data) < 5 {
			return 0, 0, fmt.Errorf("0xfe truncated")
		}
		return uint64(binary.LittleEndian.Uint32(data[1:])), 5, nil
	case 0xff:
		if len(data) < 9 {
			return 0, 0, fmt.Errorf("0xff truncated")
		}
		return binary.LittleEndian.Uint64(data[1:]), 9, nil
	default:
		return uint64(data[0]), 1, nil
	}
}

func psbt2ParseTxOut(data []byte) (*wire.TxOut, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("too short")
	}
	amount := int64(binary.LittleEndian.Uint64(data)) // #nosec G115 -- BTC wire amount is int64 satoshi; values > int64 max are invalid
	data = data[8:]
	sLen, n, err := psbt2CompactSize(data)
	if err != nil {
		return nil, err
	}
	data = data[n:]
	if uint64(len(data)) < sLen {
		return nil, fmt.Errorf("script truncated")
	}
	return wire.NewTxOut(amount, append([]byte(nil), data[:sLen]...)), nil
}

func psbt2ParseWitness(data []byte) ([][]byte, error) {
	count, n, err := psbt2CompactSize(data)
	if err != nil {
		return nil, err
	}
	data = data[n:]
	stack := make([][]byte, count)
	for i := range stack {
		itemLen, n, err := psbt2CompactSize(data)
		if err != nil {
			return nil, err
		}
		data = data[n:]
		if uint64(len(data)) < itemLen {
			return nil, fmt.Errorf("item %d truncated", i)
		}
		stack[i] = append([]byte(nil), data[:itemLen]...)
		data = data[itemLen:]
	}
	return stack, nil
}
