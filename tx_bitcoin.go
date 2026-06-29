package hdwallet

// Bitcoin transaction signing (legacy P2PKH + nested P2SH-P2WPKH + BIP-143
// P2WPKH + BIP-341/BIP-340 Taproot key-path).
//
// SignTransaction(BTC|LTC, …) builds, signs and serializes a transaction with no
// broadcast. It spends four standard single-key input types, selected per-UTXO
// by its scriptPubKey:
//   - legacy P2PKH (pre-segwit, scriptSig = <sig> <pubkey>, no witness);
//   - nested P2SH-P2WPKH (BIP-49 wrapper: scriptSig = <redeem>, witness = <sig> <pubkey>);
//   - native SegWit P2WPKH (BIP-143 witness v0);
//   - Taproot key-path P2TR (BIP-341/BIP-340 Schnorr witness v1).
//
// Outputs may be any of the four standard address types (decoded via
// bitcoinDecodeScript). A PSBT (BIP-174) build/sign/finalize/extract flow over
// the same inputs lives in tx_bitcoin_psbt.go.
//
// The transaction wire format is hand-built for byte-exactness, like the other
// non-EVM families. Correctness is pinned in tx_bitcoin_test.go against
// github.com/btcsuite/btcd (full-node txscript) as the oracle: the P2PKH,
// P2SH-P2WPKH and P2WPKH paths are asserted byte-identical to btcd's signer and
// validated through txscript.NewEngine, the Taproot sighash is asserted equal to
// txscript.CalcTaprootSignatureHash, and the Schnorr witness is verified under
// BIP-340. The BIP-143 sighash is also checked against the spec's worked example.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// btcDustThreshold is the minimum change output (satoshis) worth creating; below
// this the remainder is dropped into the fee instead of producing a dust output.
const btcDustThreshold int64 = 546

// btcDefaultSequence is the final (non-RBF) nSequence used when a UTXO leaves the
// sequence unset (0); matches the proto's documented default.
const btcDefaultSequence uint32 = 0xffffffff

// BTCSequenceRBF is the BIP-125 opt-in sequence number. Set an input's
// OutPointSequence to this value to signal that the spending transaction may
// be replaced by fee (RBF). Any UTXO whose OutPointSequence is explicitly set
// to 0xFFFFFFFD will carry that sequence through to the signed transaction.
const BTCSequenceRBF uint32 = 0xFFFFFFFD

// SigHashAll, SigHashNone, SigHashSingle and SigHashAnyoneCanPay are the
// standard Bitcoin SIGHASH flag bits used in SigningInput.HashType. A complete
// hash_type value is formed by OR-ing one base type (bits 0–4) with optional
// modifier bits: bit 7 (0x80) = AnyoneCanPay, bit 6 (0x40) = FORKID (BCH).
//
// Common combinations:
//
//	0x01  SIGHASH_ALL                  — default; all inputs, all outputs
//	0x41  SIGHASH_ALL|FORKID           — BCH default
//	0x02  SIGHASH_NONE                 — no outputs committed
//	0x03  SIGHASH_SINGLE               — only input's paired output committed
//	0x81  SIGHASH_ALL|ANYONECANPAY     — only signing input; all outputs
//	0x83  SIGHASH_SINGLE|ANYONECANPAY  — only signing input; paired output
const (
	SigHashAll          uint32 = 0x01
	SigHashNone         uint32 = 0x02
	SigHashSingle       uint32 = 0x03
	SigHashAnyoneCanPay uint32 = 0x80
)

// btcInput is one transaction input with the data needed to sign it.
type btcInput struct {
	txid        []byte // 32-byte txid in internal (little-endian) byte order
	vout        uint32
	sequence    uint32
	amount      int64
	script      []byte   // scriptPubKey of the output being spent
	scriptSig   []byte   // unlocking script (legacy P2PKH / nested P2SH-P2WPKH); empty for native segwit
	witness     [][]byte // witness stack (segwit inputs); nil for pure-legacy inputs
	keyIndex    uint32   // per-input derivation index (only meaningful when hasKeyIndex is true)
	hasKeyIndex bool     // true when keyIndex is explicitly set by the UTXO's key_index field
}

// btcOutput is one transaction output.
type btcOutput struct {
	value  int64
	script []byte
}

// signBitcoinTx builds, signs and serializes a Bitcoin/Litecoin transaction.
// By default all UTXOs are signed with the (symbol,index) key. When a UTXO
// carries an explicit key_index field, that derivation index is used for that
// input instead, allowing a single tx to sweep UTXOs from multiple indices.
func (w *HDWallet) signBitcoinTx(symbol Symbol, index uint32, in *txbtc.SigningInput) (*txbtc.SigningOutput, error) {
	// Zcash uses an entirely different (Sapling v4 / ZIP-243) wire format and
	// sighash, so it has its own builder rather than the standard Bitcoin path.
	if symbol == ZEC {
		return w.signZcashTx(index, in)
	}
	if !bitcoinTxSupported(symbol) {
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

	version := btcTxVersion(symbol)
	hashType := in.GetHashType()
	if hashType == 0 {
		hashType = bitcoinDefaultHashType(symbol)
	}
	locktime := in.GetLockTime()

	for i := range plan.inputs {
		// Resolve the derivation index for this specific input. When the UTXO
		// carries an explicit key_index, use it; otherwise fall back to the
		// tx-level index supplied by the caller.
		inputIndex := index
		if plan.inputs[i].hasKeyIndex {
			inputIndex = plan.inputs[i].keyIndex
		}
		inputPub, err := w.PublicKeyIndex(symbol, inputIndex)
		if err != nil {
			return nil, err
		}
		if len(inputPub) != 33 {
			return nil, fmt.Errorf("%w: bitcoin: expected 33-byte compressed key for input %d", ErrTxInput, i)
		}
		if err := w.signBitcoinInput(symbol, inputIndex, inputPub, plan.inputs, plan.outputs, i, version, locktime, hashType); err != nil {
			return nil, err
		}
	}

	encoded := serializeBitcoinTx(version, plan.inputs, plan.outputs, locktime, true)
	noWitness := serializeBitcoinTx(version, plan.inputs, plan.outputs, locktime, false)
	txid := reverseBytes(sha256d(noWitness))

	return &txbtc.SigningOutput{
		Encoded:       encoded,
		EncodedHex:    bytesToHex(encoded),
		TransactionId: txid,
		Fee:           plan.fee,
		UsedUtxo:      plan.used,
	}, nil
}

// signBitcoinInput computes the sighash for input i according to its script type
// and fills in its witness.
func (w *HDWallet) signBitcoinInput(symbol Symbol, index uint32, pub []byte, inputs []btcInput, outputs []btcOutput, i int, version, locktime, hashType uint32) error {
	script := inputs[i].script
	switch {
	case isP2PKH(script):
		keyhash := script[3:23] // 76 a9 14 <20-byte hash> 88 ac
		if !bytesEqual(hash160(pub), keyhash) {
			return fmt.Errorf("%w: bitcoin: utxo %d not controlled by key at index %d", ErrTxInput, i, index)
		}
		// Bitcoin Cash signs P2PKH inputs with a BIP-143 preimage carrying
		// SIGHASH_FORKID (the hashType already includes 0x40); its scriptCode is the
		// P2PKH scriptPubKey, length-prefixed. Every other chain (BTC/LTC/DOGE/DASH)
		// uses the pre-segwit legacy sighash. Both produce a legacy unlocking script
		// push(DER‖hashType) push(pubkey) with no witness.
		var digest []byte
		if symbol == BCH {
			scriptCode := append(btcVarInt(uint64(len(script))), script...)
			digest = bip143Sighash(inputs, outputs, i, scriptCode, version, locktime, hashType)
		} else {
			// SIGHASH_SINGLE with the input index at or beyond the output count has
			// no valid encoding in the legacy (pre-segwit) sighash: the output slot
			// at idx does not exist. Reject it before calling legacySighash so the
			// function is never asked to access outputs[idx] out of bounds.
			if (hashType&0x1f) == SigHashSingle && i >= len(outputs) {
				return fmt.Errorf("%w: bitcoin: SIGHASH_SINGLE input %d >= output count %d", ErrTxInput, i, len(outputs))
			}
			digest = legacySighash(inputs, outputs, i, script, version, locktime, hashType)
		}
		sigWithType, err := w.btcDERSig(symbol, index, digest, hashType)
		if err != nil {
			return err
		}
		inputs[i].scriptSig = append(btcPush(sigWithType), btcPush(pub)...)
		inputs[i].witness = nil
		return nil
	case isP2SHP2WPKH(script):
		// Only the standard BIP-49 wrapper (P2SH of OP_0<20-byte keyhash>) is
		// signable; any other P2SH is rejected.
		keyhash := hash160(pub)
		redeem := append([]byte{0x00, 0x14}, keyhash...) // OP_0 <20-byte keyhash>
		// script is a9 14 <20-byte scriptHash> 87; bytes [2:22] are the scriptHash.
		if !bytesEqual(hash160(redeem), script[2:22]) {
			return fmt.Errorf("%w: bitcoin: utxo %d is not a standard P2SH-P2WPKH for key at index %d", ErrTxInput, i, index)
		}
		scriptCode := append([]byte{0x19, 0x76, 0xa9, 0x14}, keyhash...) // implied P2WPKH scriptCode, 0x19 = len(25)
		scriptCode = append(scriptCode, 0x88, 0xac)
		digest := bip143Sighash(inputs, outputs, i, scriptCode, version, locktime, hashType)
		sigWithType, err := w.btcDERSig(symbol, index, digest, hashType)
		if err != nil {
			return err
		}
		inputs[i].scriptSig = btcPush(redeem) // scriptSig pushes the redeem script
		inputs[i].witness = [][]byte{sigWithType, pub}
		return nil
	case isP2WPKH(script):
		keyhash := script[2:]
		if !bytesEqual(hash160(pub), keyhash) {
			return fmt.Errorf("%w: bitcoin: utxo %d not controlled by key at index %d", ErrTxInput, i, index)
		}
		scriptCode := append([]byte{0x19, 0x76, 0xa9, 0x14}, keyhash...) // 0x19 = len(25)
		scriptCode = append(scriptCode, 0x88, 0xac)
		digest := bip143Sighash(inputs, outputs, i, scriptCode, version, locktime, hashType)
		sigWithType, err := w.btcDERSig(symbol, index, digest, hashType)
		if err != nil {
			return err
		}
		inputs[i].witness = [][]byte{sigWithType, pub}
		return nil
	case isP2TR(script):
		if err := checkTaprootKey(pub, script[2:], i); err != nil {
			return err
		}
		digest := bip341Sighash(inputs, outputs, i, version, locktime)
		sigBytes, err := w.signTaprootKeyPath(symbol, index, digest)
		if err != nil {
			return err
		}
		inputs[i].witness = [][]byte{sigBytes}
		return nil
	default:
		return fmt.Errorf("%w: bitcoin: utxo %d has unsupported script type (only P2PKH, P2SH-P2WPKH, P2WPKH and P2TR are signable)", ErrTxInput, i)
	}
}

// btcDERSig signs a 32-byte digest with the (symbol,index) secp256k1 key and
// returns the DER encoding with the 1-byte hashType appended, as Bitcoin
// scriptSig/witness signatures require.
func (w *HDWallet) btcDERSig(symbol Symbol, index uint32, digest []byte, hashType uint32) ([]byte, error) {
	sig, err := w.SignIndex(symbol, index, digest)
	if err != nil {
		return nil, err
	}
	der := sig.DER()
	if der == nil {
		return nil, fmt.Errorf("%w: bitcoin: %s is not an ECDSA coin", ErrTxInput, symbol)
	}
	return append(append([]byte(nil), der...), byte(hashType)), nil // #nosec G115 -- hashType is a 1-byte SIGHASH flag
}

// btcPush returns a minimal scriptSig data push for b (length-prefixed). All
// pushes here are < 76 bytes (signatures, pubkeys, the 22-byte redeem script),
// so a single length byte is always correct.
func btcPush(b []byte) []byte {
	out := make([]byte, 0, 1+len(b))
	out = append(out, byte(len(b))) // #nosec G115 -- len(b) < 76 for all callers (sig/pubkey/redeem)
	return append(out, b...)
}

// checkTaprootKey verifies the derived key's BIP-86 output key matches the
// taproot UTXO's program, so a mismatched UTXO fails loudly rather than producing
// an unspendable signature.
func checkTaprootKey(pub, program []byte, i int) error {
	internal, err := btcec.ParsePubKey(pub)
	if err != nil {
		return fmt.Errorf("%w: bitcoin: %v", ErrTxInput, err)
	}
	outKey := schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(internal))
	if !bytesEqual(outKey, program) {
		return fmt.Errorf("%w: bitcoin: taproot utxo %d not controlled by key", ErrTxInput, i)
	}
	return nil
}

// signTaprootKeyPath signs a BIP-341 key-path sighash with the BIP-86 tweaked
// key using BIP-340 Schnorr, returning the 64-byte signature. The raw and tweaked
// keys are wiped before returning.
func (w *HDWallet) signTaprootKeyPath(symbol Symbol, index uint32, sighash []byte) ([]byte, error) {
	var out []byte
	err := w.withLeafPrivateKey(symbol, index, func(raw []byte, _ Coin) error {
		priv, _ := btcec.PrivKeyFromBytes(raw)
		defer priv.Zero()
		tweaked := txscript.TweakTaprootPrivKey(*priv, []byte{}) // empty script root = BIP-86 key-spend
		defer tweaked.Zero()
		sig, err := schnorr.Sign(tweaked, sighash)
		if err != nil {
			return fmt.Errorf("hdwallet: bitcoin: schnorr sign: %w", err)
		}
		out = sig.Serialize()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// btcPlan is the result of coin selection: the chosen inputs, the outputs
// (recipient + optional change), the fee, and the used-UTXO records.
type btcPlan struct {
	inputs  []btcInput
	outputs []btcOutput
	fee     int64
	used    []*txbtc.UsedUTXO
}

// buildOpReturn builds the scriptPubKey for an OP_RETURN output carrying data.
// payload must not exceed 80 bytes (Bitcoin standardness limit).
// Script layout: 0x6a (OP_RETURN) + minimal data push:
//   - 0 < len <= 75 bytes: <0x6a> <len> <data>
//   - 76..80 bytes:         <0x6a> <0x4c> <len> <data>  (OP_PUSHDATA1)
func buildOpReturn(payload []byte) ([]byte, error) {
	if len(payload) > 80 {
		return nil, fmt.Errorf("%w: bitcoin: op_return payload exceeds 80-byte standardness limit (got %d bytes)", ErrTxInput, len(payload))
	}
	script := make([]byte, 0, 3+len(payload))
	script = append(script, 0x6a) // OP_RETURN
	if len(payload) < 76 {
		script = append(script, byte(len(payload))) // #nosec G115 -- len < 76
	} else {
		script = append(script, 0x4c, byte(len(payload))) // #nosec G115 -- OP_PUSHDATA1; len capped to 76..80 by caller guard
	}
	script = append(script, payload...)
	return script, nil
}

// BitcoinTxPlan is the result of a no-sign transaction planning step returned
// by PlanBitcoinTx. It carries all information needed to show the user what a
// subsequent SignTransaction call will do, without requiring a wallet or seed.
type BitcoinTxPlan struct {
	// Amount is the value of in.Amount (satoshis to send to the primary recipient).
	Amount int64
	// AvailableAmount is the sum of ALL UTXOs supplied in the SigningInput,
	// regardless of how many were selected.
	AvailableAmount int64
	// Fee is the estimated fee in satoshis (identical to SigningOutput.Fee).
	Fee int64
	// Change is the change output value in satoshis, or 0 when sub-threshold
	// dust is folded into the fee.
	Change int64
	// SelectedUTXO is the subset of UTXOs chosen by coin selection
	// (identical to SigningOutput.UsedUtxo).
	SelectedUTXO []*txbtc.UsedUTXO
	// VsizeEstimate is the estimated virtual size (vbytes) of the transaction.
	VsizeEstimate int64
}

// PlanBitcoinTx performs the coin-selection and fee-estimation steps for a
// Bitcoin transaction without signing or accessing any key material. The
// returned BitcoinTxPlan describes the selected UTXOs, fee, and change for
// the given SigningInput using the same logic as SignTransaction.
//
// PlanBitcoinTx is a pure function over the proto — it requires no wallet or
// seed and can be called before a signing session is available.
func PlanBitcoinTx(symbol Symbol, in *txbtc.SigningInput) (*BitcoinTxPlan, error) {
	if !bitcoinTxSupported(symbol) {
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

	// AvailableAmount = sum of ALL UTXOs (before selection).
	var availableAmount int64
	for _, u := range in.GetUtxo() {
		availableAmount += u.GetAmount()
	}

	plan, err := planBitcoinTx(symbol, in, toScript)
	if err != nil {
		return nil, err
	}

	// Compute the selected total from the used records.
	var selectedTotal int64
	for _, u := range plan.used {
		selectedTotal += u.GetAmount()
	}

	// Change = selectedTotal − fee − (amount sent to recipients).
	var sentAmount int64
	if in.GetUseMaxAmount() {
		sentAmount = selectedTotal - plan.fee // UseMaxAmount sends everything minus fee
	} else {
		sentAmount = in.GetAmount()
		for _, eo := range in.GetExtraOutputs() {
			sentAmount += eo.GetAmount()
		}
	}
	change := selectedTotal - plan.fee - sentAmount
	if change < 0 {
		change = 0
	}

	// Vsize from the plan's actual inputs and outputs.
	outScripts := make([][]byte, len(plan.outputs))
	for i, o := range plan.outputs {
		outScripts[i] = o.script
	}
	vsize := estimateVsize(plan.inputs, outScripts...)

	return &BitcoinTxPlan{
		Amount:          in.GetAmount(),
		AvailableAmount: availableAmount,
		Fee:             plan.fee,
		Change:          change,
		SelectedUTXO:    plan.used,
		VsizeEstimate:   vsize,
	}, nil
}

// sortUTXOs returns a copy of utxos sorted according to sel. SELECT_IN_ORDER
// and USE_ALL return a shallow copy in the original order (no sort needed for
// USE_ALL since every UTXO is selected).
func sortUTXOs(utxos []*txbtc.UnspentTransaction, sel txbtc.InputSelector) []*txbtc.UnspentTransaction {
	sorted := make([]*txbtc.UnspentTransaction, len(utxos))
	copy(sorted, utxos)
	switch sel {
	case txbtc.InputSelector_SELECT_ASCENDING:
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].GetAmount() < sorted[j].GetAmount()
		})
	case txbtc.InputSelector_SELECT_DESCENDING:
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].GetAmount() > sorted[j].GetAmount()
		})
		// SELECT_IN_ORDER and USE_ALL: no reordering required.
	}
	return sorted
}

// planBitcoinTx performs deterministic coin selection and output construction.
//
// Coin selection is controlled by in.InputSelector:
//   - SELECT_IN_ORDER (default): accumulate UTXOs in caller-supplied order.
//   - SELECT_ASCENDING / SELECT_DESCENDING: sort by amount before accumulating.
//   - USE_ALL (or use_max_utxo=true): select every UTXO; still produces change.
//
// Dust policy:
//   - fixed_dust_threshold > 0 overrides the built-in 546-sat threshold.
//   - disable_dust_filter = true always emits the change output when > 0.
//
// Output order is deterministic: [to_address, extra_outputs…, op_return, change].
func planBitcoinTx(symbol Symbol, in *txbtc.SigningInput, toScript []byte) (*btcPlan, error) {
	byteFee := in.GetByteFee()

	// Decode extra output scripts up front so both paths (UseMaxAmount and
	// regular) can share the validated scripts and the aggregate amount.
	extraOuts := in.GetExtraOutputs()
	extraScripts := make([][]byte, len(extraOuts))
	var extraTotal int64
	for i, eo := range extraOuts {
		if eo.GetAmount() <= 0 {
			return nil, fmt.Errorf("%w: bitcoin: extra_output[%d] amount must be positive", ErrTxInput, i)
		}
		s, err := bitcoinDecodeScript(symbol, eo.GetToAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: bitcoin: extra_output[%d] address: %v", ErrTxInput, i, err)
		}
		extraScripts[i] = s
		extraTotal += eo.GetAmount()
	}

	// Build the optional OP_RETURN script; an empty slice means no OP_RETURN.
	var opReturnScript []byte
	if payload := in.GetOutputOpReturn(); len(payload) > 0 {
		var err error
		opReturnScript, err = buildOpReturn(payload)
		if err != nil {
			return nil, err
		}
	}

	// Effective dust threshold: caller override takes precedence.
	dustThreshold := btcDustThreshold
	if in.GetFixedDustThreshold() > 0 {
		dustThreshold = in.GetFixedDustThreshold()
	}

	// Sort a copy of the UTXO list according to the input selector.
	utxos := sortUTXOs(in.GetUtxo(), in.GetInputSelector())

	// useAllInputs is true when the caller wants every UTXO selected regardless
	// of whether fewer would be sufficient to cover the target.
	useAllInputs := in.GetUseMaxUtxo() || in.GetInputSelector() == txbtc.InputSelector_USE_ALL

	// UseMaxAmount: select all UTXOs, send everything minus fee to the recipient
	// (no change output).
	if in.GetUseMaxAmount() {
		if len(extraOuts) > 0 {
			return nil, fmt.Errorf("%w: bitcoin: use_max_amount cannot be combined with extra_outputs", ErrTxInput)
		}
		inputs, used, total, err := selectAll(utxos)
		if err != nil {
			return nil, err
		}
		// Build the full output script list for vsize estimation.
		vscripts := [][]byte{toScript}
		if opReturnScript != nil {
			vscripts = append(vscripts, opReturnScript)
		}
		fee := byteFee * estimateVsize(inputs, vscripts...)
		send := total - fee
		if send <= 0 {
			return nil, fmt.Errorf("%w: bitcoin: balance %d does not cover fee %d", ErrTxInput, total, fee)
		}
		outputs := []btcOutput{{value: send, script: toScript}}
		if opReturnScript != nil {
			outputs = append(outputs, btcOutput{value: 0, script: opReturnScript})
		}
		return &btcPlan{inputs: inputs, outputs: outputs, fee: fee, used: used}, nil
	}

	amount := in.GetAmount()
	if amount <= 0 {
		return nil, fmt.Errorf("%w: bitcoin: amount must be positive", ErrTxInput)
	}
	// Total satoshis that must reach recipient outputs (excluding fee/change).
	totalAmount := amount + extraTotal

	// Decode the change script up-front (when provided) so the fee estimate
	// reflects the real change output type, not an assumed default.
	var changeScript []byte
	if in.GetChangeAddress() != "" {
		var err error
		changeScript, err = bitcoinDecodeScript(symbol, in.GetChangeAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: bitcoin: change_address: %v", ErrTxInput, err)
		}
	}

	// feeFor estimates the fee for a given set of accumulate inputs, always
	// including a tentative change output in the vsize calculation so that the
	// estimate is conservative (adding a real change output later won't
	// cause the fee to be under-estimated).
	feeFor := func(inputs []btcInput) int64 {
		changeForEst := changeScript
		if changeForEst == nil {
			changeForEst = toScript // fall back to recipient type if no change addr
		}
		s := append([][]byte{toScript}, extraScripts...)
		if opReturnScript != nil {
			s = append(s, opReturnScript)
		}
		s = append(s, changeForEst)
		return byteFee * estimateVsize(inputs, s...)
	}

	// buildBaseOutputs assembles the deterministic output list excluding change.
	buildBaseOutputs := func() []btcOutput {
		outs := []btcOutput{{value: amount, script: toScript}}
		for j, eo := range extraOuts {
			outs = append(outs, btcOutput{value: eo.GetAmount(), script: extraScripts[j]})
		}
		if opReturnScript != nil {
			outs = append(outs, btcOutput{value: 0, script: opReturnScript})
		}
		return outs
	}

	// finalise appends the change output (or folds dust into the fee) and
	// returns the completed plan.
	finalise := func(inputs []btcInput, used []*txbtc.UsedUTXO, total, fee int64) (*btcPlan, error) {
		outputs := buildBaseOutputs()
		change := total - totalAmount - fee
		if in.GetDisableDustFilter() {
			// Always emit change when non-zero and a change address is available.
			if change > 0 {
				if changeScript == nil {
					return nil, fmt.Errorf("%w: bitcoin: change of %d sat but no change_address provided", ErrTxInput, change)
				}
				outputs = append(outputs, btcOutput{value: change, script: changeScript})
			}
		} else if change >= dustThreshold {
			if changeScript == nil {
				return nil, fmt.Errorf("%w: bitcoin: change of %d sat but no change_address provided", ErrTxInput, change)
			}
			outputs = append(outputs, btcOutput{value: change, script: changeScript})
		} else {
			fee = total - totalAmount // sub-threshold change folded into the fee
		}
		return &btcPlan{inputs: inputs, outputs: outputs, fee: fee, used: used}, nil
	}

	// USE_ALL / use_max_utxo: select every UTXO and produce normal change.
	if useAllInputs {
		inputs, used, total, err := selectAll(utxos)
		if err != nil {
			return nil, err
		}
		fee := feeFor(inputs)
		if total < totalAmount+fee {
			return nil, fmt.Errorf("%w: bitcoin: insufficient funds (have %d, need %d + fee)", ErrTxInput, total, totalAmount)
		}
		return finalise(inputs, used, total, fee)
	}

	// Default: accumulate UTXOs in selector order until the target is covered.
	var inputs []btcInput
	var used []*txbtc.UsedUTXO
	var total int64
	for _, u := range utxos {
		bi, err := toBtcInput(u)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, bi)
		used = append(used, usedFrom(u))
		total += u.GetAmount()

		fee := feeFor(inputs)
		if total < totalAmount+fee {
			continue
		}
		return finalise(inputs, used, total, fee)
	}
	return nil, fmt.Errorf("%w: bitcoin: insufficient funds (have %d, need %d + fee)", ErrTxInput, total, totalAmount)
}

// selectAll converts every UTXO in the slice to a btcInput (used by
// UseMaxAmount and the USE_ALL / use_max_utxo paths).
func selectAll(utxos []*txbtc.UnspentTransaction) ([]btcInput, []*txbtc.UsedUTXO, int64, error) {
	var inputs []btcInput
	var used []*txbtc.UsedUTXO
	var total int64
	for _, u := range utxos {
		bi, err := toBtcInput(u)
		if err != nil {
			return nil, nil, 0, err
		}
		inputs = append(inputs, bi)
		used = append(used, usedFrom(u))
		total += u.GetAmount()
	}
	return inputs, used, total, nil
}

// usedFrom records a spent UTXO for the SigningOutput.
func usedFrom(u *txbtc.UnspentTransaction) *txbtc.UsedUTXO {
	return &txbtc.UsedUTXO{
		OutPointHash:  u.GetOutPointHash(),
		OutPointIndex: u.GetOutPointIndex(),
		Amount:        u.GetAmount(),
	}
}

// toBtcInput validates and converts a proto UTXO into a btcInput.
func toBtcInput(u *txbtc.UnspentTransaction) (btcInput, error) {
	if len(u.GetOutPointHash()) != 32 {
		return btcInput{}, fmt.Errorf("%w: bitcoin: out_point_hash must be 32 bytes", ErrTxInput)
	}
	if len(u.GetScript()) == 0 {
		return btcInput{}, fmt.Errorf("%w: bitcoin: utxo missing script", ErrTxInput)
	}
	seq := u.GetOutPointSequence()
	if seq == 0 {
		seq = btcDefaultSequence
	}
	bi := btcInput{
		txid:     u.GetOutPointHash(),
		vout:     u.GetOutPointIndex(),
		sequence: seq,
		amount:   u.GetAmount(),
		script:   u.GetScript(),
	}
	if u.KeyIndex != nil {
		bi.keyIndex = u.GetKeyIndex()
		bi.hasKeyIndex = true
	}
	return bi, nil
}

// BitcoinInputKind identifies the script type of an input being spent, for the
// fee/size estimator (EstimateTxVsize / EstimateBitcoinFee).
type BitcoinInputKind int

const (
	// InputP2PKH is a legacy pay-to-pubkey-hash input (no witness).
	InputP2PKH BitcoinInputKind = iota
	// InputP2SHP2WPKH is a nested SegWit (BIP-49) P2SH-P2WPKH input.
	InputP2SHP2WPKH
	// InputP2WPKH is a native SegWit v0 P2WPKH input.
	InputP2WPKH
	// InputP2TR is a Taproot key-path P2TR input.
	InputP2TR
)

// BitcoinOutputKind identifies the script type of an output, for the
// fee/size estimator.
type BitcoinOutputKind int

const (
	// OutputP2PKH is a legacy pay-to-pubkey-hash output (25-byte script).
	OutputP2PKH BitcoinOutputKind = iota
	// OutputP2SH is a pay-to-script-hash output (23-byte script).
	OutputP2SH
	// OutputP2WPKH is a native SegWit v0 P2WPKH output (22-byte script).
	OutputP2WPKH
	// OutputP2TR is a Taproot P2TR output (34-byte script).
	OutputP2TR
)

// Approximate per-input virtual sizes (vbytes), measured against btcd's
// blockchain/txsizes constants. Witness data is discounted at 1/4 weight, so a
// single-key input's vsize is roughly: 41 base + ceil(witnessBytes/4).
//   - P2PKH:        148 (41 base + ~107 scriptSig, no witness discount)
//   - P2SH-P2WPKH:   91 (~64 base incl. redeem-script push + ~27 witness vbytes)
//   - P2WPKH:        68 (41 base + ~27 witness vbytes)
//   - P2TR:          58 (41 base + ~17 witness vbytes: 1-byte stack + 64-byte sig)
const (
	vsizeInP2PKH      = 148
	vsizeInP2SHP2WPKH = 91
	vsizeInP2WPKH     = 68
	vsizeInP2TR       = 58
)

// Per-output virtual sizes (vbytes): 8-byte value + 1-byte len + script.
const (
	vsizeOutP2PKH  = 34 // 8 + 1 + 25
	vsizeOutP2SH   = 32 // 8 + 1 + 23
	vsizeOutP2WPKH = 31 // 8 + 1 + 22
	vsizeOutP2TR   = 43 // 8 + 1 + 34
)

func (k BitcoinInputKind) vsize() int64 {
	switch k {
	case InputP2PKH:
		return vsizeInP2PKH
	case InputP2SHP2WPKH:
		return vsizeInP2SHP2WPKH
	case InputP2TR:
		return vsizeInP2TR
	default: // InputP2WPKH
		return vsizeInP2WPKH
	}
}

func (k BitcoinOutputKind) vsize() int64 {
	switch k {
	case OutputP2PKH:
		return vsizeOutP2PKH
	case OutputP2SH:
		return vsizeOutP2SH
	case OutputP2TR:
		return vsizeOutP2TR
	default: // OutputP2WPKH
		return vsizeOutP2WPKH
	}
}

// EstimateTxVsize returns an approximate virtual size (vbytes) for a transaction
// spending the given input kinds to the given output kinds. It is a coarse
// estimate for fee planning only (not consensus-exact): per-type constants are
// measured against btcd's blockchain/txsizes, with a fixed overhead for the
// version, locktime, the input/output counts and the amortised SegWit
// marker/flag when any input carries a witness.
//
// ponytail: coarse per-type constants, good enough for fee math; refine if
// fee-rate accuracy ever matters.
func EstimateTxVsize(inputs []BitcoinInputKind, outputs []BitcoinOutputKind) int64 {
	vbytes := int64(10) // 4 version + 4 locktime + ~2 amortised in/out compactSize counts
	hasWitness := false
	for _, k := range inputs {
		vbytes += k.vsize()
		if k != InputP2PKH {
			hasWitness = true
		}
	}
	if hasWitness {
		vbytes++ // amortised marker/flag (2 weight units → ~1 vbyte once)
	}
	for _, k := range outputs {
		vbytes += k.vsize()
	}
	return vbytes
}

// EstimateBitcoinFee returns the estimated fee (satoshis) for a transaction of
// the given input/output kinds at satPerVbyte sat/vbyte. It is fee-planning
// guidance, not a consensus value: fee = EstimateTxVsize * satPerVbyte.
func EstimateBitcoinFee(inputs []BitcoinInputKind, outputs []BitcoinOutputKind, satPerVbyte int64) int64 {
	return EstimateTxVsize(inputs, outputs) * satPerVbyte
}

// inputKind classifies an input's scriptPubKey for the estimator.
func inputKind(script []byte) BitcoinInputKind {
	switch {
	case isP2PKH(script):
		return InputP2PKH
	case isP2SHP2WPKH(script):
		return InputP2SHP2WPKH
	case isP2TR(script):
		return InputP2TR
	default: // P2WPKH (or unknown, treated as the segwit default)
		return InputP2WPKH
	}
}

// outputKind classifies an output's scriptPubKey for the estimator.
func outputKind(script []byte) BitcoinOutputKind {
	switch {
	case isP2PKH(script):
		return OutputP2PKH
	case isP2SHP2WPKH(script): // 23-byte P2SH
		return OutputP2SH
	case isP2TR(script) || isP2WSH(script): // both are 34-byte scripts; same vsize (43 vbytes)
		return OutputP2TR
	default: // P2WPKH (or unknown, incl. OP_RETURN)
		return OutputP2WPKH
	}
}

// estimateVsize estimates the vsize of a plan's chosen inputs plus extraOutputs
// output scripts, classifying each input by its scriptPubKey so coin-selection
// fee math reflects the real input types being spent. extraOutputs are the
// recipient/change scriptPubKeys known at planning time.
func estimateVsize(inputs []btcInput, extraOutputs ...[]byte) int64 {
	inKinds := make([]BitcoinInputKind, len(inputs))
	for i, in := range inputs {
		inKinds[i] = inputKind(in.script)
	}
	outKinds := make([]BitcoinOutputKind, len(extraOutputs))
	for i, s := range extraOutputs {
		outKinds[i] = outputKind(s)
	}
	return EstimateTxVsize(inKinds, outKinds)
}

// ---- script-type detection ----

// isP2PKH matches a 25-byte legacy pay-to-pubkey-hash scriptPubKey:
// OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG (76 a9 14 …20… 88 ac).
func isP2PKH(script []byte) bool {
	return len(script) == 25 &&
		script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 &&
		script[23] == 0x88 && script[24] == 0xac
}

// isP2SHP2WPKH matches a 23-byte pay-to-script-hash scriptPubKey:
// OP_HASH160 <20> OP_EQUAL (a9 14 …20… 87). Whether it actually wraps the
// standard P2WPKH redeem script is verified at signing time against the key.
func isP2SHP2WPKH(script []byte) bool {
	return len(script) == 23 &&
		script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87
}

func isP2WPKH(script []byte) bool {
	return len(script) == 22 && script[0] == 0x00 && script[1] == 0x14
}

func isP2TR(script []byte) bool {
	return len(script) == 34 && script[0] == 0x51 && script[1] == 0x20
}

// ---- sighash ----

// legacySighash computes the pre-segwit (BIP-16/legacy) SIGHASH digest for
// input idx. hashType controls which inputs and outputs are committed:
//
//   - SIGHASH_ALL (default): all inputs with their nSequence; all outputs.
//   - SIGHASH_NONE: all inputs; every other input's nSequence zeroed; no outputs.
//   - SIGHASH_SINGLE: all inputs; every other input's nSequence zeroed; outputs
//     truncated to idx+1 with outputs[0..idx-1] as empty slots (value =
//     0xffffffffffffffff, empty script). Callers must guard idx < len(outputs)
//     before calling; signBitcoinInput does this and returns ErrTxInput otherwise.
//   - SIGHASH_ANYONECANPAY (bit 0x80): only input idx is included (nSequence
//     unchanged); combined with the base type above for the outputs section.
func legacySighash(inputs []btcInput, outputs []btcOutput, idx int, subScript []byte, version, locktime, hashType uint32) []byte {
	base := hashType & 0x1f
	anyoneCanPay := (hashType & SigHashAnyoneCanPay) != 0

	var b []byte
	b = append(b, btcLE32(version)...)

	if anyoneCanPay {
		// Only the signing input is committed; its nSequence is unchanged.
		b = append(b, btcVarInt(1)...)
		in := inputs[idx]
		b = append(b, in.txid...)
		b = append(b, btcLE32(in.vout)...)
		b = append(b, btcVarInt(uint64(len(subScript)))...)
		b = append(b, subScript...)
		b = append(b, btcLE32(in.sequence)...)
	} else {
		b = append(b, btcVarInt(uint64(len(inputs)))...)
		for j, in := range inputs {
			b = append(b, in.txid...)
			b = append(b, btcLE32(in.vout)...)
			if j == idx {
				b = append(b, btcVarInt(uint64(len(subScript)))...)
				b = append(b, subScript...)
			} else {
				b = append(b, 0x00) // empty scriptSig
			}
			seq := in.sequence
			if j != idx && (base == SigHashNone || base == SigHashSingle) {
				seq = 0 // other inputs' nSequence zeroed for NONE and SINGLE
			}
			b = append(b, btcLE32(seq)...)
		}
	}

	// Outputs section depends on the base type.
	switch base {
	case SigHashNone:
		b = append(b, btcVarInt(0)...)
	case SigHashSingle:
		// outputs[0..idx-1] are empty placeholders; outputs[idx] is the real output.
		b = append(b, btcVarInt(uint64(idx+1))...) // #nosec G115 -- idx is a non-negative input index
		for range idx {
			b = append(b, btcLE64(0xffffffffffffffff)...) // empty slot: value = -1
			b = append(b, btcVarInt(0)...)                // empty script
		}
		b = appendOutput(b, outputs[idx])
	default: // SigHashAll (and any unknown base treated as ALL)
		b = append(b, btcVarInt(uint64(len(outputs)))...)
		for _, o := range outputs {
			b = appendOutput(b, o)
		}
	}

	b = append(b, btcLE32(locktime)...)
	b = append(b, btcLE32(hashType)...)
	return sha256d(b)
}

// bip143Sighash computes the BIP-143 witness v0 sighash for input idx.
// scriptCode must already include its length prefix.
//
// hashPrevouts, hashSequence and hashOutputs are conditionally zeroed to honour
// SIGHASH_NONE, SIGHASH_SINGLE and SIGHASH_ANYONECANPAY per BIP-143:
//
//	hashPrevouts: 32 zero bytes when ANYONECANPAY; else sha256d(all outpoints).
//	hashSequence: 32 zero bytes when ANYONECANPAY, or base==NONE, or base==SINGLE;
//	              else sha256d(all input nSequences).
//	hashOutputs:  sha256d(all outputs)            when base is ALL (non-NONE/SINGLE);
//	              sha256d(serialize(outputs[idx])) when base==SINGLE and idx in range;
//	              32 zero bytes                   for NONE or SINGLE-out-of-range.
//
// Bitcoin Cash (FORKID 0x40) routes its P2PKH inputs through this function;
// the base type is extracted with & 0x1f so FORKID does not interfere with the
// NONE/SINGLE/ANYONECANPAY conditions.
func bip143Sighash(inputs []btcInput, outputs []btcOutput, idx int, scriptCode []byte, version, locktime, hashType uint32) []byte {
	base := hashType & 0x1f
	anyoneCanPay := (hashType & SigHashAnyoneCanPay) != 0

	// hashPrevouts: zero if ANYONECANPAY, else sha256d(all outpoints).
	var hashPrevouts [32]byte
	if !anyoneCanPay {
		prev := make([]byte, 0, len(inputs)*36)
		for _, in := range inputs {
			prev = append(prev, in.txid...)
			prev = append(prev, btcLE32(in.vout)...)
		}
		copy(hashPrevouts[:], sha256d(prev))
	}

	// hashSequence: zero unless base==ALL and not ANYONECANPAY.
	var hashSequence [32]byte
	if !anyoneCanPay && base != SigHashNone && base != SigHashSingle {
		seqs := make([]byte, 0, len(inputs)*4)
		for _, in := range inputs {
			seqs = append(seqs, btcLE32(in.sequence)...)
		}
		copy(hashSequence[:], sha256d(seqs))
	}

	// hashOutputs: all outputs for ALL; outputs[idx] for SINGLE (if in range);
	// 32 zero bytes for NONE or out-of-range SINGLE.
	var hashOutputs [32]byte
	if base != SigHashNone && base != SigHashSingle {
		outs := make([]byte, 0, len(outputs)*43)
		for _, o := range outputs {
			outs = appendOutput(outs, o)
		}
		copy(hashOutputs[:], sha256d(outs))
	} else if base == SigHashSingle && idx < len(outputs) {
		var out []byte
		out = appendOutput(out, outputs[idx])
		copy(hashOutputs[:], sha256d(out))
	}
	// else: NONE or SINGLE-out-of-range → hashOutputs stays [32]byte{} (zeros).

	in := inputs[idx]
	pre := make([]byte, 0, 4+32+32+36+len(scriptCode)+8+4+32+4+4)
	pre = append(pre, btcLE32(version)...)
	pre = append(pre, hashPrevouts[:]...)
	pre = append(pre, hashSequence[:]...)
	pre = append(pre, in.txid...)
	pre = append(pre, btcLE32(in.vout)...)
	pre = append(pre, scriptCode...)
	pre = append(pre, btcLE64(i64AsU64(in.amount))...)
	pre = append(pre, btcLE32(in.sequence)...)
	pre = append(pre, hashOutputs[:]...)
	pre = append(pre, btcLE32(locktime)...)
	pre = append(pre, btcLE32(hashType)...)
	return sha256d(pre)
}

// bip341Sighash computes the BIP-341 key-path sighash for input idx with
// SIGHASH_DEFAULT (0x00) and no annex.
func bip341Sighash(inputs []btcInput, outputs []btcOutput, idx int, version, locktime uint32) []byte {
	prevouts := make([]byte, 0, len(inputs)*36)
	amounts := make([]byte, 0, len(inputs)*8)
	scriptpubkeys := make([]byte, 0, len(inputs)*35)
	sequences := make([]byte, 0, len(inputs)*4)
	outs := make([]byte, 0, len(outputs)*43)
	for _, in := range inputs {
		prevouts = append(prevouts, in.txid...)
		prevouts = append(prevouts, btcLE32(in.vout)...)
		amounts = append(amounts, btcLE64(i64AsU64(in.amount))...)
		scriptpubkeys = append(scriptpubkeys, btcVarInt(uint64(len(in.script)))...)
		scriptpubkeys = append(scriptpubkeys, in.script...)
		sequences = append(sequences, btcLE32(in.sequence)...)
	}
	for _, o := range outputs {
		outs = appendOutput(outs, o)
	}
	shaPrevouts := sha256.Sum256(prevouts)
	shaAmounts := sha256.Sum256(amounts)
	shaScriptpubkeys := sha256.Sum256(scriptpubkeys)
	shaSequences := sha256.Sum256(sequences)
	shaOutputs := sha256.Sum256(outs)

	msg := make([]byte, 0, 1+4+4+32*5+1+4)
	msg = append(msg, 0x00) // hash_type = SIGHASH_DEFAULT
	msg = append(msg, btcLE32(version)...)
	msg = append(msg, btcLE32(locktime)...)
	msg = append(msg, shaPrevouts[:]...)
	msg = append(msg, shaAmounts[:]...)
	msg = append(msg, shaScriptpubkeys[:]...)
	msg = append(msg, shaSequences[:]...)
	msg = append(msg, shaOutputs[:]...)
	msg = append(msg, 0x00)                                       // spend_type = 0 (no annex, key path)
	msg = append(msg, btcLE32(uint32(idx))...)                    // #nosec G115 -- input index, bounded by len(inputs)
	return taggedHash("TapSighash", append([]byte{0x00}, msg...)) // 0x00 epoch byte
}

// taggedHash computes BIP-340 tagged hash: SHA256(SHA256(tag)||SHA256(tag)||msg).
func taggedHash(tag string, msg []byte) []byte {
	t := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(t[:])
	h.Write(t[:])
	h.Write(msg)
	return h.Sum(nil)
}

// ---- serialization ----

// serializeBitcoinTx serializes the transaction. When withWitness is true and any
// input has a witness, the SegWit marker/flag and witness stacks are included;
// otherwise the legacy (txid) serialization is produced.
func serializeBitcoinTx(version uint32, inputs []btcInput, outputs []btcOutput, locktime uint32, withWitness bool) []byte {
	hasWitness := false
	if withWitness {
		for _, in := range inputs {
			if len(in.witness) > 0 {
				hasWitness = true
				break
			}
		}
	}

	var b []byte
	b = append(b, btcLE32(version)...)
	if hasWitness {
		b = append(b, 0x00, 0x01) // marker, flag
	}
	b = append(b, btcVarInt(uint64(len(inputs)))...)
	for _, in := range inputs {
		b = append(b, in.txid...)
		b = append(b, btcLE32(in.vout)...)
		b = append(b, btcVarInt(uint64(len(in.scriptSig)))...) // empty for native segwit, set for legacy/nested P2SH
		b = append(b, in.scriptSig...)
		b = append(b, btcLE32(in.sequence)...)
	}
	b = append(b, btcVarInt(uint64(len(outputs)))...)
	for _, o := range outputs {
		b = appendOutput(b, o)
	}
	if hasWitness {
		for _, in := range inputs {
			b = append(b, btcVarInt(uint64(len(in.witness)))...)
			for _, item := range in.witness {
				b = append(b, btcVarInt(uint64(len(item)))...)
				b = append(b, item...)
			}
		}
	}
	b = append(b, btcLE32(locktime)...)
	return b
}

// appendOutput appends value(8 LE) || varint(scriptLen) || script.
func appendOutput(b []byte, o btcOutput) []byte {
	b = append(b, btcLE64(i64AsU64(o.value))...)
	b = append(b, btcVarInt(uint64(len(o.script)))...)
	b = append(b, o.script...)
	return b
}

// ---- low-level encoders ----

func btcLE32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func btcLE64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// btcVarInt encodes a Bitcoin compactSize unsigned integer.
func btcVarInt(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		b := make([]byte, 3)
		b[0] = 0xfd
		binary.LittleEndian.PutUint16(b[1:], uint16(n)) // #nosec G115 -- bounded by case guard
		return b
	case n <= 0xffffffff:
		b := make([]byte, 5)
		b[0] = 0xfe
		binary.LittleEndian.PutUint32(b[1:], uint32(n)) // #nosec G115 -- bounded by case guard
		return b
	default:
		b := make([]byte, 9)
		b[0] = 0xff
		binary.LittleEndian.PutUint64(b[1:], n)
		return b
	}
}

// reverseBytes returns a reversed copy of b (used to display txid big-endian).
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}
