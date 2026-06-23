package hdwallet

// Bitcoin transaction signing (BIP-143 P2WPKH + BIP-341/BIP-340 Taproot key-path).
//
// SignTransaction(BTC|LTC, …) builds, signs and serializes a SegWit transaction
// with no broadcast. It spends native-SegWit (P2WPKH) and Taproot key-path
// (P2TR) inputs; the per-UTXO scriptPubKey selects the path. Outputs may be any
// of the four standard address types (decoded via bitcoinDecodeScript).
//
// The transaction wire format is hand-built for byte-exactness, like the other
// non-EVM families. Correctness is pinned in tx_bitcoin_test.go against
// github.com/btcsuite/btcd (full-node txscript) as the oracle: the P2WPKH path
// is asserted byte-identical to btcd's signer, the Taproot sighash is asserted
// equal to txscript.CalcTaprootSignatureHash, and the Schnorr witness is
// verified under BIP-340. The BIP-143 sighash is also checked against the spec's
// worked example.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

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

// btcInput is one transaction input with the data needed to sign it.
type btcInput struct {
	txid     []byte // 32-byte txid in internal (little-endian) byte order
	vout     uint32
	sequence uint32
	amount   int64
	script   []byte // scriptPubKey of the output being spent
	witness  [][]byte
}

// btcOutput is one transaction output.
type btcOutput struct {
	value  int64
	script []byte
}

// signBitcoinTx builds, signs and serializes a Bitcoin/Litecoin SegWit
// transaction. All UTXOs are assumed controlled by the (symbol,index) key.
func (w *HDWallet) signBitcoinTx(symbol Symbol, index uint32, in *txbtc.SigningInput) (*txbtc.SigningOutput, error) {
	if _, ok := btcAddrParams[symbol]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrTxUnsupported, symbol)
	}
	if len(in.GetUtxo()) == 0 {
		return nil, fmt.Errorf("%w: bitcoin: no utxo provided", ErrTxInput)
	}
	if in.GetToAddress() == "" {
		return nil, fmt.Errorf("%w: bitcoin: missing to_address", ErrTxInput)
	}

	pub, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(pub) != 33 {
		return nil, fmt.Errorf("%w: bitcoin: expected 33-byte compressed key", ErrTxInput)
	}

	toScript, err := bitcoinDecodeScript(symbol, in.GetToAddress())
	if err != nil {
		return nil, fmt.Errorf("%w: bitcoin: to_address: %v", ErrTxInput, err)
	}

	plan, err := planBitcoinTx(symbol, in, toScript)
	if err != nil {
		return nil, err
	}

	const version uint32 = 2
	hashType := in.GetHashType()
	if hashType == 0 {
		hashType = 0x01 // SIGHASH_ALL
	}
	locktime := in.GetLockTime()

	for i := range plan.inputs {
		if err := w.signBitcoinInput(symbol, index, pub, plan.inputs, plan.outputs, i, version, locktime, hashType); err != nil {
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
	case isP2WPKH(script):
		keyhash := script[2:]
		if !bytesEqual(hash160(pub), keyhash) {
			return fmt.Errorf("%w: bitcoin: utxo %d not controlled by key at index %d", ErrTxInput, i, index)
		}
		scriptCode := append([]byte{0x19, 0x76, 0xa9, 0x14}, keyhash...) // 0x19 = len(25)
		scriptCode = append(scriptCode, 0x88, 0xac)
		digest := bip143Sighash(inputs, outputs, i, scriptCode, version, locktime, hashType)
		sig, err := w.SignIndex(symbol, index, digest)
		if err != nil {
			return err
		}
		der := sig.DER()
		if der == nil {
			return fmt.Errorf("%w: bitcoin: %s is not an ECDSA coin", ErrTxInput, symbol)
		}
		sigWithType := append(append([]byte(nil), der...), byte(hashType)) // #nosec G115 -- hashType is a 1-byte SIGHASH flag
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
		return fmt.Errorf("%w: bitcoin: utxo %d has unsupported script type (only P2WPKH and P2TR are signable)", ErrTxInput, i)
	}
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

// planBitcoinTx performs simple deterministic coin selection.
//
// ponytail: naive in-order accumulate-until-covered selection; upgrade path is a
// smarter UTXO/fee-optimising selector if fee minimisation ever matters. This is
// not pinned to Trust Wallet's selection PLAN — only the signing/serialization of
// the resulting tx is vector-verified.
func planBitcoinTx(symbol Symbol, in *txbtc.SigningInput, toScript []byte) (*btcPlan, error) {
	byteFee := in.GetByteFee()

	if in.GetUseMaxAmount() {
		inputs, used, total, err := selectAll(in.GetUtxo())
		if err != nil {
			return nil, err
		}
		fee := byteFee * estimateVsize(inputs, 1)
		send := total - fee
		if send <= 0 {
			return nil, fmt.Errorf("%w: bitcoin: balance %d does not cover fee %d", ErrTxInput, total, fee)
		}
		return &btcPlan{
			inputs:  inputs,
			outputs: []btcOutput{{value: send, script: toScript}},
			fee:     fee,
			used:    used,
		}, nil
	}

	amount := in.GetAmount()
	if amount <= 0 {
		return nil, fmt.Errorf("%w: bitcoin: amount must be positive", ErrTxInput)
	}

	var inputs []btcInput
	var used []*txbtc.UsedUTXO
	var total int64
	for _, u := range in.GetUtxo() {
		bi, err := toBtcInput(u)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, bi)
		used = append(used, usedFrom(u))
		total += u.GetAmount()

		fee := byteFee * estimateVsize(inputs, 2) // assume a change output for now
		if total < amount+fee {
			continue
		}
		outputs := []btcOutput{{value: amount, script: toScript}}
		change := total - amount - fee
		if change >= btcDustThreshold {
			changeScript, err := bitcoinDecodeScript(symbol, in.GetChangeAddress())
			if err != nil {
				return nil, fmt.Errorf("%w: bitcoin: change_address: %v", ErrTxInput, err)
			}
			outputs = append(outputs, btcOutput{value: change, script: changeScript})
		} else {
			fee = total - amount // dust change folded into the fee
		}
		return &btcPlan{inputs: inputs, outputs: outputs, fee: fee, used: used}, nil
	}
	return nil, fmt.Errorf("%w: bitcoin: insufficient funds (have %d, need %d + fee)", ErrTxInput, total, amount)
}

// selectAll converts every UTXO to an input (used by UseMaxAmount).
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
	return btcInput{
		txid:     u.GetOutPointHash(),
		vout:     u.GetOutPointIndex(),
		sequence: seq,
		amount:   u.GetAmount(),
		script:   u.GetScript(),
	}, nil
}

// estimateVsize is a rough virtual-size estimate (vbytes) used only for fee
// computation; exact size parity is not required (not vector-pinned).
//
// ponytail: coarse per-type constants, good enough for fee math; refine if
// fee-rate accuracy ever matters.
func estimateVsize(inputs []btcInput, numOutputs int) int64 {
	vbytes := 11 // version + locktime + counts + amortized segwit marker/flag
	for _, in := range inputs {
		switch {
		case isP2TR(in.script):
			vbytes += 58 // 41 base + ~17 witness vbytes
		default:
			vbytes += 68 // P2WPKH: 41 base + ~27 witness vbytes
		}
	}
	vbytes += numOutputs * 34
	return int64(vbytes)
}

// ---- script-type detection ----

func isP2WPKH(script []byte) bool {
	return len(script) == 22 && script[0] == 0x00 && script[1] == 0x14
}

func isP2TR(script []byte) bool {
	return len(script) == 34 && script[0] == 0x51 && script[1] == 0x20
}

// ---- sighash ----

// bip143Sighash computes the BIP-143 witness v0 (P2WPKH) sighash for input idx.
// scriptCode must already include its length prefix.
func bip143Sighash(inputs []btcInput, outputs []btcOutput, idx int, scriptCode []byte, version, locktime, hashType uint32) []byte {
	prevouts := make([]byte, 0, len(inputs)*36)
	sequences := make([]byte, 0, len(inputs)*4)
	outs := make([]byte, 0, len(outputs)*43)
	for _, in := range inputs {
		prevouts = append(prevouts, in.txid...)
		prevouts = append(prevouts, btcLE32(in.vout)...)
		sequences = append(sequences, btcLE32(in.sequence)...)
	}
	for _, o := range outputs {
		outs = appendOutput(outs, o)
	}
	hashPrevouts := sha256d(prevouts)
	hashSequence := sha256d(sequences)
	hashOutputs := sha256d(outs)

	in := inputs[idx]
	pre := make([]byte, 0, 4+32+32+36+len(scriptCode)+8+4+32+4+4)
	pre = append(pre, btcLE32(version)...)
	pre = append(pre, hashPrevouts...)
	pre = append(pre, hashSequence...)
	pre = append(pre, in.txid...)
	pre = append(pre, btcLE32(in.vout)...)
	pre = append(pre, scriptCode...)
	pre = append(pre, btcLE64(i64AsU64(in.amount))...)
	pre = append(pre, btcLE32(in.sequence)...)
	pre = append(pre, hashOutputs...)
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
		b = append(b, 0x00) // empty scriptSig (all inputs are SegWit)
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
