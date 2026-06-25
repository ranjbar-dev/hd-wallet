package hdwallet

// Zcash transparent transaction signing (Sapling v4 / ZIP-243).
//
// signZcashTx spends transparent P2PKH (t-addr) UTXOs and pays any t-addr output,
// reusing the deterministic coin-selection plan (planBitcoinTx) and the secp256k1
// DER signer shared with the Bitcoin builder. Zcash differs from Bitcoin in two
// fund-critical ways, both implemented here:
//
//   - Wire format: a Sapling v4 transaction is an Overwinter-flagged version-4
//     header (0x80000004) plus an nVersionGroupId (0x892F2085), the usual
//     transparent inputs/outputs, then nLockTime, nExpiryHeight, valueBalance and
//     three zero shielded-bundle counts (no shielded data, no binding sig).
//
//   - Sighash: ZIP-243 replaces Bitcoin's double-SHA256 sighash with a set of
//     BLAKE2b-256 hashes personalized with the network's consensus branch id.
//
// It is pinned byte-for-byte to Trust Wallet Core's Zcash AnySigner vector
// (tx_zcash_test.go), which was broadcast on Zcash mainnet.

import (
	"fmt"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

const (
	// zcashOverwinterVersion is the Sapling transaction header: the Overwinter
	// flag (bit 31) set over transaction version 4.
	zcashOverwinterVersion uint32 = 0x80000004
	// zcashSaplingVersionGroupID is the nVersionGroupId for Sapling v4 transactions.
	zcashSaplingVersionGroupID uint32 = 0x892F2085
	// zcashSaplingBranchID is the Sapling consensus branch id, folded into the
	// ZIP-243 sighash personalization. (Only Sapling is wired; later upgrades —
	// Blossom/Heartwood/Canopy/NU5 — would each need their own branch id + vector.)
	zcashSaplingBranchID uint32 = 0x76b809bb
)

// signZcashTx builds, signs and serializes a Zcash Sapling v4 transparent
// transaction. All UTXOs are assumed controlled by the (ZEC,index) key.
func (w *HDWallet) signZcashTx(index uint32, in *txbtc.SigningInput) (*txbtc.SigningOutput, error) {
	if len(in.GetUtxo()) == 0 {
		return nil, fmt.Errorf("%w: zcash: no utxo provided", ErrTxInput)
	}
	if in.GetToAddress() == "" {
		return nil, fmt.Errorf("%w: zcash: missing to_address", ErrTxInput)
	}

	pub, err := w.PublicKeyIndex(ZEC, index)
	if err != nil {
		return nil, err
	}
	if len(pub) != 33 {
		return nil, fmt.Errorf("%w: zcash: expected 33-byte compressed key", ErrTxInput)
	}

	toScript, err := bitcoinDecodeScript(ZEC, in.GetToAddress())
	if err != nil {
		return nil, fmt.Errorf("%w: zcash: to_address: %v", ErrTxInput, err)
	}

	plan, err := planBitcoinTx(ZEC, in, toScript)
	if err != nil {
		return nil, err
	}

	hashType := in.GetHashType()
	if hashType == 0 {
		hashType = 0x01 // SIGHASH_ALL
	}
	locktime := in.GetLockTime()
	const expiry uint32 = 0 // nExpiryHeight; the pinned vector uses 0 (no expiry)

	for i := range plan.inputs {
		if err := w.signZcashInput(index, pub, plan.inputs, plan.outputs, i, locktime, expiry, hashType); err != nil {
			return nil, err
		}
	}

	encoded := serializeZcashTx(plan.inputs, plan.outputs, locktime, expiry)
	txid := reverseBytes(sha256d(encoded))

	return &txbtc.SigningOutput{
		Encoded:       encoded,
		EncodedHex:    bytesToHex(encoded),
		TransactionId: txid,
		Fee:           plan.fee,
		UsedUtxo:      plan.used,
	}, nil
}

// signZcashInput computes the ZIP-243 sighash for transparent input i and fills
// in its legacy P2PKH scriptSig. Only transparent P2PKH inputs are signable.
func (w *HDWallet) signZcashInput(index uint32, pub []byte, inputs []btcInput, outputs []btcOutput, i int, locktime, expiry, hashType uint32) error {
	script := inputs[i].script
	if !isP2PKH(script) {
		return fmt.Errorf("%w: zcash: utxo %d has unsupported script type (only transparent P2PKH is signable)", ErrTxInput, i)
	}
	if !bytesEqual(hash160(pub), script[3:23]) {
		return fmt.Errorf("%w: zcash: utxo %d not controlled by key at index %d", ErrTxInput, i, index)
	}
	scriptCode := append(btcVarInt(uint64(len(script))), script...)
	digest := zcashSighash(inputs, outputs, i, scriptCode, locktime, expiry, hashType, zcashSaplingBranchID)
	sigWithType, err := w.btcDERSig(ZEC, index, digest, hashType)
	if err != nil {
		return err
	}
	inputs[i].scriptSig = append(btcPush(sigWithType), btcPush(pub)...)
	inputs[i].witness = nil
	return nil
}

// zcashSighash computes the ZIP-243 transparent-input signature hash for input
// idx. scriptCode must already include its length prefix. The branch id selects
// the network upgrade (Sapling here) and enters the final BLAKE2b personalization.
func zcashSighash(inputs []btcInput, outputs []btcOutput, idx int, scriptCode []byte, locktime, expiry, hashType, branchID uint32) []byte {
	prevouts := make([]byte, 0, len(inputs)*36)
	sequences := make([]byte, 0, len(inputs)*4)
	for _, in := range inputs {
		prevouts = append(prevouts, in.txid...)
		prevouts = append(prevouts, btcLE32(in.vout)...)
		sequences = append(sequences, btcLE32(in.sequence)...)
	}
	outs := make([]byte, 0, len(outputs)*34)
	for _, o := range outputs {
		outs = appendOutput(outs, o)
	}

	hashPrevouts := blake2bPersonal(32, []byte("ZcashPrevoutHash"), prevouts)
	hashSequence := blake2bPersonal(32, []byte("ZcashSequencHash"), sequences)
	hashOutputs := blake2bPersonal(32, []byte("ZcashOutputsHash"), outs)
	zero32 := make([]byte, 32) // hashJoinSplits / hashShieldedSpends / hashShieldedOutputs

	in := inputs[idx]
	pre := make([]byte, 0, 4+4+32*6+4+4+8+4+36+len(scriptCode)+8+4)
	pre = append(pre, btcLE32(zcashOverwinterVersion)...)
	pre = append(pre, btcLE32(zcashSaplingVersionGroupID)...)
	pre = append(pre, hashPrevouts...)
	pre = append(pre, hashSequence...)
	pre = append(pre, hashOutputs...)
	pre = append(pre, zero32...) // hashJoinSplits
	pre = append(pre, zero32...) // hashShieldedSpends
	pre = append(pre, zero32...) // hashShieldedOutputs
	pre = append(pre, btcLE32(locktime)...)
	pre = append(pre, btcLE32(expiry)...)
	pre = append(pre, btcLE64(0)...) // valueBalance (no shielded value)
	pre = append(pre, btcLE32(hashType)...)
	pre = append(pre, in.txid...)
	pre = append(pre, btcLE32(in.vout)...)
	pre = append(pre, scriptCode...)
	pre = append(pre, btcLE64(i64AsU64(in.amount))...)
	pre = append(pre, btcLE32(in.sequence)...)

	person := append([]byte("ZcashSigHash"), btcLE32(branchID)...) // 12 + 4 = 16 bytes
	return blake2bPersonal(32, person, pre)
}

// serializeZcashTx serializes a Sapling v4 transparent transaction. There are no
// shielded spends/outputs/joinsplits (all-transparent), so their counts are zero
// and no binding signature is appended.
func serializeZcashTx(inputs []btcInput, outputs []btcOutput, locktime, expiry uint32) []byte {
	var b []byte
	b = append(b, btcLE32(zcashOverwinterVersion)...)
	b = append(b, btcLE32(zcashSaplingVersionGroupID)...)
	b = append(b, btcVarInt(uint64(len(inputs)))...)
	for _, in := range inputs {
		b = append(b, in.txid...)
		b = append(b, btcLE32(in.vout)...)
		b = append(b, btcVarInt(uint64(len(in.scriptSig)))...)
		b = append(b, in.scriptSig...)
		b = append(b, btcLE32(in.sequence)...)
	}
	b = append(b, btcVarInt(uint64(len(outputs)))...)
	for _, o := range outputs {
		b = appendOutput(b, o)
	}
	b = append(b, btcLE32(locktime)...)
	b = append(b, btcLE32(expiry)...)
	b = append(b, btcLE64(0)...) // valueBalance
	b = append(b, 0x00)          // nShieldedSpend
	b = append(b, 0x00)          // nShieldedOutput
	b = append(b, 0x00)          // nJoinSplit
	return b
}
