package hdwallet

// BRC-20 / Ordinals inscription support: commit + reveal transactions.
//
// An Ordinals inscription is a tapscript leaf that carries arbitrary content
// (BRC-20 JSON for transfers) inside an OP_FALSE OP_IF … OP_ENDIF envelope.
// The two-phase flow is:
//
//  1. Commit: send funds to a P2TR address whose taproot output key commits to
//     the inscription leaf.  The internal/signing key is the wallet key.
//
//  2. Reveal: spend that output via a script-path spend that pushes the
//     witness stack [sig, leafScript, controlBlock] and thereby reveals the
//     inscription on-chain.
//
// Security invariants are unchanged: private keys are derived and wiped inside
// withLeafPrivateKey / signTaprootScriptPath; they are never returned.

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// inscriptionChunkSize is the maximum number of bytes in a single OP_0 data
// push inside the inscription envelope.  Bitcoin's script engine limits a
// single PUSHDATA to 520 bytes.
const inscriptionChunkSize = 520

// BuildInscriptionScript builds the tapscript leaf for an Ordinals inscription.
//
// Layout:
//
//	<32-byte xonly pubkey> OP_CHECKSIG   // key-spend guard
//	OP_FALSE OP_IF                        // envelope open  (OP_0 = 0x00, OP_IF = 0x63)
//	  push("ord")                         // protocol tag
//	  OP_1 push(<contentType bytes>)      // content-type field
//	  OP_0 push(<body chunk>)             // body chunks, ≤520 bytes each
//	  [OP_0 push(<next chunk>) …]
//	OP_ENDIF                              // envelope close
//
// xonlyPubkey must be exactly 32 bytes; returns ErrTxInput otherwise.
func BuildInscriptionScript(xonlyPubkey []byte, contentType string, body []byte) ([]byte, error) {
	if len(xonlyPubkey) != 32 {
		return nil, fmt.Errorf("%w: inscription: xonly pubkey must be 32 bytes (got %d)", ErrTxInput, len(xonlyPubkey))
	}

	var s []byte

	// <32-byte xonly pubkey> OP_CHECKSIG
	s = append(s, 0x20) // push 32 bytes
	s = append(s, xonlyPubkey...)
	s = append(s, 0xac) // OP_CHECKSIG

	// OP_FALSE OP_IF  (OP_0 = 0x00, OP_IF = 0x63)
	s = append(s, 0x00, 0x63)

	// push("ord")
	s = append(s, btcPush([]byte("ord"))...)

	// OP_1 push(<contentType>)
	s = append(s, 0x51) // OP_1
	s = append(s, btcPush([]byte(contentType))...)

	// OP_0 push(<body chunk>) for each ≤520-byte chunk
	for len(body) > 0 {
		chunk := body
		if len(chunk) > inscriptionChunkSize {
			chunk = body[:inscriptionChunkSize]
		}
		body = body[len(chunk):]
		s = append(s, 0x00) // OP_0
		s = append(s, btcPush(chunk)...)
	}

	// OP_ENDIF
	s = append(s, 0x68)

	return s, nil
}

// BuildBRC20TransferBody returns the canonical BRC-20 transfer JSON body.
// Field order is fund-critical (indexers are order-sensitive); we use
// fmt.Sprintf rather than json.Marshal to guarantee the exact field sequence.
func BuildBRC20TransferBody(ticker, amount string) []byte {
	return []byte(fmt.Sprintf(`{"p":"brc-20","op":"transfer","tick":"%s","amt":"%s"}`, ticker, amount))
}

// InscriptionCommit carries all the data a caller needs to build and broadcast
// the reveal transaction after the commit has confirmed.
type InscriptionCommit struct {
	// CommitAddress is the bech32m P2TR address to which the commit tx sends funds.
	CommitAddress string
	// CommitScript is the 34-byte P2TR scriptPubKey (OP_1 <32-byte xonly output key>)
	// of the commit output — needed as the prevout scriptPubKey when signing the reveal.
	CommitScript []byte
	// LeafScript is the full inscription tapscript leaf built by BuildInscriptionScript.
	LeafScript []byte
	// ControlBlock is the BIP-341 control block for the script-path reveal spend.
	ControlBlock []byte
	// InternalKey is the 33-byte compressed public key of the wallet key used as the
	// internal taproot key.
	InternalKey []byte
}

// BuildBRC20Commit builds and signs the commit transaction for a BRC-20 transfer
// inscription, returning the signed raw-tx hex and an InscriptionCommit that
// carries all data needed for the subsequent reveal.
//
// The commit output pays to a P2TR address whose taproot output key is derived
// from the wallet key (internal key) tweaked by the merkle root of a single-leaf
// script tree containing the inscription envelope.
//
// in.ToAddress is overwritten with the derived commit address before signing; the
// caller should treat the SigningInput as consumed after this call.
func (w *HDWallet) BuildBRC20Commit(chain Chain, index uint32, ticker, amount string,
	in *txbtc.SigningInput) (commitTxHex string, reveal *InscriptionCommit, err error) {

	// a. Derive the 33-byte compressed public key for (chain, index).
	pub33, err := w.PublicKeyIndex(chain, index)
	if err != nil {
		return "", nil, fmt.Errorf("hdwallet: inscription: public key: %w", err)
	}

	// b. x-only (strip the 0x02/0x03 prefix byte).
	xonly := pub33[1:]

	// c. Build the BRC-20 transfer body.
	body := BuildBRC20TransferBody(ticker, amount)

	// d. Build the tapscript leaf.
	leafScript, err := BuildInscriptionScript(xonly, "text/plain;charset=utf-8", body)
	if err != nil {
		return "", nil, err
	}

	// e–f. Assemble a single-leaf script tree and extract the merkle root.
	tree := txscript.AssembleTaprootScriptTree(txscript.NewBaseTapLeaf(leafScript))
	rootHash := tree.RootNode.TapHash()
	merkleRoot := rootHash.CloneBytes()

	// g. Derive the tweaked output key (x-only + parity).
	xonlyOut, parity, err := taprootOutputKey(pub33, merkleRoot)
	if err != nil {
		return "", nil, fmt.Errorf("hdwallet: inscription: output key: %w", err)
	}

	// h. Reconstruct a full *btcec.PublicKey from the x-only output key.
	prefix := byte(0x02)
	if parity == 1 {
		prefix = 0x03
	}
	outputPubKey, err := btcec.ParsePubKey(append([]byte{prefix}, xonlyOut...))
	if err != nil {
		return "", nil, fmt.Errorf("hdwallet: inscription: parse output pubkey: %w", err)
	}

	// i. Build the P2TR scriptPubKey for the commit output.
	commitScript, err := txscript.PayToTaprootScript(outputPubKey)
	if err != nil {
		return "", nil, fmt.Errorf("hdwallet: inscription: commit script: %w", err)
	}

	// j. Derive the bech32m commit address.
	addrTaproot, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(outputPubKey), &chaincfg.MainNetParams)
	if err != nil {
		return "", nil, fmt.Errorf("hdwallet: inscription: commit address: %w", err)
	}
	commitAddr := addrTaproot.EncodeAddress()

	// k. Sign the commit tx (routes the payment to the inscription output address).
	in.ToAddress = commitAddr
	out, err := w.signBitcoinTx(chain, index, in)
	if err != nil {
		return "", nil, fmt.Errorf("hdwallet: inscription: sign commit: %w", err)
	}

	// l. Build the control block for the single-leaf script-path spend.
	// InclusionProof is a flat []byte (32 bytes per sibling hash); chunk it.
	proof := tree.LeafMerkleProofs[0]
	proofBytes := proof.InclusionProof
	merkleProofHashes := make([][]byte, 0, len(proofBytes)/32)
	for len(proofBytes) >= 32 {
		h := make([]byte, 32)
		copy(h, proofBytes[:32])
		merkleProofHashes = append(merkleProofHashes, h)
		proofBytes = proofBytes[32:]
	}
	cb := taprootControlBlock(pub33, parity, merkleProofHashes, 0xc0)

	// m. Return the signed commit hex and the reveal descriptor.
	return out.EncodedHex, &InscriptionCommit{
		CommitAddress: commitAddr,
		CommitScript:  commitScript,
		LeafScript:    leafScript,
		ControlBlock:  cb,
		InternalKey:   pub33,
	}, nil
}

// SignBRC20Reveal builds and signs the reveal transaction for a BRC-20 transfer
// inscription.
//
// The reveal spends the commit output (identified by commitTxID:commitVout) via a
// tapscript script-path spend, pushing the Ordinals witness stack
// [sig, leafScript, controlBlock] so that the inscription is revealed on-chain.
//
// revealFee = feeRate * 200 (fixed 200-vbyte estimate).
// The net output value (commitAmount − revealFee) must exceed btcDustThreshold.
func (w *HDWallet) SignBRC20Reveal(chain Chain, index uint32, reveal *InscriptionCommit,
	commitTxID []byte, commitVout uint32, commitAmount int64,
	toAddress string, feeRate int64) (revealTxHex string, err error) {

	// a. Decode the destination output script.
	toScript, err := bitcoinDecodeScript(chain, toAddress)
	if err != nil {
		return "", fmt.Errorf("hdwallet: inscription: reveal: to_address: %w", err)
	}

	// b. Fixed 200-vbyte fee estimate (ponytail: replace with estimateVsize if
	//    precision matters).
	revealFee := feeRate * 200

	// c. Compute the net output value and validate it.
	outputValue := commitAmount - revealFee
	if outputValue <= 0 || outputValue < btcDustThreshold {
		return "", fmt.Errorf("%w: inscription: reveal output value %d is below dust threshold after fee %d",
			ErrTxInput, outputValue, revealFee)
	}

	// d. Build the single input spending the commit output.
	inp := btcInput{
		txid:     commitTxID,
		vout:     commitVout,
		sequence: btcDefaultSequence,
		amount:   commitAmount,
		script:   reveal.CommitScript,
	}

	// e. Build the single output delivering the inscription to the recipient.
	outputs := []btcOutput{{value: outputValue, script: toScript}}

	// f. Transaction version and locktime.
	version := btcTxVersion(chain)
	locktime := uint32(0)

	// g. Compute the BIP-342 tapscript sighash for the script-path spend.
	sighash, err := tapscriptSighash([]btcInput{inp}, outputs, 0, reveal.LeafScript, version, locktime)
	if err != nil {
		return "", fmt.Errorf("hdwallet: inscription: reveal: sighash: %w", err)
	}

	// h. Sign with the UNTWEAKED internal key (script-path signing rule).
	sig64, err := w.signTaprootScriptPath(chain, index, sighash)
	if err != nil {
		return "", fmt.Errorf("hdwallet: inscription: reveal: sign: %w", err)
	}

	// i. Attach the Ordinals script-path witness stack.
	inp.witness = [][]byte{sig64, reveal.LeafScript, reveal.ControlBlock}

	// j. Serialize the transaction.
	encoded := serializeBitcoinTx(version, []btcInput{inp}, outputs, locktime, true)

	// k. Return the hex-encoded raw transaction.
	return bytesToHex(encoded), nil
}
