package hdwallet

// BIP-341/342 Taproot script-path primitives.
//
// This file provides the building blocks for spending a taproot output by
// revealing a leaf script (script-path spend), complementing the key-path
// spend already implemented in tx_bitcoin.go.  Task 6 (inscriptions) consumes
// these helpers.
//
// Key invariant: signTaprootScriptPath signs with the UNTWEAKED internal key
// (the leaf key).  The tweak commitment lives in the control block, not in the
// signing key.  This is the fundamental difference from signTaprootKeyPath,
// which signs with the BIP-86 tweaked output key.

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// tapLeafHash returns the BIP-341 TapLeaf hash for a script with leaf version
// 0xc0 (LEAF_VERSION_TAPSCRIPT).  The result equals:
//
//	taggedHash("TapLeaf", []byte{0xc0} || varint(len(script)) || script)
//
// We delegate to txscript.NewBaseTapLeaf so that the leaf-version constant and
// the compact-size encoding are always in sync with the btcd implementation.
func tapLeafHash(script []byte) []byte {
	h := txscript.NewBaseTapLeaf(script).TapHash()
	return h.CloneBytes()
}

// taprootOutputKey derives the BIP-341 tweaked output key from an internal key
// and a merkle root.
//
// internalKeyBytes may be:
//   - 33 bytes (compressed SEC encoding, 0x02/0x03 prefix), or
//   - 32 bytes (x-only, as returned by schnorr.SerializePubKey).
//
// merkleRoot is the tap-tree root hash (32 bytes); pass nil or an empty slice
// for a key-path-only output (BIP-86 H-point tweak with no script).
//
// Returns:
//   - xonly: the 32-byte x-only encoding of the output key.
//   - parity: 0 if the output key's y-coordinate is even, 1 if odd.
//   - err: ErrInvalidAddress if internalKeyBytes cannot be parsed.
func taprootOutputKey(internalKeyBytes []byte, merkleRoot []byte) (xonly []byte, parity byte, err error) {
	internalKey, err := parseTaprootInternalKey(internalKeyBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: taproot: %v", ErrInvalidAddress, err)
	}
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, merkleRoot)
	compressed := outputKey.SerializeCompressed() // 0x02 or 0x03 prefix
	xonly = compressed[1:]                        // drop the parity prefix byte
	parity = compressed[0] & 1                    // 0 = even (0x02), 1 = odd (0x03)
	return xonly, parity, nil
}

// taprootControlBlock builds the BIP-341 control block for a script-path spend.
//
// Layout (BIP-341 §Script path spending):
//
//	byte 0:     leafVersion | parity  (e.g. 0xc0 | parity)
//	bytes 1-32: x-only internal key
//	bytes 33+:  merkle proof hashes, each 32 bytes, in path order
//
// internalKeyBytes may be 33-byte compressed or 32-byte x-only.
// merkleProof is the sibling hashes on the path from the leaf to the root; it
// may be nil or empty for a single-leaf tree (no siblings).
// leafVersion should be 0xc0 (LEAF_VERSION_TAPSCRIPT) for standard tapscript.
func taprootControlBlock(internalKeyBytes []byte, parity byte, merkleProof [][]byte, leafVersion byte) []byte {
	// Derive the 32-byte x-only representation of the internal key.
	var xonly []byte
	if len(internalKeyBytes) == 33 {
		xonly = internalKeyBytes[1:] // strip 0x02/0x03 prefix
	} else {
		xonly = internalKeyBytes // already 32-byte x-only
	}

	cb := make([]byte, 0, 1+32+len(merkleProof)*32)
	cb = append(cb, leafVersion|parity) // control byte
	cb = append(cb, xonly...)           // 32-byte x-only internal key
	for _, h := range merkleProof {
		cb = append(cb, h...)
	}
	return cb
}

// signTaprootScriptPath signs a BIP-342 tapscript sighash with the UNTWEAKED
// (internal) key using BIP-340 Schnorr.  The raw key bytes are wiped on return.
//
// IMPORTANT: Script-path signing must use the internal key, NOT the tweaked
// output key.  The commitment to the script tree is carried by the control
// block, not by the signing key.  Using the tweaked key here would be incorrect
// and would produce a signature that cannot be verified by the consensus rules.
//
// sighash must be exactly 32 bytes (the output of tapscriptSighash).
func (w *HDWallet) signTaprootScriptPath(chain Chain, index uint32, sighash []byte) ([]byte, error) {
	var out []byte
	err := w.withLeafPrivateKey(chain, index, func(raw []byte, _ Coin) error {
		priv, _ := btcec.PrivKeyFromBytes(raw)
		// priv is a *btcec.PrivateKey; raw is wiped on callback return by withLeafPrivateKey.
		sig, err := schnorr.Sign(priv, sighash)
		if err != nil {
			return fmt.Errorf("hdwallet: bitcoin: tapscript schnorr sign: %w", err)
		}
		out = sig.Serialize()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// tapscriptSighash computes the BIP-342 script-path sighash for a tapscript
// spend (SIGHASH_DEFAULT / 0x00).
//
// inputs and outputs describe the transaction being signed.  idx is the index
// of the input being signed.  leafScript is the tapscript leaf being executed.
// version and locktime are the transaction version and lock-time fields.
//
// Internally this delegates to btcd's txscript.CalcTaprootSignatureHash with
// the txscript.WithBaseTapscriptVersion option so that the leaf hash is
// computed consistently with the reference implementation.
func tapscriptSighash(inputs []btcInput, outputs []btcOutput, idx int, leafScript []byte, version, locktime uint32) ([]byte, error) {
	if idx < 0 || idx >= len(inputs) {
		return nil, fmt.Errorf("%w: bitcoin: tapscript sighash: input index %d out of range", ErrTxInput, idx)
	}

	// Build a wire.MsgTx from our internal representation.
	tx := &wire.MsgTx{
		Version:  int32(version), // #nosec G115 -- version is a tx version field (1 or 2)
		LockTime: locktime,
	}
	for _, in := range inputs {
		var h chainhash.Hash
		copy(h[:], in.txid)
		txIn := wire.NewTxIn(&wire.OutPoint{Hash: h, Index: in.vout}, nil, nil)
		txIn.Sequence = in.sequence
		tx.TxIn = append(tx.TxIn, txIn)
	}
	for _, out := range outputs {
		tx.TxOut = append(tx.TxOut, wire.NewTxOut(out.value, out.script))
	}

	// Build a MultiPrevOutFetcher with each input's amount and scriptPubKey.
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(inputs))
	for _, in := range inputs {
		var h chainhash.Hash
		copy(h[:], in.txid)
		op := wire.OutPoint{Hash: h, Index: in.vout}
		prevOuts[op] = wire.NewTxOut(in.amount, in.script)
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)

	hash, err := txscript.CalcTapscriptSignaturehash(
		sigHashes,
		txscript.SigHashDefault,
		tx,
		idx,
		fetcher,
		txscript.NewBaseTapLeaf(leafScript),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: bitcoin: tapscript sighash: %v", ErrTxInput, err)
	}
	return hash, nil
}

// parseTaprootInternalKey parses a 33-byte compressed or 32-byte x-only public
// key into a *btcec.PublicKey.  Returns an error for any other length or an
// invalid key encoding.
func parseTaprootInternalKey(keyBytes []byte) (*btcec.PublicKey, error) {
	switch len(keyBytes) {
	case 33:
		return btcec.ParsePubKey(keyBytes)
	case 32:
		// Prepend the even-parity prefix and parse as compressed.
		compressed := make([]byte, 33)
		compressed[0] = 0x02
		copy(compressed[1:], keyBytes)
		return btcec.ParsePubKey(compressed)
	default:
		return nil, fmt.Errorf("invalid key length %d (want 32 or 33)", len(keyBytes))
	}
}
