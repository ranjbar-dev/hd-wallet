package hdwallet

import (
	"fmt"
	"sort"

	"google.golang.org/protobuf/proto"

	txalgo "github.com/ranjbar-dev/hd-wallet/txproto/algorand"
)

// Algorand (ALGO) transaction signing.
//
// Wire format: canonical MessagePack with the following rules:
//   - Maps: string keys, sorted lexicographically
//   - Zero-value fields: omitted (not encoded)
//   - Integers: smallest unsigned msgpack type that fits the value
//   - Byte arrays: msgpack bin format
//   - Strings: msgpack str format
//
// Signing preimage:
//  1. prefix    = []byte("TX")                        — 2-byte domain tag
//  2. msgpackTx = canonical_msgpack(payment_tx_map)
//  3. preimage  = prefix || msgpackTx
//  4. sig       = ed25519.Sign(key, preimage)
//     ed25519 signs the full preimage directly — do NOT pre-hash with SHA-512/256.
//     ed25519 hashes internally (SHA-512 over the message) as per RFC 8032.
//  5. output    = canonical_msgpack({ "sig": sig, "txn": payment_tx_map })
//
// The sender's 32-byte public key is derived from the wallet's ed25519 key
// and used as the "snd" field.
//
// Verified byte-for-byte against Trust Wallet Core AlgorandTests.cpp
// test "TEST(AlgorandSigner, Sign)" (private key c9d3cc16...).
//
// Source: https://github.com/trustwallet/wallet-core/blob/master/tests/chains/Algorand/SignerTests.cpp

// algoTxPrefix is the 2-byte domain separation tag prepended before signing.
var algoTxPrefix = []byte("TX")

// signALGOTx signs an Algorand payment transaction and returns the canonical
// msgpack-encoded signed transaction.
func (w *HDWallet) signALGOTx(_ Symbol, index uint32, in *txalgo.SigningInput) (proto.Message, error) {
	if len(in.GenesisHash) != 32 {
		return nil, fmt.Errorf("%w: ALGO: genesis_hash must be 32 bytes", ErrTxInput)
	}
	if len(in.To) != 32 {
		return nil, fmt.Errorf("%w: ALGO: to must be 32 bytes (raw public key)", ErrTxInput)
	}

	// Derive the sender's 32-byte ed25519 public key.
	snd, err := w.PublicKeyIndex(ALGO, index)
	if err != nil {
		return nil, fmt.Errorf("ALGO: derive public key: %w", err)
	}

	// Build the canonical msgpack transaction map (unsigned).
	txMap := algoMakePaymentMap(snd, in)
	txMsgpack := algoEncodeMsgpackMap(txMap)

	// preimage = "TX" || canonical_msgpack(tx). ed25519 signs the full preimage
	// directly — Algorand does NOT pre-hash with SHA-512/256. The ed25519 scheme
	// hashes internally (SHA-512) as part of the EdDSA signing algorithm.
	preimage := make([]byte, 0, len(algoTxPrefix)+len(txMsgpack))
	preimage = append(preimage, algoTxPrefix...)
	preimage = append(preimage, txMsgpack...)

	// Sign the full preimage with ed25519. Key is derived and wiped inside.
	sig, err := w.SignIndex(ALGO, index, preimage)
	if err != nil {
		return nil, fmt.Errorf("ALGO: sign: %w", err)
	}
	sigBytes := sig.Bytes() // 64-byte ed25519 signature

	// Encode the signed transaction: {"sig": sig, "txn": tx_map}.
	// The outer map must also be sorted canonically; sort defensively even though
	// "sig" < "txn" is already correct, to guard against future field additions.
	signedMap := []algoMapEntry{
		{"sig", algoMsgpackBin(sigBytes)},
		{"txn", algoMsgpackRaw(txMsgpack)},
	}
	sort.Slice(signedMap, func(i, j int) bool { return signedMap[i].key < signedMap[j].key })
	encoded := algoEncodeMsgpackMap(signedMap)

	return &txalgo.SigningOutput{
		Encoded:    encoded,
		EncodedHex: bytesToHex(encoded),
	}, nil
}

// algoMapEntry is a key-value pair for canonical msgpack encoding.
type algoMapEntry struct {
	key string
	val []byte // pre-encoded msgpack value
}

// algoMakePaymentMap builds the sorted list of map entries for a payment tx.
// Zero-value fields (note, genesis_id) are omitted when empty.
func algoMakePaymentMap(snd []byte, in *txalgo.SigningInput) []algoMapEntry {
	entries := make([]algoMapEntry, 0, 10)

	// "amt": amount in microAlgos
	if in.Amount != 0 {
		entries = append(entries, algoMapEntry{"amt", algoMsgpackUint(in.Amount)})
	}

	// "fee": fee in microAlgos
	if in.Fee != 0 {
		entries = append(entries, algoMapEntry{"fee", algoMsgpackUint(in.Fee)})
	}

	// "fv": first valid round
	if in.FirstValid != 0 {
		entries = append(entries, algoMapEntry{"fv", algoMsgpackUint(in.FirstValid)})
	}

	// "gen": genesis ID (optional)
	if in.GenesisId != "" {
		entries = append(entries, algoMapEntry{"gen", algoMsgpackStr(in.GenesisId)})
	}

	// "gh": genesis hash (32 bytes)
	entries = append(entries, algoMapEntry{"gh", algoMsgpackBin(in.GenesisHash)})

	// "lv": last valid round
	if in.LastValid != 0 {
		entries = append(entries, algoMapEntry{"lv", algoMsgpackUint(in.LastValid)})
	}

	// "note": optional note
	if len(in.Note) != 0 {
		entries = append(entries, algoMapEntry{"note", algoMsgpackBin(in.Note)})
	}

	// "rcv": recipient 32-byte pubkey
	entries = append(entries, algoMapEntry{"rcv", algoMsgpackBin(in.To)})

	// "snd": sender 32-byte pubkey
	entries = append(entries, algoMapEntry{"snd", algoMsgpackBin(snd)})

	// "type": "pay"
	entries = append(entries, algoMapEntry{"type", algoMsgpackStr("pay")})

	// Sort entries lexicographically by key (canonical msgpack requirement).
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	return entries
}

// algoEncodeMsgpackMap encodes a sorted list of map entries as canonical msgpack.
func algoEncodeMsgpackMap(entries []algoMapEntry) []byte {
	n := len(entries)
	var buf []byte
	// fixmap: 0x80 | n (requires n <= 15; Algorand tx maps are always small)
	buf = append(buf, lowByte(0x80|n))
	for _, e := range entries {
		buf = append(buf, algoMsgpackStr(e.key)...)
		buf = append(buf, e.val...)
	}
	return buf
}

// algoMsgpackRaw wraps pre-encoded msgpack bytes as a raw value (no re-encoding).
func algoMsgpackRaw(b []byte) []byte {
	return b
}

// algoMsgpackBin encodes a byte slice as msgpack bin format.
// Uses bin8 (0xc4 + 1-byte len) for ≤255 bytes.
func algoMsgpackBin(b []byte) []byte {
	l := len(b)
	if l <= 0xff {
		out := make([]byte, 0, 2+l)
		out = append(out, 0xc4, lowByte(l))
		return append(out, b...)
	}
	// bin16 (covers up to 65535 bytes)
	out := make([]byte, 0, 3+l)
	out = append(out, 0xc5, lowByte(l>>8), lowByte(l))
	return append(out, b...)
}

// algoMsgpackStr encodes a string as msgpack str format.
// Uses fixstr (0xa0 | len) for ≤31 bytes; str8 (0xd9 + 1-byte len) for ≤255 bytes.
func algoMsgpackStr(s string) []byte {
	b := []byte(s)
	l := len(b)
	if l <= 31 {
		out := make([]byte, 0, 1+l)
		out = append(out, lowByte(0xa0|l))
		return append(out, b...)
	}
	// str8
	out := make([]byte, 0, 2+l)
	out = append(out, 0xd9, lowByte(l))
	return append(out, b...)
}

// algoMsgpackUint encodes a uint64 using the smallest msgpack unsigned integer
// type that fits the value.
func algoMsgpackUint(v uint64) []byte {
	switch {
	case v <= 0x7f: // positive fixint
		return []byte{lowByte(int(v))} // lowByte masks to low byte; value bounded to 0x7f
	case v <= 0xff: // uint8
		return []byte{0xcc, lowByte(int(v))} // lowByte masks to low byte; value bounded to 0xff
	case v <= 0xffff: // uint16
		return []byte{0xcd,
			byte(v >> 8),   // #nosec G115 -- v <= 0xffff; shift brings value into [0,0xff]
			byte(v & 0xff)} // #nosec G115 -- explicit low-byte mask
	case v <= 0xffffffff: // uint32
		return []byte{0xce,
			byte(v >> 24),  // #nosec G115 -- v <= 0xffffffff; byte extraction of big-endian word
			byte(v >> 16),  // #nosec G115 -- same
			byte(v >> 8),   // #nosec G115 -- same
			byte(v & 0xff)} // #nosec G115 -- explicit low-byte mask
	default: // uint64
		return []byte{0xcf,
			byte(v >> 56),  // #nosec G115 -- byte extraction of big-endian uint64
			byte(v >> 48),  // #nosec G115 -- same
			byte(v >> 40),  // #nosec G115 -- same
			byte(v >> 32),  // #nosec G115 -- same
			byte(v >> 24),  // #nosec G115 -- same
			byte(v >> 16),  // #nosec G115 -- same
			byte(v >> 8),   // #nosec G115 -- same
			byte(v & 0xff)} // #nosec G115 -- explicit low-byte mask
	}
}
