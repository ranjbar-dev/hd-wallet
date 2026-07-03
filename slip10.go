package hdwallet

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
)

// hardenedOffset is the BIP-32 hardened key boundary (2^31). It matches
// hdkeychain.HardenedKeyStart, so the same index space is used across curves.
const hardenedOffset uint32 = 0x80000000

// slipNode is a SLIP-0010 derived node: a 32-byte private key + 32-byte chain code.
type slipNode struct {
	key   []byte
	chain []byte
}

func hmacSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// deriveEd25519 implements SLIP-0010 derivation over the ed25519 curve. Per the
// spec, ed25519 supports hardened derivation only; non-hardened elements are an
// error. Every chain Trust Wallet uses for ed25519 is fully hardened.
func deriveEd25519(seed []byte, path []uint32) (*slipNode, error) {
	i := hmacSHA512([]byte("ed25519 seed"), seed)
	node := &slipNode{key: i[:32], chain: i[32:]}
	for _, idx := range path {
		if idx < hardenedOffset {
			wipe(i) // discard the unreturned node before erroring out
			return nil, errors.New("ed25519 derivation requires hardened path elements")
		}
		data := make([]byte, 1+32+4)
		data[0] = 0x00
		copy(data[1:33], node.key)
		binary.BigEndian.PutUint32(data[33:], idx)
		next := hmacSHA512(node.chain, data)
		wipe(data) // copy of the parent key; no longer needed
		wipe(i)    // parent node (key+chain) superseded by next; wipe before reuse
		i = next
		node = &slipNode{key: i[:32], chain: i[32:]}
	}
	return node, nil
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
