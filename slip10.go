package hdwallet

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
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
			return nil, errors.New("ed25519 derivation requires hardened path elements")
		}
		data := make([]byte, 1+32+4)
		data[0] = 0x00
		copy(data[1:33], node.key)
		binary.BigEndian.PutUint32(data[33:], idx)
		i = hmacSHA512(node.chain, data)
		node = &slipNode{key: i[:32], chain: i[32:]}
	}
	return node, nil
}

// deriveNist256p1 implements SLIP-0010 derivation over the NIST P-256 curve.
// It supports both hardened and non-hardened elements (NEO uses m/44'/888'/0'/0/0).
func deriveNist256p1(seed []byte, path []uint32) (*slipNode, error) {
	n := elliptic.P256().Params().N

	i := hmacSHA512([]byte("Nist256p1 seed"), seed)
	for {
		il := new(big.Int).SetBytes(i[:32])
		if il.Sign() != 0 && il.Cmp(n) < 0 {
			break
		}
		i = hmacSHA512([]byte("Nist256p1 seed"), i) // invalid master key: retry with I as data
	}
	node := &slipNode{key: i[:32], chain: i[32:]}

	for _, idx := range path {
		var data []byte
		if idx >= hardenedOffset {
			data = make([]byte, 1+32+4)
			data[0] = 0x00
			copy(data[1:33], node.key)
			binary.BigEndian.PutUint32(data[33:], idx)
		} else {
			pub := compressP256(node.key)
			data = make([]byte, len(pub)+4)
			copy(data, pub)
			binary.BigEndian.PutUint32(data[len(pub):], idx)
		}

		for {
			i = hmacSHA512(node.chain, data)
			il := new(big.Int).SetBytes(i[:32])
			ki := new(big.Int).Add(il, new(big.Int).SetBytes(node.key))
			ki.Mod(ki, n)
			if il.Cmp(n) < 0 && ki.Sign() != 0 {
				node = &slipNode{key: leftPad(ki.Bytes(), 32), chain: i[32:]}
				break
			}
			// Invalid child: retry with Data = 0x01 || IR || ser32(i), key unchanged.
			retry := make([]byte, 1+32+4)
			retry[0] = 0x01
			copy(retry[1:33], i[32:])
			copy(retry[33:], data[len(data)-4:])
			data = retry
		}
	}
	return node, nil
}

// compressP256 returns the SEC1 compressed public key for a P-256 private key.
func compressP256(priv []byte) []byte {
	//nolint:staticcheck // ScalarBaseMult is the simplest correct API for SLIP-0010
	x, y := elliptic.P256().ScalarBaseMult(priv)
	out := make([]byte, 33)
	if y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	xb := x.Bytes()
	copy(out[33-len(xb):], xb)
	return out
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
