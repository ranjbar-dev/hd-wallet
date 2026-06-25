package hdwallet

// Personalized BLAKE2b.
//
// Zcash's ZIP-243 transparent sighash (tx_zcash.go) keys BLAKE2b with a 16-byte
// personalization string ("ZcashSigHash"||branchId, "ZcashPrevoutHash", …).
// golang.org/x/crypto/blake2b — used elsewhere in this package — does not expose
// the personalization parameter, so this is a small, self-contained BLAKE2b
// (RFC 7693) that does.
//
// Correctness is pinned two ways: the unkeyed, zero-personalization path is
// asserted byte-for-byte against blake2b.Sum256 over many input lengths
// (blake2b_personal_test.go), and the personalized path is pinned end-to-end by
// the authoritative Trust Wallet Core Zcash transaction vector (tx_zcash_test.go)
// — a single wrong bit there changes the signature and fails the test.

import (
	"encoding/binary"
	"math/bits"
)

// blake2bIV is the BLAKE2b initialization vector (the SHA-512 IV).
var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// blake2bSigma is the BLAKE2b message-word permutation schedule (12 rounds).
var blake2bSigma = [12][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

// blake2bCompress applies the BLAKE2b compression function F to state h over one
// 128-byte block, with byte counter t (low word; our messages are far below 2^64
// bytes so the high word is always 0) and the final-block flag.
func blake2bCompress(h *[8]uint64, block []byte, t uint64, final bool) {
	var m [16]uint64
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint64(block[i*8:])
	}

	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], blake2bIV[:])
	v[12] ^= t
	if final {
		v[14] ^= 0xffffffffffffffff
	}

	g := func(a, b, c, d int, x, y uint64) {
		v[a] = v[a] + v[b] + x
		v[d] = bits.RotateLeft64(v[d]^v[a], -32)
		v[c] = v[c] + v[d]
		v[b] = bits.RotateLeft64(v[b]^v[c], -24)
		v[a] = v[a] + v[b] + y
		v[d] = bits.RotateLeft64(v[d]^v[a], -16)
		v[c] = v[c] + v[d]
		v[b] = bits.RotateLeft64(v[b]^v[c], -63)
	}

	for r := 0; r < 12; r++ {
		s := &blake2bSigma[r]
		g(0, 4, 8, 12, m[s[0]], m[s[1]])
		g(1, 5, 9, 13, m[s[2]], m[s[3]])
		g(2, 6, 10, 14, m[s[4]], m[s[5]])
		g(3, 7, 11, 15, m[s[6]], m[s[7]])
		g(0, 5, 10, 15, m[s[8]], m[s[9]])
		g(1, 6, 11, 12, m[s[10]], m[s[11]])
		g(2, 7, 8, 13, m[s[12]], m[s[13]])
		g(3, 4, 9, 14, m[s[14]], m[s[15]])
	}

	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}

// blake2bPersonal computes a BLAKE2b digest of `size` bytes (1..64) over data,
// using the given personalization (right-padded with zeros to 16 bytes; longer
// values are truncated). No key or salt is used.
func blake2bPersonal(size int, person, data []byte) []byte {
	var person16 [16]byte
	copy(person16[:], person)

	var h [8]uint64
	copy(h[:], blake2bIV[:])
	// Parameter-block word 0: digest_length(1) | key_length(0)<<8 | fanout(1)<<16
	// | depth(1)<<24, leaf_length 0 (sequential, unkeyed).
	h[0] ^= 0x01010000 | uint64(size) // #nosec G115 -- size is 1..64
	// Personalization fills parameter-block bytes 48..63 → words 6 and 7.
	h[6] ^= binary.LittleEndian.Uint64(person16[0:8])
	h[7] ^= binary.LittleEndian.Uint64(person16[8:16])

	var block [128]byte
	var t uint64
	for len(data) > 128 {
		copy(block[:], data[:128])
		t += 128
		blake2bCompress(&h, block[:], t, false)
		data = data[128:]
	}
	// Final block: zero-padded to 128 bytes, counter = total message length.
	for i := range block {
		block[i] = 0
	}
	copy(block[:], data)
	t += uint64(len(data))
	blake2bCompress(&h, block[:], t, true)

	out := make([]byte, 64)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], h[i])
	}
	return out[:size]
}
