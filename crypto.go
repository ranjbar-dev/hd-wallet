package hdwallet

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/blake2b"

	// RIPEMD-160 is consensus-mandated for Bitcoin/Cosmos address hashing
	// (hash160); its use here is required for correctness, not a security choice.
	"golang.org/x/crypto/ripemd160" // #nosec G507 -- consensus-mandated for Bitcoin/Cosmos hash160 //nolint:staticcheck
	"golang.org/x/crypto/sha3"
)

// hash160 = RIPEMD160(SHA256(b)). Used by Bitcoin-style chains and Cosmos.
func hash160(b []byte) []byte {
	s := sha256.Sum256(b)
	r := ripemd160.New() // #nosec G406 -- RIPEMD-160 required for Bitcoin/Cosmos hash160
	r.Write(s[:])
	return r.Sum(nil)
}

// ripemd160Sum is a plain RIPEMD-160 (no SHA-256 pre-hash), used for the EOS /
// FIO / WAX public-key string checksum (base58 of pubkey || ripemd160(pubkey)[:4]).
func ripemd160Sum(b []byte) []byte {
	r := ripemd160.New() // #nosec G406 -- RIPEMD-160 required for EOS-family key checksum
	r.Write(b)
	return r.Sum(nil)
}

// keccak256 is original Keccak (NOT finalized SHA-3) as used by Ethereum/Tron.
func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

// sha256d is double SHA-256, the checksum used by base58check chains.
func sha256d(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// sha512Sum256 is SHA-512/256, used for the Algorand address checksum.
func sha512Sum256(b []byte) []byte {
	h := sha512.Sum512_256(b)
	return h[:]
}

// sha3Sum256 is finalized SHA3-256 (not Keccak), used for Aptos addresses.
func sha3Sum256(b []byte) []byte {
	h := sha3.Sum256(b) //nolint:govet // govet's inline suggestion; the value form is clearest here
	return h[:]
}

// blake2b256 is BLAKE2b-256, used for Sui addresses.
func blake2b256(b []byte) []byte {
	h := blake2b.Sum256(b)
	return h[:]
}

// blake2b512 is BLAKE2b-512, used for the SS58 (Polkadot/Kusama) checksum.
func blake2b512(b []byte) []byte {
	h := blake2b.Sum512(b)
	return h[:]
}

// blake2b160 is BLAKE2b-160 (20-byte digest), used for Tezos tz1 key hashes.
func blake2b160(b []byte) []byte {
	h, err := blake2b.New(20, nil)
	if err != nil {
		// Only fails on invalid size; 20 is always valid.
		panic("hdwallet: blake2b-160 init failed: " + err.Error())
	}
	h.Write(b)
	return h.Sum(nil)
}

// wipe overwrites a byte slice with zeros. Used for ephemeral key material;
// long-lived secrets are protected by memguard (see secret.go). It delegates to
// memguard.WipeBytes, whose zeroing the compiler is not free to elide.
func wipe(b []byte) {
	memguard.WipeBytes(b)
}
