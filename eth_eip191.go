package hdwallet

import "strconv"

// EIP-191 "personal_sign" message hashing.
//
// EIP-191 version 0x45 ('E') prefixes a message with
//
//	"\x19Ethereum Signed Message:\n" + len(message) + message
//
// and hashes the whole thing with keccak256. The leading 0x19 byte makes the
// preimage impossible to confuse with an RLP-encoded transaction (which never
// starts with 0x19), so a wallet signature over a human-readable message can
// never be replayed as a transaction signature.

// eip191Prefix is the fixed "\x19Ethereum Signed Message:\n" preamble (the 0x19
// byte is included).
const eip191Prefix = "\x19Ethereum Signed Message:\n"

// EthereumPersonalMessageHash returns the 32-byte keccak256 digest that EIP-191
// personal_sign signs for the given message. len(message) is rendered as its
// decimal ASCII representation, per the standard.
func EthereumPersonalMessageHash(message []byte) []byte {
	preimage := make([]byte, 0, len(eip191Prefix)+20+len(message))
	preimage = append(preimage, eip191Prefix...)
	preimage = append(preimage, strconv.Itoa(len(message))...)
	preimage = append(preimage, message...)
	return keccak256(preimage)
}
