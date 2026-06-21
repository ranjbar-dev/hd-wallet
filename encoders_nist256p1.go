package hdwallet

import "github.com/btcsuite/btcd/btcutil/base58"

// encodeNEO builds a legacy NEO address from a 33-byte compressed P-256 key.
//
// The verification script is PUSHBYTES33 <pubkey> CHECKSIG; the script hash is
// hash160(script); the address is base58check of that hash with version 0x17.
func encodeNEO(pub []byte) (string, error) {
	script := make([]byte, 0, 1+33+1)
	script = append(script, 0x21) // PUSHBYTES33
	script = append(script, pub...)
	script = append(script, 0xac) // CHECKSIG
	return base58.CheckEncode(hash160(script), 0x17), nil
}
