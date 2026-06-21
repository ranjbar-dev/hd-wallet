package hdwallet

import (
	"encoding/base32"
	"math/big"
)

// Base58 alphabets. Most chains use the Bitcoin alphabet; XRP uses its own.
const (
	base58BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	base58XRP = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
)

// base32NoPad is RFC 4648 base32 without padding (Stellar, Algorand).
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// base58Encode encodes input using the supplied 58-character alphabet.
// Leading zero bytes map to the alphabet's first character.
func base58Encode(alphabet string, input []byte) string {
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	num := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	mod := new(big.Int)

	out := make([]byte, 0, len(input)*138/100+1)
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, alphabet[0])
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// base58CheckEncode encodes version||payload with a 4-byte double-SHA256
// checksum appended, using the supplied alphabet. Unlike btcutil's helper this
// supports multi-byte version prefixes (needed for Zcash, Tezos, etc.).
func base58CheckEncode(alphabet string, version, payload []byte) string {
	buf := make([]byte, 0, len(version)+len(payload)+4)
	buf = append(buf, version...)
	buf = append(buf, payload...)
	checksum := sha256d(buf)[:4]
	buf = append(buf, checksum...)
	return base58Encode(alphabet, buf)
}

// crc16XModem computes the CRC-16/XMODEM checksum used by Stellar strkeys.
func crc16XModem(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
