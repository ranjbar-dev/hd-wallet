package hdwallet

import (
	"encoding/hex"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// All secp256k1 encoders receive the 33-byte compressed public key.

// ---------- Bitcoin / Litecoin: native SegWit (P2WPKH, bech32) ----------

func encodeBTC(pub []byte) (string, error) { return segwitAddress("bc", pub) }
func encodeLTC(pub []byte) (string, error) { return segwitAddress("ltc", pub) }

// Additional native-SegWit (P2WPKH, bech32) chains. The witness program is the
// standard hash160(pub), so these reuse segwitAddress with a per-chain HRP.
func encodeGRS(pub []byte) (string, error) { return segwitAddress("grs", pub) }
func encodeDGB(pub []byte) (string, error) { return segwitAddress("dgb", pub) }
func encodeBTG(pub []byte) (string, error) { return segwitAddress("btg", pub) }
func encodeSYS(pub []byte) (string, error) { return segwitAddress("sys", pub) }
func encodeVIA(pub []byte) (string, error) { return segwitAddress("via", pub) }

func segwitAddress(hrp string, pubCompressed []byte) (string, error) {
	conv, err := bech32.ConvertBits(hash160(pubCompressed), 8, 5, true)
	if err != nil {
		return "", err
	}
	// Prepend witness version 0.
	return bech32.Encode(hrp, append([]byte{0x00}, conv...))
}

// ---------- Legacy P2PKH (base58check, single version byte) ----------

func encodeDOGE(pub []byte) (string, error) { return base58.CheckEncode(hash160(pub), 0x1e), nil }
func encodeDASH(pub []byte) (string, error) { return base58.CheckEncode(hash160(pub), 0x4c), nil }

// Additional legacy P2PKH (base58check, single version byte) chains.
func encodeQTUM(pub []byte) (string, error) { return base58.CheckEncode(hash160(pub), 0x3a), nil }
func encodeRVN(pub []byte) (string, error)  { return base58.CheckEncode(hash160(pub), 0x3c), nil }
func encodeKMD(pub []byte) (string, error)  { return base58.CheckEncode(hash160(pub), 0x3c), nil }
func encodeFIRO(pub []byte) (string, error) { return base58.CheckEncode(hash160(pub), 0x52), nil }
func encodeMONA(pub []byte) (string, error) { return base58.CheckEncode(hash160(pub), 0x32), nil }
func encodeXVG(pub []byte) (string, error)  { return base58.CheckEncode(hash160(pub), 0x1e), nil }
func encodePIVX(pub []byte) (string, error) { return base58.CheckEncode(hash160(pub), 0x1e), nil }
func encodeNEBL(pub []byte) (string, error) { return base58.CheckEncode(hash160(pub), 0x35), nil }

// Zcash transparent t-addr uses a two-byte version prefix (0x1c, 0xb8).
func encodeZEC(pub []byte) (string, error) {
	return base58CheckEncode(base58BTC, []byte{0x1c, 0xb8}, hash160(pub)), nil
}

// ---------- Ethereum / EVM: keccak256(pubkey)[12:], EIP-55 checksum ----------

func encodeETH(pub []byte) (string, error) {
	pk, err := btcec.ParsePubKey(pub)
	if err != nil {
		return "", err
	}
	// SerializeUncompressed() = 0x04 || X || Y ; drop the 0x04 prefix.
	raw := keccak256(pk.SerializeUncompressed()[1:])[12:]
	return eip55(raw), nil
}

// encodeRonin produces a Ronin address: the EIP-55 Ethereum address with the
// "0x" prefix replaced by "ronin:" (lower-case prefix, mixed-case body).
func encodeRonin(pub []byte) (string, error) {
	addr, err := encodeETH(pub)
	if err != nil {
		return "", err
	}
	return "ronin:" + strings.TrimPrefix(addr, "0x"), nil
}

// roninValidator validates a Ronin address by stripping the "ronin:" prefix,
// restoring the "0x" form, and delegating to the Ethereum validator.
func roninValidator(symbol Symbol) addressValidator {
	eth := ethValidator(symbol)
	return func(addr string) ([]byte, error) {
		if !strings.HasPrefix(addr, "ronin:") {
			return nil, addrErr(symbol, "must start with ronin:")
		}
		return eth("0x" + strings.TrimPrefix(addr, "ronin:"))
	}
}

func eip55(addr []byte) string {
	hexAddr := hex.EncodeToString(addr)
	hash := keccak256([]byte(hexAddr))
	out := []byte("0x")
	for i := 0; i < len(hexAddr); i++ {
		c := hexAddr[i]
		if c >= 'a' && c <= 'f' {
			var nibble byte
			if i%2 == 0 {
				nibble = hash[i/2] >> 4
			} else {
				nibble = hash[i/2] & 0x0f
			}
			if nibble >= 8 {
				c -= 32 // uppercase
			}
		}
		out = append(out, c)
	}
	return string(out)
}

// ---------- Tron: keccak256(pubkey)[12:], prefix 0x41, base58check ----------

func encodeTRX(pub []byte) (string, error) {
	pk, err := btcec.ParsePubKey(pub)
	if err != nil {
		return "", err
	}
	raw := keccak256(pk.SerializeUncompressed()[1:])[12:]
	return base58.CheckEncode(raw, 0x41), nil
}

// ---------- XRP Ledger: hash160 account ID, base58check (XRP alphabet) ----------

func encodeXRP(pub []byte) (string, error) {
	return base58CheckEncode(base58XRP, []byte{0x00}, hash160(pub)), nil
}

// ---------- Cosmos SDK chains: bech32 of hash160, per-chain HRP ----------

func cosmosEncoder(hrp string) func([]byte) (string, error) {
	return func(pub []byte) (string, error) {
		conv, err := bech32.ConvertBits(hash160(pub), 8, 5, true)
		if err != nil {
			return "", err
		}
		return bech32.Encode(hrp, conv)
	}
}

// ---------- Bitcoin Cash: CashAddr (P2KH, 160-bit) ----------

const cashCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func encodeBCH(pub []byte) (string, error) {
	const prefix = "bitcoincash"
	// version byte 0x00 = type P2KH + 160-bit hash size.
	payload := append([]byte{0x00}, hash160(pub)...)
	conv, err := bech32.ConvertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	// conv already holds 5-bit groups (0-31), so it indexes the charset directly.
	combined := append(conv, cashChecksum(prefix, conv)...)

	var sb strings.Builder
	sb.WriteString(prefix)
	sb.WriteByte(':')
	for _, v := range combined {
		sb.WriteByte(cashCharset[v])
	}
	return sb.String(), nil
}

func cashChecksum(prefix string, payload []byte) []byte {
	enc := make([]byte, 0, len(prefix)+1+len(payload)+8)
	for i := 0; i < len(prefix); i++ {
		enc = append(enc, prefix[i]&0x1f)
	}
	enc = append(enc, 0) // separator
	enc = append(enc, payload...)
	enc = append(enc, 0, 0, 0, 0, 0, 0, 0, 0) // checksum template
	mod := cashPolymod(enc)
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte((mod >> uint(5*(7-i))) & 0x1f)
	}
	return out
}

func cashPolymod(v []byte) uint64 {
	c := uint64(1)
	for _, d := range v {
		c0 := byte(c >> 35)
		c = ((c & 0x07ffffffff) << 5) ^ uint64(d)
		if c0&0x01 != 0 {
			c ^= 0x98f2bc8e61
		}
		if c0&0x02 != 0 {
			c ^= 0x79b76d99e2
		}
		if c0&0x04 != 0 {
			c ^= 0xf33e5fb3c4
		}
		if c0&0x08 != 0 {
			c ^= 0xae2eabe2a8
		}
		if c0&0x10 != 0 {
			c ^= 0x1e4f43e470
		}
	}
	return c ^ 1
}
