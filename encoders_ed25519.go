package hdwallet

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// All ed25519 encoders receive the raw 32-byte public key.

// ---------- MultiversX (Elrond): bech32("erd", pubkey) ----------

// encodeEGLD bech32-encodes the raw 32-byte ed25519 public key under the "erd"
// HRP (no hashing), matching Trust Wallet Core's MultiversX address.
func encodeEGLD(pub []byte) (string, error) {
	conv, err := bech32.ConvertBits(pub, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode("erd", conv)
}

// ---------- Hedera: "0.0." || hex(DER ed25519 SPKI prefix || pubkey) ----------

// hederaDERPrefix is the fixed 12-byte DER/SPKI prefix for an Ed25519 public key
// (AlgorithmIdentifier 1.3.101.112 + BIT STRING header).
var hederaDERPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

func encodeHBAR(pub []byte) (string, error) {
	data := make([]byte, 0, len(hederaDERPrefix)+len(pub))
	data = append(data, hederaDERPrefix...)
	data = append(data, pub...)
	return "0.0." + hex.EncodeToString(data), nil
}

// ---------- Oasis: bech32("oasis", 0x00 || SHA512/256(ctx || pubkey)[:20]) ----------

// oasisStakingContext is the address-derivation context for Oasis staking
// accounts (the bytes hashed together with a 0x00 version byte and the pubkey).
var oasisStakingContext = append([]byte("oasis-core/address: staking"), 0x00)

func encodeOasis(pub []byte) (string, error) {
	h := sha512Sum256(append(append([]byte{}, oasisStakingContext...), pub...))
	data := make([]byte, 0, 1+20)
	data = append(data, 0x00) // address version
	data = append(data, h[:20]...)
	conv, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode("oasis", conv)
}

// ---------- Aeternity: "ak_" || base58(pubkey || sha256d(pubkey)[:4]) ----------

func encodeAE(pub []byte) (string, error) {
	body := make([]byte, 0, 32+4)
	body = append(body, pub...)
	body = append(body, sha256d(pub)[:4]...)
	return "ak_" + base58Encode(base58BTC, body), nil
}

// ---------- validators for the additional ed25519 chains ----------

// egldValidator validates a MultiversX address: bech32("erd", 32-byte pubkey).
func egldValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		hrp, data, err := bech32.Decode(addr)
		if err != nil {
			return nil, addrErr(symbol, "bech32 decode failed: "+err.Error())
		}
		if hrp != "erd" {
			return nil, addrErr(symbol, "wrong prefix (want erd)")
		}
		payload, err := bech32.ConvertBits(data, 5, 8, false)
		if err != nil {
			return nil, addrErr(symbol, "invalid payload: "+err.Error())
		}
		if len(payload) != 32 {
			return nil, addrErr(symbol, "payload length not 32")
		}
		return payload, nil
	}
}

// oasisValidator validates an Oasis address: bech32("oasis", version || 20-byte
// truncated context hash). Returns the 20-byte account hash.
func oasisValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		hrp, data, err := bech32.Decode(addr)
		if err != nil {
			return nil, addrErr(symbol, "bech32 decode failed: "+err.Error())
		}
		if hrp != "oasis" {
			return nil, addrErr(symbol, "wrong prefix (want oasis)")
		}
		payload, err := bech32.ConvertBits(data, 5, 8, false)
		if err != nil {
			return nil, addrErr(symbol, "invalid payload: "+err.Error())
		}
		if len(payload) != 21 || payload[0] != 0x00 {
			return nil, addrErr(symbol, "bad version/length")
		}
		return payload[1:], nil
	}
}

// hbarValidator validates a Hedera address: "0.0." followed by the hex of the
// DER ed25519 SPKI prefix and a 32-byte public key.
func hbarValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		const p = "0.0."
		if len(addr) <= len(p) || addr[:len(p)] != p {
			return nil, addrErr(symbol, "must start with 0.0.")
		}
		raw, err := hex.DecodeString(addr[len(p):])
		if err != nil {
			return nil, addrErr(symbol, "invalid hex")
		}
		if len(raw) != len(hederaDERPrefix)+32 {
			return nil, addrErr(symbol, "wrong length")
		}
		for i := range hederaDERPrefix {
			if raw[i] != hederaDERPrefix[i] {
				return nil, addrErr(symbol, "bad DER prefix")
			}
		}
		return raw[len(hederaDERPrefix):], nil
	}
}

// aeValidator validates an Aeternity address: "ak_" + base58(pubkey ||
// sha256d(pubkey)[:4]). Returns the 32-byte public key.
func aeValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		const p = "ak_"
		if len(addr) <= len(p) || addr[:len(p)] != p {
			return nil, addrErr(symbol, "must start with ak_")
		}
		raw, err := base58Decode(base58BTC, addr[len(p):])
		if err != nil {
			return nil, addrErr(symbol, err.Error())
		}
		if len(raw) != 32+4 {
			return nil, addrErr(symbol, "wrong length")
		}
		pub := raw[:32]
		if !bytesEqual(raw[32:], sha256d(pub)[:4]) {
			return nil, addrErr(symbol, "bad checksum")
		}
		return pub, nil
	}
}

// ---------- Solana: raw base58 (Bitcoin alphabet, no checksum) ----------

func encodeSOL(pub []byte) (string, error) {
	return base58.Encode(pub), nil
}

// ---------- NEAR: lowercase hex implicit account ----------

func encodeNEAR(pub []byte) (string, error) {
	return hex.EncodeToString(pub), nil
}

// ---------- Stellar: strkey (version 'G', CRC16-XMODEM, base32) ----------

func encodeXLM(pub []byte) (string, error) {
	const versionAccountID = 6 << 3 // 0x30 -> addresses start with 'G'
	payload := make([]byte, 0, 1+32+2)
	payload = append(payload, byte(versionAccountID))
	payload = append(payload, pub...)
	var crc [2]byte
	binary.LittleEndian.PutUint16(crc[:], crc16XModem(payload))
	payload = append(payload, crc[:]...)
	return base32NoPad.EncodeToString(payload), nil
}

// ---------- Polkadot / Kusama: SS58 (BLAKE2b checksum, base58) ----------

func ss58Encoder(prefix byte) func([]byte) (string, error) {
	return func(pub []byte) (string, error) {
		data := make([]byte, 0, 1+32+2)
		data = append(data, prefix)
		data = append(data, pub...)
		checksum := blake2b512(append([]byte("SS58PRE"), data...))
		data = append(data, checksum[0], checksum[1])
		return base58Encode(base58BTC, data), nil
	}
}

// ---------- Algorand: base32(pubkey || SHA512/256(pubkey)[-4:]) ----------

func encodeALGO(pub []byte) (string, error) {
	checksum := sha512Sum256(pub)
	data := make([]byte, 0, 32+4)
	data = append(data, pub...)
	data = append(data, checksum[len(checksum)-4:]...)
	return base32NoPad.EncodeToString(data), nil
}

// ---------- Sui: 0x || hex(BLAKE2b-256(flag 0x00 || pubkey)) ----------

func encodeSUI(pub []byte) (string, error) {
	data := make([]byte, 0, 1+32)
	data = append(data, 0x00) // ed25519 signature scheme flag
	data = append(data, pub...)
	return "0x" + hex.EncodeToString(blake2b256(data)), nil
}

// ---------- Aptos: 0x || hex(SHA3-256(pubkey || scheme 0x00)) ----------

func encodeAPTOS(pub []byte) (string, error) {
	data := make([]byte, 0, 32+1)
	data = append(data, pub...)
	data = append(data, 0x00) // single-signer ed25519 scheme
	return "0x" + hex.EncodeToString(sha3Sum256(data)), nil
}

// ---------- Tezos: tz1 (BLAKE2b-160 key hash, base58check, 3-byte prefix) ----------

func encodeXTZ(pub []byte) (string, error) {
	prefix := []byte{0x06, 0xa1, 0x9f} // "tz1"
	return base58CheckEncode(base58BTC, prefix, blake2b160(pub)), nil
}
