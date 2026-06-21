package hdwallet

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil/base58"
)

// All ed25519 encoders receive the raw 32-byte public key.

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
