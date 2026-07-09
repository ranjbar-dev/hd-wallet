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

// ---------- Algorand: base32(pubkey || SHA512/256(pubkey)[-4:]) ----------

func encodeALGO(pub []byte) (string, error) {
	checksum := sha512Sum256(pub)
	data := make([]byte, 0, 32+4)
	data = append(data, pub...)
	data = append(data, checksum[len(checksum)-4:]...)
	return base32NoPad.EncodeToString(data), nil
}

// ---------- Polkadot: SS58 base58(prefix || pubkey || blake2b-512[:2]) ----------

// ss58Encoder builds an SS58 address encoder for the given network prefix
// (0 = Polkadot). The checksum is the first two bytes of
// BLAKE2b-512("SS58PRE" || prefix || pubkey).
func ss58Encoder(prefix byte) func([]byte) (string, error) {
	return func(pub []byte) (string, error) {
		data := make([]byte, 0, 1+32+2)
		data = append(data, prefix)
		data = append(data, pub...)
		checksum := blake2bPersonal(64, nil, append([]byte("SS58PRE"), data...))
		data = append(data, checksum[0], checksum[1])
		return base58Encode(base58BTC, data), nil
	}
}

// ---------- Aptos: 0x || hex(SHA3-256(pubkey || scheme 0x00)) ----------

func encodeAPTOS(pub []byte) (string, error) {
	data := make([]byte, 0, 32+1)
	data = append(data, pub...)
	data = append(data, 0x00) // single-signer ed25519 scheme
	return "0x" + hex.EncodeToString(sha3Sum256(data)), nil
}
