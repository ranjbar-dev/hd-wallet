package hdwallet

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Bitcoin "signmessage" support (the Bitcoin Core / Electrum standard, matching
// Trust Wallet Core's BitcoinMessageSigner). The message is committed under the
// magic envelope
//
//	varInt(len(magic)) || "Bitcoin Signed Message:\n" || varInt(len(msg)) || msg
//
// double-SHA256'd, then signed with the secp256k1 RFC-6979 / low-S recoverable
// signer. The result is the 65-byte compact signature [header || R || S], where
// header = 27 + recoveryID + (4 if the public key is compressed), base64-encoded.

// bitcoinMsgMagic is the fixed Bitcoin signed-message prefix string.
const bitcoinMsgMagic = "Bitcoin Signed Message:\n"

// ErrNotRecoverable is returned by SignBitcoinMessage when the coin's curve is
// not secp256k1 (only secp256k1 produces a recoverable signature).
var ErrNotRecoverable = errors.New("hdwallet: coin curve does not support recoverable signatures")

// bitcoinMessageDigest returns the double-SHA256 digest Bitcoin signs for a
// message.
func bitcoinMessageDigest(message []byte) []byte {
	buf := make([]byte, 0, 1+len(bitcoinMsgMagic)+9+len(message))
	buf = append(buf, bitcoinVarInt(uint64(len(bitcoinMsgMagic)))...)
	buf = append(buf, bitcoinMsgMagic...)
	buf = append(buf, bitcoinVarInt(uint64(len(message)))...)
	buf = append(buf, message...)
	return sha256d(buf)
}

// bitcoinVarInt encodes a Bitcoin CompactSize unsigned integer.
func bitcoinVarInt(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)} // #nosec G115 -- n < 0xfd by the case guard
	case n <= 0xffff:
		b := make([]byte, 3)
		b[0] = 0xfd
		binary.LittleEndian.PutUint16(b[1:], uint16(n)) // #nosec G115 -- n <= 0xffff
		return b
	case n <= 0xffffffff:
		b := make([]byte, 5)
		b[0] = 0xfe
		binary.LittleEndian.PutUint32(b[1:], uint32(n)) // #nosec G115 -- n <= 0xffffffff
		return b
	default:
		b := make([]byte, 9)
		b[0] = 0xff
		binary.LittleEndian.PutUint64(b[1:], n)
		return b
	}
}

// SignBitcoinMessage signs message under the Bitcoin signed-message standard with
// the key derived for symbol at the given address index, returning the base64
// compact signature. symbol must be a secp256k1 coin (e.g. BTC, LTC); the derived
// private key is wiped immediately after signing and never leaves the package.
//
// The signature commits only to the message and key, so it is independent of the
// address format; this library derives compressed keys, so the header byte marks
// the key compressed (verifiers recover the compressed key / its legacy address).
func (w *HDWallet) SignBitcoinMessage(symbol Symbol, index uint32, message []byte) (string, error) {
	digest := bitcoinMessageDigest(message)
	sig, err := w.SignIndex(symbol, index, digest)
	if err != nil {
		return "", err
	}
	rec := sig.Recoverable() // 65 bytes R||S||V, V in {0,1}
	if rec == nil {
		return "", fmt.Errorf("%w: %s", ErrNotRecoverable, symbol)
	}
	out := make([]byte, 65)
	out[0] = 27 + rec[64] + 4 // compressed key
	copy(out[1:], rec[:64])
	return base64.StdEncoding.EncodeToString(out), nil
}

// VerifyBitcoinMessage reports whether sigBase64 is a valid Bitcoin signed-message
// signature of message by the key behind a legacy P2PKH (base58check, "1"-prefix)
// address. It recovers the public key from the compact signature and checks its
// legacy address equals address.
func VerifyBitcoinMessage(address string, message []byte, sigBase64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigBase64))
	if err != nil || len(sig) != 65 {
		return false
	}
	digest := bitcoinMessageDigest(message)
	pub, compressed, err := btcecdsa.RecoverCompact(sig, digest)
	if err != nil {
		return false
	}
	pubBytes := pub.SerializeUncompressed()
	if compressed {
		pubBytes = pub.SerializeCompressed()
	}
	// Legacy mainnet P2PKH address (version byte 0x00) of the recovered key.
	want := base58CheckEncode(base58BTC, []byte{0x00}, hash160(pubBytes))
	return want == strings.TrimSpace(address)
}
