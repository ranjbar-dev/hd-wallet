package hdwallet

import (
	"encoding/hex"
	"fmt"
	"strings"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/base58"
)

// Tron TIP-191 arbitrary-message signing.
//
// The signing scheme matches Trust Wallet Core's TronMessageSigner and the
// trx.signMessageV2 API in TronWeb (v6+):
//
//  1. msgHash    = keccak256(message)
//  2. signDigest = keccak256("\x19TRON Signed Message:\n32" || msgHash)
//  3. Sign signDigest with secp256k1 RFC-6979 / low-S recoverable signer.
//
// The prefix "\x19TRON Signed Message:\n32" is constant because keccak256
// always produces a 32-byte output; "32" is the decimal byte-length of the
// inner hash, making the envelope self-describing.
//
// SignTronMessage returns a 65-byte hex string "0x{R‖S‖V}" where V ∈ {27, 28}
// (V = 27 + recoveryID), matching the TronWeb output format. VerifyTronMessage
// recovers the signer's public key via ecrecover and derives its Tron address
// (base58check, version byte 0x41) to compare against the provided address.
//
// Reference: Trust Wallet Core TronMessageSigner.cpp:signMessage / verifyMessage.
// Algorithm is pinned to the TWC wire format; see message_tron_test.go for the
// vector.

const tronMsgPrefix = "\x19TRON Signed Message:\n32"

// tronMessageDigest builds the 32-byte sign digest for a Tron TIP-191 message.
// The inner keccak256 reduces the message to a 32-byte hash; the outer keccak256
// wraps it in the Tron signed-message envelope.
func tronMessageDigest(message []byte) []byte {
	msgHash := keccak256(message)
	envelope := append([]byte(tronMsgPrefix), msgHash...)
	return keccak256(envelope)
}

// SignTronMessage signs message under the Tron TIP-191 standard with the key
// derived for chain at the given address index.
//
// chain must be a secp256k1 coin (e.g. TRX); other curves return
// ErrNotRecoverable. The derived private key is wiped immediately after signing
// and never leaves the package.
//
// The returned signature is a hex-encoded 65-byte string "0x{R‖S‖V}" where
// V ∈ {27, 28}, matching the format TronWeb trx.signMessageV2 produces.
func (w *HDWallet) SignTronMessage(chain Chain, index uint32, message []byte) (string, error) {
	digest := tronMessageDigest(message)
	sig, err := w.SignIndex(chain, index, digest)
	if err != nil {
		return "", fmt.Errorf("hdwallet: SignTronMessage %s: %w", chain, err)
	}
	rec := sig.Recoverable() // 65-byte R‖S‖V, V ∈ {0,1}
	if rec == nil {
		return "", fmt.Errorf("%w: %s", ErrNotRecoverable, chain)
	}
	// Tron / TronWeb convention: V = 27 + recoveryID.
	out := make([]byte, 65)
	copy(out[:64], rec[:64])
	out[64] = rec[64] + 27
	return "0x" + hex.EncodeToString(out), nil
}

// VerifyTronMessage reports whether sigHex is a valid Tron TIP-191 signature
// of message by the key behind tronAddr. sigHex is the hex-encoded 65-byte
// signature (with or without the "0x" prefix) where the last byte V ∈ {27, 28}.
//
// It recovers the secp256k1 public key from the signature and derives the Tron
// address (keccak256(uncompressed[1:])[12:], version 0x41, base58check) to
// compare against tronAddr.
func VerifyTronMessage(tronAddr string, message []byte, sigHex string) bool {
	hexStr := strings.TrimPrefix(strings.TrimSpace(sigHex), "0x")
	sigBytes, err := hex.DecodeString(hexStr)
	if err != nil || len(sigBytes) != 65 {
		return false
	}
	v := sigBytes[64]
	if v < 27 || v > 28 {
		return false
	}
	recid := v - 27 // 0 or 1

	digest := tronMessageDigest(message)

	// btcecdsa.RecoverCompact expects [27 + recid] ‖ R ‖ S.
	compact := make([]byte, 65)
	compact[0] = 27 + recid
	copy(compact[1:], sigBytes[:64])
	pub, _, err := btcecdsa.RecoverCompact(compact, digest)
	if err != nil {
		return false
	}

	// Tron address: base58check(keccak256(uncompressed[1:])[12:], version 0x41).
	// This mirrors the encodeTRX encoder; uncompressed is the 65-byte 0x04‖X‖Y form.
	uncompressed := pub.SerializeUncompressed()
	addrPayload := keccak256(uncompressed[1:])[12:]
	got := base58.CheckEncode(addrPayload, 0x41)
	return got == strings.TrimSpace(tronAddr)
}
