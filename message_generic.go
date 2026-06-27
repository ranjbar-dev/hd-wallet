package hdwallet

import "fmt"

// SignRawMessage is the chain-neutral signing primitive. It routes to the
// correct curve for the given symbol and returns the raw Signature.
//
// For ECDSA chains (secp256k1, nist256p1, starkex — e.g. ETH, BTC, NEO,
// ATOM) message must be the 32-byte digest the caller has pre-hashed with
// the chain's own hash function (keccak256 for Ethereum/Tron, double-SHA256
// for Bitcoin, SHA-256 for Cosmos, …). A non-32-byte input returns a wrapped
// ErrInvalidDigest.
//
// For ed25519 chains (SOL, XLM, DOT, …) message is the raw payload; the
// EdDSA scheme hashes internally, so any length is accepted.
//
// This is the low-level primitive. For chain-specific standards with magic
// envelope prefixes use SignBitcoinMessage, SignSolanaMessage,
// SignCosmosADR36, or SignTronMessage instead. The derived private key is
// wiped immediately after signing and never leaves the package.
func (w *HDWallet) SignRawMessage(symbol Symbol, index uint32, message []byte) (*Signature, error) {
	sig, err := w.SignIndex(symbol, index, message)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: SignRawMessage: %w", err)
	}
	return sig, nil
}

// VerifyRawMessage reports whether sig is a valid raw signature of message
// by the public key pub for the coin symbol. It is the Symbol-keyed
// counterpart to SignRawMessage and wraps VerifySignature.
//
// As with SignRawMessage, message is the 32-byte digest for ECDSA chains and
// the raw message for ed25519 chains. An unknown symbol returns a wrapped
// ErrUnsupportedCoin; a non-32-byte input for an ECDSA chain returns a
// wrapped ErrInvalidDigest. It needs no secret and is a free function.
func VerifyRawMessage(symbol Symbol, pub, message []byte, sig *Signature) (bool, error) {
	return VerifySignature(symbol, pub, message, sig)
}
