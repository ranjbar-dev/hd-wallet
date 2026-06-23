package hdwallet

import "crypto/ed25519"

// Solana off-chain message signing, matching Trust Wallet Core's
// SolanaMessageSigner: the message bytes are signed directly with the account's
// ed25519 key (EdDSA hashes internally; there is no separate digest or domain
// envelope), and the 64-byte signature is returned base58-encoded — the same
// form `solana sign-offchain-message` and TWC report.

// SignSolanaMessage signs message with the ed25519 key derived for symbol at the
// given address index and returns the base58-encoded 64-byte signature.
//
// symbol must be a Solana / ed25519 coin (e.g. SOL). The derived private key is
// wiped immediately after signing and never leaves the package.
func (w *HDWallet) SignSolanaMessage(symbol Symbol, index uint32, message []byte) (string, error) {
	sig, err := w.SignIndex(symbol, index, message)
	if err != nil {
		return "", err
	}
	return base58Encode(base58BTC, sig.Bytes()), nil
}

// VerifySolanaMessage reports whether sigBase58 is a valid Solana off-chain
// message signature for message under the given base58 account address (which is
// itself the 32-byte ed25519 public key).
func VerifySolanaMessage(address string, message []byte, sigBase58 string) bool {
	pub, err := ParseAddress(SOL, address)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base58Decode(base58BTC, sigBase58)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}
