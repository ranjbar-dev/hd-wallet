package hdwallet

import (
	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

// sr25519 (schnorrkel over ristretto255) is the native key scheme for
// Polkadot/Kusama. The leaf 32-byte key (from SLIP-0010 ed25519 derivation) is
// treated as a MiniSecretKey and expanded via ExpandEd25519 — the same path
// substrate uses for a seed-derived account key. Signatures are produced over a
// merlin transcript with the "substrate" signing context, matching the substrate
// runtime. Signing is randomised (a fresh nonce per call), so it is verified by
// round-trip (sign then verify) rather than against a fixed signature vector.

// substrateSigningContext is the context label substrate uses for sr25519
// account signatures.
var substrateSigningContext = []byte("substrate")

// sr25519MiniSecret builds the expanded schnorrkel secret key from a 32-byte
// leaf private key.
func sr25519MiniSecret(priv []byte) (*schnorrkel.SecretKey, error) {
	if len(priv) != 32 {
		return nil, errInvalidKeyLen("sr25519", len(priv), 32)
	}
	var raw [32]byte
	copy(raw[:], priv)
	defer func() { wipe(raw[:]) }()
	mini, err := schnorrkel.NewMiniSecretKeyFromRaw(raw)
	if err != nil {
		return nil, err
	}
	return mini.ExpandEd25519(), nil
}

// sr25519PublicKey returns the 32-byte sr25519 (ristretto255) public key.
func sr25519PublicKey(priv []byte) ([]byte, error) {
	sk, err := sr25519MiniSecret(priv)
	if err != nil {
		return nil, err
	}
	pub, err := sk.Public()
	if err != nil {
		return nil, err
	}
	enc := pub.Encode()
	return enc[:], nil
}

// signMessageSr25519 signs message with the sr25519 scheme over a "substrate"
// transcript. The 64-byte signature is non-deterministic.
func signMessageSr25519(priv, message []byte) (*Signature, error) {
	sk, err := sr25519MiniSecret(priv)
	if err != nil {
		return nil, err
	}
	t := schnorrkel.NewSigningContext(substrateSigningContext, message)
	sig, err := sk.Sign(t)
	if err != nil {
		return nil, err
	}
	enc := sig.Encode()
	out := make([]byte, 64)
	copy(out, enc[:])
	return &Signature{Curve: Sr25519, raw: out}, nil
}

// verifySr25519 verifies an sr25519 signature over a "substrate" transcript.
func verifySr25519(pub, message, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}
	var pubRaw [32]byte
	copy(pubRaw[:], pub)
	pk, err := schnorrkel.NewPublicKey(pubRaw)
	if err != nil {
		return false
	}
	var sigRaw [64]byte
	copy(sigRaw[:], sig)
	signature := new(schnorrkel.Signature)
	if err := signature.Decode(sigRaw); err != nil {
		return false
	}
	t := schnorrkel.NewSigningContext(substrateSigningContext, message)
	ok, err := pk.Verify(signature, t)
	if err != nil {
		return false
	}
	return ok
}
