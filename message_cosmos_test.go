package hdwallet

import "testing"

// Roadmap — Cosmos ADR-36 arbitrary-message signing.
//
// ADR-36 signs an amino-JSON StdSignDoc whose single message is
//
//	{"type":"sign/MsgSignData","value":{"signer":<bech32>,"data":<base64(msg)>}}
//
// with chain_id "", account_number "0", sequence "0", an empty fee and memo;
// the canonical (sorted-key, no-whitespace) JSON is SHA-256'd and signed with the
// secp256k1 RFC-6979 / low-S signer, the same primitives already used by the
// Cosmos transaction builder (tx_cosmos.go) and the Bitcoin message signer.
//
// It is intentionally NOT shipped yet: this is a fund-/identity-critical signing
// path, and Trust Wallet Core publishes no ADR-36 AnySigner/MessageSigner vector
// to reproduce byte-for-byte (its Cosmos tests cover transactions only). Per the
// project rule, a signing scheme ships only once it reproduces an authoritative
// external vector — so this records the gap instead of guessing the exact
// amino-JSON serialization (key ordering, escaping, empty-field handling), any of
// which would silently change the signed bytes.
//
// To finish: wire SignCosmosADR36(symbol, index, signer, data) (string sig) using
// cosmosCanonicalJSON + the secp256k1 signer, then pin a vector sourced from a
// reference implementation (CosmJS makeADR36AminoSignDoc / Keplr signArbitrary).
func TestSignCosmosADR36(t *testing.T) {
	t.Skip("roadmap: no authoritative ADR-36 vector wired yet; see the package note above")
}
