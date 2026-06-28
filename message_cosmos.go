package hdwallet

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// Cosmos ADR-36 arbitrary-message signing.
//
// ADR-36 signs an amino-JSON StdSignDoc whose single message is a MsgSignData:
//
//	{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},
//	 "memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":"<base64(msg)>",
//	 "signer":"<bech32>"}}],"sequence":"0"}
//
// The canonical (sorted-key, no-whitespace) JSON is SHA-256'd and signed with
// the secp256k1 RFC-6979 / low-S signer — the same primitives already used by
// the Cosmos transaction builder (tx_cosmos.go) and the Bitcoin message signer.
// This matches the CosmJS makeADR36AminoSignDoc / serializeSignDoc pipeline
// and the Keplr signArbitrary API.
//
// SignCosmosADR36 returns a base64-encoded 65-byte recoverable R‖S‖V signature
// (V ∈ {0,1}) so VerifyCosmosADR36 can ecrecover the signer's public key and
// check its bech32 address without needing a stored public key.

// cosmosADR36SignBytes builds the canonical amino-JSON bytes for an ADR-36
// sign document. The output is byte-identical to:
//
//	CosmJS: toUtf8(JSON.stringify(sortedObject(makeADR36AminoSignDoc(signer, data))))
//
// Keys are alphabetically sorted at every level. signer is a bech32 address
// (lower-case alphanumeric + "1"): all characters are JSON-safe without
// escaping. Standard base64 output uses [A-Z,a-z,0-9,+,/,=]: all JSON-safe.
func cosmosADR36SignBytes(signer string, data []byte) []byte {
	dataB64 := base64.StdEncoding.EncodeToString(data)
	return []byte(
		`{"account_number":"0","chain_id":"","fee":{"amount":[],"gas":"0"},"memo":"","msgs":[{"type":"sign/MsgSignData","value":{"data":"` +
			dataB64 + `","signer":"` + signer + `"}}],"sequence":"0"}`,
	)
}

// SignCosmosADR36 signs data with the key for symbol at the given address index
// using the Cosmos ADR-36 arbitrary-message signing standard. signer must be
// the bech32 address corresponding to that key (e.g. obtained via
// w.AddressIndex(symbol, index) or w.Address(symbol) for index 0).
//
// It returns a base64-encoded 65-byte recoverable secp256k1 signature (R‖S‖V,
// V ∈ {0,1}) over sha256(amino_json). symbol must be a secp256k1 coin
// (e.g. ATOM, OSMO); other curves return ErrNotRecoverable. The derived
// private key is wiped immediately after signing and never leaves the package.
func (w *HDWallet) SignCosmosADR36(symbol Symbol, index uint32, signer string, data []byte) (string, error) {
	// Reject a signer that is not a well-formed bech32 address before embedding it
	// in the amino-JSON sign document. The bech32 charset (lower-case alphanumeric
	// plus the "1" separator) contains no JSON metacharacters, so a successful
	// decode guarantees signer cannot break out of or inject into the document.
	if hrp, _, err := bech32.Decode(signer); err != nil || hrp == "" {
		return "", fmt.Errorf("hdwallet: SignCosmosADR36 %s: signer must be a valid bech32 address", symbol)
	}
	signBytes := cosmosADR36SignBytes(signer, data)
	h := sha256.Sum256(signBytes)
	sig, err := w.SignIndex(symbol, index, h[:])
	if err != nil {
		return "", fmt.Errorf("hdwallet: SignCosmosADR36 %s: %w", symbol, err)
	}
	rec := sig.Recoverable() // 65-byte R‖S‖V, V ∈ {0,1}
	if rec == nil {
		return "", fmt.Errorf("%w: %s", ErrNotRecoverable, symbol)
	}
	return base64.StdEncoding.EncodeToString(rec), nil
}

// VerifyCosmosADR36 reports whether sigBase64 is a valid ADR-36 signature of
// data by the key behind the bech32 signer address. sigBase64 must be a
// base64-encoded 65-byte R‖S‖V signature (V ∈ {0,1}) as returned by
// SignCosmosADR36. It recovers the public key from the signature and checks
// that its bech32 Cosmos address (same HRP as signer) equals signer.
func VerifyCosmosADR36(signer string, data []byte, sigBase64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigBase64))
	if err != nil || len(sig) != 65 {
		return false
	}
	v := sig[64]
	if v > 1 {
		return false
	}
	// Decode the provided bech32 signer to extract HRP and 20-byte payload.
	hrp, addrData, err := bech32.Decode(signer)
	if err != nil || hrp == "" {
		return false
	}
	wantPayload, err := bech32.ConvertBits(addrData, 5, 8, false)
	if err != nil || len(wantPayload) != 20 {
		return false
	}
	// SHA-256 of the amino-JSON sign bytes.
	signBytes := cosmosADR36SignBytes(signer, data)
	h := sha256.Sum256(signBytes)
	// Recover the secp256k1 public key from the recoverable signature.
	// btcec RecoverCompact expects [27+recid] || R || S.
	compact := make([]byte, 65)
	compact[0] = 27 + v
	copy(compact[1:], sig[:64])
	pub, _, err := btcecdsa.RecoverCompact(compact, h[:])
	if err != nil {
		return false
	}
	// Cosmos address: bech32(hrp, hash160(compressed_pub)).
	gotPayload := hash160(pub.SerializeCompressed())
	return bytesEqual(wantPayload, gotPayload)
}
