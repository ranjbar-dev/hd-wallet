package hdwallet

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	txalgo "github.com/ranjbar-dev/hd-wallet/txproto/algorand"
)

// Algorand (ALGO) transaction signing — vector-pinned test.
//
// Source: Trust Wallet Core SignerTests.cpp (Algorand), test "TEST(AlgorandSigner, Sign)".
// https://github.com/trustwallet/wallet-core/blob/master/tests/chains/Algorand/SignerTests.cpp
//
// Wire summary:
//   - Canonical MessagePack (string keys, sorted, skip zero-value fields)
//   - preimage = "TX" || canonical_msgpack(tx_map)
//   - ed25519 signs the full preimage directly (NO SHA-512/256 pre-hash)
//   - Output: canonical_msgpack({"sig": sig64, "txn": tx_map})

// algoTestPrivKey is the ed25519 private key seed for the TWC Algorand test vector.
var algoTestPrivKey, _ = hex.DecodeString("c9d3cc16fecabe2747eab86b81528c6ed8b65efc1d6906d86aabc27187a1fe7c")

// algoTestGenesisHash is the mainnet Algorand genesis hash (base64: wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=).
var algoTestGenesisHash, _ = base64.StdEncoding.DecodeString("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=")

// algoTestRecipient is the 32-byte recipient public key decoded from
// UCE2U2JC4O4ZR6W763GUQCG57HQCDZEUJY4J5I6VYY4HQZUJDF7AKZO5GM
// (Algorand base32(pubkey || sha512_256(pubkey)[-4:]), 36-byte total, last 4 = checksum).
var algoTestRecipient, _ = hex.DecodeString("a089aa6922e3b998fadff6cd4808ddf9e021e4944e389ea3d5c638786689197e")

// TestSignTxALGO pins the Algorand payment signer byte-for-byte to the TWC vector.
func TestSignTxALGO(t *testing.T) {
	w, err := FromPrivateKeyBytes(algoTestPrivKey, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txalgo.SigningInput{
		GenesisHash: algoTestGenesisHash,
		GenesisId:   "mainnet-v1.0",
		FirstValid:  51,
		LastValid:   61,
		Note:        nil,
		To:          algoTestRecipient,
		Amount:      847,
		Fee:         488931,
	}

	out, err := w.SignTransaction(ALGO, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	got, ok := out.(*txalgo.SigningOutput)
	if !ok {
		t.Fatalf("expected *algorand.SigningOutput, got %T", out)
	}
	if got.Error != "" {
		t.Fatalf("signing error: %s", got.Error)
	}

	// Expected: TWC AlgorandTests.cpp assertion (hex of canonical msgpack signed tx).
	const wantHex = "82a3736967c440de73363dbdeda0682adca06f6268a16a6ec47253c94d5692dc1c49a84a05847812cf66d7c4cf07c7e2f50f143ec365d405e30b35117b264a994626054d2af604a374786e89a3616d74cd034fa3666565ce000775e3a2667633a367656eac6d61696e6e65742d76312e30a26768c420c061c4d8fc1dbdded2d7604be4568e3f6d041987ac37bde4b620b5ab39248adfa26c763da3726376c420a089aa6922e3b998fadff6cd4808ddf9e021e4944e389ea3d5c638786689197ea3736e64c42074b000b6368551a6066d713e2866002e8dab34b69ede09a72e85a39bbb1f7928a474797065a3706179"
	if got.EncodedHex != wantHex {
		t.Errorf("encoded_hex mismatch\n got: %s\nwant: %s", got.EncodedHex, wantHex)
	}
}

// TestSignTxALGONilInput verifies that a nil input returns an error (not a panic).
func TestSignTxALGONilInput(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()

	_, err := w.SignTransaction(ALGO, 0, nil)
	if err == nil {
		t.Fatal("expected error for nil input, got nil")
	}
}
