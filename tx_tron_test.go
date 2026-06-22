package hdwallet

import (
	"encoding/hex"
	"testing"

	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// TestTronAddressBytes covers both accepted address forms: a base58check "T..."
// address and a raw 21-byte hex (0x41-prefixed) address must decode to the same
// 21-byte payload.
func TestTronAddressBytes(t *testing.T) {
	const hexAddr = "415cd0fb0ab3ce40f3051414c604b27756e69e43db"
	raw := mustHexTx(t, hexAddr)
	// Build the canonical base58check T-address for the same payload.
	b58 := base58CheckEncode(base58BTC, raw[:1], raw[1:])

	fromHex, err := tronAddressBytes(hexAddr)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	fromB58, err := tronAddressBytes(b58)
	if err != nil {
		t.Fatalf("base58: %v", err)
	}
	if hex.EncodeToString(fromHex) != hexAddr || hex.EncodeToString(fromB58) != hexAddr {
		t.Fatalf("address decode mismatch: hex=%x b58=%x want=%s", fromHex, fromB58, hexAddr)
	}
}

// Tron TransferContract signing verified against Trust Wallet Core's Tron
// AnySigner vector (swift/Tests/Blockchains/TronTests.swift). The expected txID
// and 65-byte recoverable signature pin both the raw_data protobuf serialization
// (a wrong byte changes the sha256 txID) and the signature.
func TestSignTxTronTransfer(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "ba005cd605d8a02e3d5dfd04234cef3a3ee4f76bfbad2722d1fb5af8e12e6764"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:  1539295479000,
			Expiration: 1539331479000,
			BlockHeader: &txtron.BlockHeader{
				Timestamp:      1539295479000,
				TxTrieRoot:     mustHexTx(t, "64288c2db0641316762a99dbb02ef7c90f968b60f9f2e410835980614332f86d"),
				ParentHash:     mustHexTx(t, "00000000002f7b3af4f5f8b9e23a30c530f719f165b742e7358536b280eead2d"),
				Number:         3111739,
				WitnessAddress: mustHexTx(t, "415863f6091b8e71766da808b1dd3159790f61de7d"),
				Version:        3,
			},
			ContractOneof: &txtron.Transaction_Transfer{
				Transfer: &txtron.TransferContract{
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					ToAddress:    "41521ea197907927725ef36d70f25f850d1659c7c7",
					Amount:       2000000,
				},
			},
		},
	}

	const (
		wantID  = "dc6f6d9325ee44ab3c00528472be16e1572ab076aa161ccd12515029869d0451"
		wantSig = "6b5de85a80b2f4f02351f691593fb0e49f14c5cb42451373485357e42d7890cd77ad7bfcb733555c098b992da79dabe5050f5e2db77d9d98f199074222de037701"
		wantRBB = "7b3b"
	)

	out, err := w.SignTransaction(TRX, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	to, ok := out.(*txtron.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *tron.SigningOutput", out)
	}
	if to.GetError() != "" {
		t.Fatalf("signing error: %s", to.GetError())
	}
	if got := hex.EncodeToString(to.GetId()); got != wantID {
		t.Fatalf("txID mismatch:\n got  %s\n want %s", got, wantID)
	}
	if got := hex.EncodeToString(to.GetSignature()); got != wantSig {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", got, wantSig)
	}
	if to.GetRefBlockBytes() != wantRBB {
		t.Fatalf("ref_block_bytes = %s, want %s", to.GetRefBlockBytes(), wantRBB)
	}
}
