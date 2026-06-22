package hdwallet

import (
	"encoding/hex"
	"testing"

	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// TestSignTxTronTransferTRC20 verifies a TRC-20 token transfer (built as a
// TriggerSmartContract calling transfer(address,uint256)) against Trust Wallet
// Core's Tron SignTransferTrc20Contract vector. The expected txID and 65-byte
// recoverable signature pin the TriggerSmartContract serialization, the ABI
// calldata, and the signature.
func TestSignTxTronTransferTRC20(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "2d8f68944bdbfbc0769542fba8fc2d2a3de67393334471624364c7006da2aa54"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp: 1539295479000,
			BlockHeader: &txtron.BlockHeader{
				Timestamp:      1539295479000,
				TxTrieRoot:     mustHexTx(t, "64288c2db0641316762a99dbb02ef7c90f968b60f9f2e410835980614332f86d"),
				ParentHash:     mustHexTx(t, "00000000002f7b3af4f5f8b9e23a30c530f719f165b742e7358536b280eead2d"),
				Number:         3111739,
				WitnessAddress: mustHexTx(t, "415863f6091b8e71766da808b1dd3159790f61de7d"),
				Version:        3,
			},
			ContractOneof: &txtron.Transaction_TransferTrc20{
				TransferTrc20: &txtron.TransferTRC20Contract{
					OwnerAddress:    "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC",
					ContractAddress: "THTR75o8xXAgCTQqpiot2AFRAjvW1tSbVV",
					ToAddress:       "TW1dU4L3eNm7Lw8WvieLKEHpXWAussRG9Z",
					Amount:          []byte{0x03, 0xe8}, // 1000
				},
			},
		},
	}

	const (
		wantID  = "0d644290e3cf554f6219c7747f5287589b6e7e30e1b02793b48ba362da6a5058"
		wantSig = "bec790877b3a008640781e3948b070740b1f6023c29ecb3f7b5835433c13fc5835e5cad3bd44360ff2ddad5ed7dc9d7dee6878f90e86a40355b7697f5954b88c01"
	)

	out, err := w.SignTransaction(TRX, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	to := out.(*txtron.SigningOutput)
	if to.GetError() != "" {
		t.Fatalf("signing error: %s", to.GetError())
	}
	if got := hex.EncodeToString(to.GetId()); got != wantID {
		t.Fatalf("txID mismatch:\n got  %s\n want %s", got, wantID)
	}
	if got := hex.EncodeToString(to.GetSignature()); got != wantSig {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", got, wantSig)
	}
}
