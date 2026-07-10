package hdwallet

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	txdot "github.com/ranjbar-dev/hd-wallet/txproto/polkadot"
)

// TestDecodePolkadotTxBalanceTransfer round-trips the TWC-pinned
// SignTransfer_9fd062 vector (raw AccountId, no MultiAddress — the vector
// predates spec 28) through DecodePolkadotTx and asserts every field.
func TestDecodePolkadotTxBalanceTransfer(t *testing.T) {
	w, err := FromPrivateKeyBytes(dotTestPrivKey(), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKey(DOT)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	out, err := w.SignTransaction(DOT, 0, dotVectorInput())
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	enc := out.(*txdot.SigningOutput).Encoded

	f, err := DecodePolkadotTx(enc, 0)
	if err != nil {
		t.Fatalf("DecodePolkadotTx: %v", err)
	}

	if !bytes.Equal(f.SignerPubKey, pub) {
		t.Errorf("SignerPubKey = %x, want %x", f.SignerPubKey, pub)
	}
	if f.SignerAddress != dotTestSender {
		t.Errorf("SignerAddress = %s, want %s", f.SignerAddress, dotTestSender)
	}
	if f.MultiAddress {
		t.Error("MultiAddress = true, want false (vector predates spec 28)")
	}
	if f.SignatureScheme != "ed25519" {
		t.Errorf("SignatureScheme = %s, want ed25519", f.SignatureScheme)
	}
	if len(f.Signature) != 64 {
		t.Errorf("len(Signature) = %d, want 64", len(f.Signature))
	}
	if f.Immortal {
		t.Error("Immortal = true, want false (mortal era in this vector)")
	}
	if f.Period != 64 {
		t.Errorf("Period = %d, want 64", f.Period)
	}
	if f.Phase != 58 {
		t.Errorf("Phase = %d, want 58 (3541050 mod 64)", f.Phase)
	}
	if f.Nonce != 3 {
		t.Errorf("Nonce = %d, want 3", f.Nonce)
	}
	if f.Tip == nil || f.Tip.Sign() != 0 {
		t.Errorf("Tip = %v, want 0", f.Tip)
	}
	if f.ModuleIndex != 5 || f.MethodIndex != 0 {
		t.Errorf("ModuleIndex/MethodIndex = %d/%d, want 5/0", f.ModuleIndex, f.MethodIndex)
	}
	if f.ToAddress != dotTestRecipient {
		t.Errorf("ToAddress = %s, want %s", f.ToAddress, dotTestRecipient)
	}
	if f.Value == nil || f.Value.Cmp(big.NewInt(2000000000)) != 0 {
		t.Errorf("Value = %v, want 2000000000", f.Value)
	}
	if f.AssetID != nil {
		t.Errorf("AssetID = %v, want nil", f.AssetID)
	}
}

// TestDecodePolkadotTxAssetTransfer round-trips the Asset Hub
// Assets.transfer_keep_alive structure (MultiAddress, immortal era) through
// DecodePolkadotTx and asserts every field, including the asset id.
func TestDecodePolkadotTxAssetTransfer(t *testing.T) {
	w, err := FromPrivateKeyBytes(dotTestPrivKey(), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKey(DOT)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	input := &txdot.SigningInput{
		GenesisHash:        dotTestGenesisHash,
		Nonce:              0,
		SpecVersion:        1002000,
		TransactionVersion: 15,
		MultiAddress:       true,
		MessageOneof: &txdot.SigningInput_AssetTransfer{AssetTransfer: &txdot.AssetTransfer{
			ToAddress: dotTestRecipient,
			Value:     big.NewInt(5000000).Bytes(),
			AssetId:   1984,
		}},
	}
	out, err := w.SignTransaction(DOT, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	enc := out.(*txdot.SigningOutput).Encoded

	f, err := DecodePolkadotTx(enc, 0)
	if err != nil {
		t.Fatalf("DecodePolkadotTx: %v", err)
	}

	if !bytes.Equal(f.SignerPubKey, pub) {
		t.Errorf("SignerPubKey = %x, want %x", f.SignerPubKey, pub)
	}
	if f.SignerAddress != dotTestSender {
		t.Errorf("SignerAddress = %s, want %s", f.SignerAddress, dotTestSender)
	}
	if !f.MultiAddress {
		t.Error("MultiAddress = false, want true (Asset Hub uses MultiAddress)")
	}
	if f.SignatureScheme != "ed25519" {
		t.Errorf("SignatureScheme = %s, want ed25519", f.SignatureScheme)
	}
	if !f.Immortal {
		t.Error("Immortal = false, want true (no Era set on this input)")
	}
	if f.Period != 0 || f.Phase != 0 {
		t.Errorf("Period/Phase = %d/%d, want 0/0 for immortal", f.Period, f.Phase)
	}
	if f.Nonce != 0 {
		t.Errorf("Nonce = %d, want 0", f.Nonce)
	}
	if f.Tip == nil || f.Tip.Sign() != 0 {
		t.Errorf("Tip = %v, want 0", f.Tip)
	}
	if f.ModuleIndex != 50 || f.MethodIndex != 9 {
		t.Errorf("ModuleIndex/MethodIndex = %d/%d, want 50/9", f.ModuleIndex, f.MethodIndex)
	}
	if f.ToAddress != dotTestRecipient {
		t.Errorf("ToAddress = %s, want %s", f.ToAddress, dotTestRecipient)
	}
	if f.Value == nil || f.Value.Cmp(big.NewInt(5000000)) != 0 {
		t.Errorf("Value = %v, want 5000000", f.Value)
	}
	if f.AssetID == nil || *f.AssetID != 1984 {
		t.Errorf("AssetID = %v, want 1984", f.AssetID)
	}
}

// TestDecodePolkadotTxErrors covers malformed/truncated/unrecognised input.
func TestDecodePolkadotTxErrors(t *testing.T) {
	w, err := FromPrivateKeyBytes(dotTestPrivKey(), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	out, err := w.SignTransaction(DOT, 0, dotVectorInput())
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	valid := out.(*txdot.SigningOutput).Encoded

	if _, err := DecodePolkadotTx(nil, 0); !errors.Is(err, ErrTxDecode) {
		t.Errorf("nil input: err = %v, want ErrTxDecode", err)
	}
	if _, err := DecodePolkadotTx([]byte{0x00}, 0); !errors.Is(err, ErrTxDecode) {
		t.Errorf("empty body: err = %v, want ErrTxDecode", err)
	}
	// Truncate at every prefix strictly shorter than the full extrinsic: must
	// never panic and must always return ErrTxDecode.
	for n := 0; n < len(valid); n++ {
		if _, err := DecodePolkadotTx(valid[:n], 0); !errors.Is(err, ErrTxDecode) {
			t.Errorf("truncated to %d bytes: err = %v, want ErrTxDecode", n, err)
		}
	}
	// Corrupt the version byte (index 2: after the 2-byte length prefix).
	corrupt := append([]byte(nil), valid...)
	corrupt[2] = 0x00
	if _, err := DecodePolkadotTx(corrupt, 0); !errors.Is(err, ErrTxDecode) {
		t.Errorf("bad version byte: err = %v, want ErrTxDecode", err)
	}
	// Trailing garbage after a structurally-complete extrinsic.
	withTrailer := append(append([]byte(nil), valid...), 0xff)
	if _, err := DecodePolkadotTx(withTrailer, 0); !errors.Is(err, ErrTxDecode) {
		t.Errorf("trailing garbage: err = %v, want ErrTxDecode", err)
	}
}
