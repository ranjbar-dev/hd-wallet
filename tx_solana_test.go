package hdwallet

import (
	"testing"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// Solana native system-transfer signing verified against Trust Wallet Core's
// Solana AnySigner transfer vector (swift/Tests/Blockchains/SolanaTests.swift
// testTransferSigner). The expected base58 transaction pins the message
// serialization (header, account-key order, instruction encoding) and the
// ed25519 signature over the raw message.
func TestSignTxSolanaTransfer(t *testing.T) {
	// TWC supplies the ed25519 private key as base58; it decodes to the 32-byte
	// seed our key-only wallet expects.
	priv, err := base58Decode(base58BTC, "A7psj2GW7ZMdY4E5hJq14KMeYg7HFjULSsWSrTXZLvYr")
	if err != nil {
		t.Fatalf("base58 decode private key: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("private key length %d, want 32", len(priv))
	}
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	// Sanity: the derived public key matches TWC's sender address.
	if got, _ := w.Address(SOL); got != "7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q" {
		t.Fatalf("sender address = %s, want 7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q", got)
	}

	in := &txsolana.SigningInput{
		RecentBlockhash: "11111111111111111111111111111111",
		TransactionType: &txsolana.SigningInput_TransferTransaction{
			TransferTransaction: &txsolana.Transfer{
				Recipient: "EN2sCsJ1WDV8UFqsiTXHcUPUxQ4juE71eCknHYYMifkd",
				Value:     42,
			},
		},
	}

	const want = "3p2kzZ1DvquqC6LApPuxpTg5CCDVPqJFokGSnGhnBHrta4uq7S2EyehV1XNUVXp51D69GxGzQZUjikfDzbWBG2aFtG3gHT1QfLzyFKHM4HQtMQMNXqay1NAeiiYZjNhx9UvMX4uAQZ4Q6rx6m2AYfQ7aoMUrejq298q1wBFdtS9XVB5QTiStnzC7zs97FUEK2T4XapjF1519EyFBViTfHpGpnf5bfizDzsW9kYUtRDW1UC2LgHr7npgq5W9TBmHf9hSmRgM9XXucjXLqubNWE7HUMhbKjuBqkirRM"

	out, err := w.SignTransaction(SOL, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	so, ok := out.(*txsolana.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *solana.SigningOutput", out)
	}
	if so.GetError() != "" {
		t.Fatalf("signing error: %s", so.GetError())
	}
	if so.GetEncoded() != want {
		t.Fatalf("encoded mismatch:\n got  %s\n want %s", so.GetEncoded(), want)
	}
	// tx_id is base58 of the fee-payer's signature (the first signature) — on
	// Solana the signature IS the transaction id. The signed tx is
	// [compact-u16 count=1][64-byte signature][message], so the first signature
	// is raw[1:65]; derive the expected id from the (locked) raw output.
	wantTxID := base58Encode(base58BTC, so.GetRaw()[1:65])
	if so.GetTxId() != wantTxID {
		t.Fatalf("tx_id mismatch:\n got  %s\n want %s", so.GetTxId(), wantTxID)
	}
}
