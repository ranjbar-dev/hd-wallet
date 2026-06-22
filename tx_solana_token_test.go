package hdwallet

import (
	"testing"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// TestSignTxSolanaTokenTransfer verifies an SPL TransferChecked against Trust
// Wallet Core's Solana token-transfer AnySigner vector (rust tw_tests
// solana_sign::test_solana_sign_token_transfer). The expected base58 pins the
// account ordering, instruction data, and ed25519 signature byte-for-byte.
func TestSignTxSolanaTokenTransfer(t *testing.T) {
	// TWC's test private key is base58-encoded (32-byte ed25519 seed).
	priv, err := base58Decode(base58BTC, "9YtuoD4sH4h88CVM8DSnkfoAaLY7YeGC2TarDJ8eyMS5")
	if err != nil {
		t.Fatalf("decode priv: %v", err)
	}
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txsolana.SigningInput{
		RecentBlockhash: "CNaHfvqePgGYMvtYi9RuUdVxDYttr1zs4TWrTXYabxZi",
		TransactionType: &txsolana.SigningInput_TokenTransferTransaction{
			TokenTransferTransaction: &txsolana.TokenTransfer{
				TokenMintAddress:      "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
				SenderTokenAddress:    "EDNd1ycsydWYwVmrYZvqYazFqwk1QjBgAUKFjBoz1jKP",
				RecipientTokenAddress: "3WUX9wASxyScbA7brDipioKfXS1XEYkQ4vo3Kej9bKei",
				Amount:                4000,
				Decimals:              6,
			},
		},
	}

	const want = "PGfKqEaH2zZXDMZLcU6LUKdBSzU1GJWJ1CJXtRYCxaCH7k8uok38WSadZfrZw3TGejiau7nSpan2GvbK26hQim24jRe2AupmcYJFrgsdaCt1Aqs5kpGjPqzgj9krgxTZwwob3xgC1NdHK5BcNwhxwRtrCphGEH7zUFpGFrFrHzgpf2KY8FvPiPELQyxzTBuyNtjLjMMreehSKShEjD9Xzp1QeC1pEF8JL6vUKzxMXuveoEYem8q8JiWszYzmTMfDk13JPgv7pXFGMqDV3yNGCLsWccBeSFKN4UKECre6x2QbUEiKGkHkMc4zQwwyD8tGmEMBAGm339qdANssEMNpDeJp2LxLDStSoWShHnotcrH7pUa94xCVvCPPaomF"

	out, err := w.SignTransaction(SOL, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	so := out.(*txsolana.SigningOutput)
	if so.GetError() != "" {
		t.Fatalf("signing error: %s", so.GetError())
	}
	if so.GetEncoded() != want {
		t.Fatalf("encoded mismatch:\n got  %s\n want %s", so.GetEncoded(), want)
	}
}
