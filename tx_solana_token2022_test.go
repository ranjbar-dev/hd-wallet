package hdwallet

import (
	"testing"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// Solana Token-2022 (SPL Token Extensions program) support: TransferChecked
// and CreateAndTransferToken both accept an alternate token_program_id
// (0 = classic SPL Token, 1 = Token-2022). Both vectors below are from Trust
// Wallet Core's Solana AnySigner suite (rust/tw_tests/tests/chains/solana/
// solana_sign.rs), byte-for-byte pinned.

// TWC test_solana_sign_transfer_token_2022: TransferChecked routed through the
// Token-2022 program id instead of the classic SPL Token program.
func TestSignSolanaTransferToken2022(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "9U2eTS9b2Essvo1s5hDmwgC1atkSCCUipj2FemLvdWbj",
		TransactionType: &txsolana.SigningInput_TokenTransferTransaction{
			TokenTransferTransaction: &txsolana.TokenTransfer{
				TokenMintAddress:      "BSQCmMAFB9itonyVSLsUxX92Ne1rgBZFqothBk3q91k6",
				SenderTokenAddress:    "EQxRyhzjyhRX4TJXt7FmQ3HfFdRcu49krjxHMszidQYS",
				RecipientTokenAddress: "FzsLNpzsLMBbm1LWpM6P3W4tKrCkd8KqnMmADNvArW5d",
				Amount:                1000000000,
				Decimals:              9,
				TokenProgramId:        SolanaTokenProgram2022,
			},
		},
	}
	const want = "SAXNFUd7dNBu956Gi4XNuvMkKKjS9vp6puz45ErYMHFpMNwC3AQxDxGbweXt4GzY2FnUZ6ubm231NrdwWa8dg9bqgRMaHPLuPiy99YwtvcQ1E6mHxHqq8nL5VaN8wiVnrMU57zCLfHsSsVCHZc5peHHAPXMDE318uMCLLBwgDWuD1FfAvUAyXRSYniXzWG3jtBdDhuDohh13E2TMrtqTcKVv3crejFqFjtsNuW7KCqrZwxCv1ASNiiL2XScQBdHwStyjH2UTqLmT6wjGLiDYy7PZ88Tbz65r8NLr4Vb1aYSTChasfVjMLdybetfNaf4nJuBE4ZuXca7W66txKbHesxQbzrjUCXX12JFbKyaA8KJKBpbgkc9jWJjQkzyn"
	signSolanaVector(t, mustB58Priv(t, "MCyXa2gTJELxTPemyVi5ydDcQ3vVgFyddQYXj6UM3tw"), in, want)
}

// TWC test_solana_sign_create_and_transfer_token_2022: create the recipient's
// Token-2022 ATA and TransferChecked into it in one transaction. The
// recipient_token_address supplied here must equal the internally derived
// Token-2022 ATA (fund-critical guard, mirroring the classic-program path).
func TestSignSolanaCreateAndTransferToken2022(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "5oba9g5nWnvutTTb935aBMkHBYGXoak1ot4U2p34zEiJ",
		TransactionType: &txsolana.SigningInput_CreateAndTransferTokenTransaction{
			CreateAndTransferTokenTransaction: &txsolana.CreateAndTransferToken{
				RecipientMainAddress:  "EbHdsfVpWzeQV4TceYQ2xENS8meBHyztyTKVSFtgHPUw",
				TokenMintAddress:      "BSQCmMAFB9itonyVSLsUxX92Ne1rgBZFqothBk3q91k6",
				RecipientTokenAddress: "FzsLNpzsLMBbm1LWpM6P3W4tKrCkd8KqnMmADNvArW5d",
				SenderTokenAddress:    "EQxRyhzjyhRX4TJXt7FmQ3HfFdRcu49krjxHMszidQYS",
				Amount:                1000000000,
				Decimals:              9,
				TokenProgramId:        SolanaTokenProgram2022,
			},
		},
	}
	const want = "2xzg9AVGv8wWEn9S4m8954WSzh2MUQPCTCyFmyrSs4DJCkSaZRMAbGL8NcyDeJFT3RwUabHsX1m5CFuqzJ5Jg9knNwG6uBjYjWjNjGLBEBURa3ARqziaMAL2mZY8uZwaZETE33WZeSxNrm7zv1jJYLfqbWxquEedGND9vB9AuEspHg7TCZxfJbzY4W8QtLqyQ598z9adxWgwNXanHzqu7B4bNsp1wfKPPyx8AGQaVSx6fepaevDEZX9h2Rg1daW9TjVpktp7EHrriYVs4m44WJ18fejWLyqituXqQPdhos5oZ3e5vNXE8KcgARKXtwsXCGwwKwc9ZEVNvUp6qyUZZV8os2FHorodrT9g3Xrso5dgdsRCb42AUrKHyDdXMpRA1PmeZX6UdzgL8knt2xfzCFxzGPuMKeTtvZKFcEPJvNg73CSMPVH1mm3jz75nATdChR7xu5R4m5Gy8vhr5ndEnb8fM5P1gv6hDbfmesAEf5wye4mKTVAC4B8Mhf8WC8YNaGUG7CcxeQZXrjEfUQenboArhqbxqHFYrURK3GJLAQojXmkwSMGwv4TYL"
	signSolanaVector(t, mustB58Priv(t, "MCyXa2gTJELxTPemyVi5ydDcQ3vVgFyddQYXj6UM3tw"), in, want)
}

// A Token-2022 CreateAndTransferToken with a recipient_token_address that does
// not match the internally derived Token-2022 ATA must be rejected — the
// fund-critical guard applies identically to the alternate program id.
func TestSignSolanaCreateAndTransferToken2022Mismatch(t *testing.T) {
	w, err := FromPrivateKeyBytes(mustB58Priv(t, "MCyXa2gTJELxTPemyVi5ydDcQ3vVgFyddQYXj6UM3tw"), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()
	in := &txsolana.SigningInput{
		RecentBlockhash: "5oba9g5nWnvutTTb935aBMkHBYGXoak1ot4U2p34zEiJ",
		TransactionType: &txsolana.SigningInput_CreateAndTransferTokenTransaction{
			CreateAndTransferTokenTransaction: &txsolana.CreateAndTransferToken{
				RecipientMainAddress: "EbHdsfVpWzeQV4TceYQ2xENS8meBHyztyTKVSFtgHPUw",
				TokenMintAddress:     "BSQCmMAFB9itonyVSLsUxX92Ne1rgBZFqothBk3q91k6",
				// valid address, but NOT the Token-2022 ATA for (main, mint):
				RecipientTokenAddress: "EQxRyhzjyhRX4TJXt7FmQ3HfFdRcu49krjxHMszidQYS",
				SenderTokenAddress:    "EQxRyhzjyhRX4TJXt7FmQ3HfFdRcu49krjxHMszidQYS",
				Amount:                1000000000,
				Decimals:              9,
				TokenProgramId:        SolanaTokenProgram2022,
			},
		},
	}
	if _, err := w.SignTransaction(SOL, 0, in); err == nil {
		t.Fatalf("mismatched recipient_token_address: err = nil, want ErrTxInput")
	}
}

// SolanaTokenAccountAddress (classic program) must be unaffected by the
// Token-2022 addition — regression check against an existing pinned vector.
func TestSolanaTokenAccountAddressClassicRegression(t *testing.T) {
	got, err := SolanaTokenAccountAddress("B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V", "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt")
	if err != nil {
		t.Fatalf("SolanaTokenAccountAddress: %v", err)
	}
	const want = "EDNd1ycsydWYwVmrYZvqYazFqwk1QjBgAUKFjBoz1jKP"
	if got != want {
		t.Fatalf("classic ATA = %s, want %s", got, want)
	}
}

// SolanaTokenAccountAddressWithProgram with the classic program id must equal
// SolanaTokenAccountAddress exactly (delegation correctness).
func TestSolanaTokenAccountAddressWithProgramClassicMatchesClassic(t *testing.T) {
	wallet := "B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V"
	mint := "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt"
	classic, err := SolanaTokenAccountAddress(wallet, mint)
	if err != nil {
		t.Fatalf("SolanaTokenAccountAddress: %v", err)
	}
	withProgram, err := SolanaTokenAccountAddressWithProgram(wallet, mint, solanaTokenProgramID)
	if err != nil {
		t.Fatalf("SolanaTokenAccountAddressWithProgram: %v", err)
	}
	if withProgram != classic {
		t.Fatalf("SolanaTokenAccountAddressWithProgram(classic) = %s, want %s", withProgram, classic)
	}
}
