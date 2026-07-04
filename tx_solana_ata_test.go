package hdwallet

import (
	"errors"
	"testing"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// TWC test_solana_sign_create_token_account (funder == owner; explorer-confirmed).
func TestSignSolanaCreateTokenAccount(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "9ipJh5xfyoyDaiq8trtrdqQeAhQbQkWy2eANizKvx75K",
		TransactionType: &txsolana.SigningInput_CreateTokenAccountTransaction{
			CreateTokenAccountTransaction: &txsolana.CreateTokenAccount{
				MainAddress:      "B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V",
				TokenMintAddress: "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
				TokenAddress:     "EDNd1ycsydWYwVmrYZvqYazFqwk1QjBgAUKFjBoz1jKP",
			},
		},
	}
	const want = "CKzRLx3AQeVeLQ7T4hss2rdbUpuAHdbwXDazxtRnSKBuncCk3WnYgy7XTrEiya19MJviYHYdTxi9gmWJY8qnR2vHVnH2DbPiKA8g72rD3VvMnjosGUBBvCwbBLge6FeQdgczMyRo9n5PcHvg9yJBTJaEEvuewyBVHwCGyGQci7eYd26xtZtCjAjwcTq4gGr3NZbeRW6jZp6j6APuew7jys4MKYRV4xPodua1TZFCkyWZr1XKzmPh7KTavtN5VzPDA8rbsvoEjHnKzjB2Bszs6pDjcBFSHyQqGsHoF8XPD35BLfjDghNtBmf9cFqo5axa6oSjANAuYg6cMSP4Hy28waSj8isr6gQjE315hWi3W1swwwPcn322gYZx6aMAcmjczaxX9aktpHYgZxixF7cYWEHxJs5QUK9mJePu9Xc6yW75UB4Ynx6dUgaSTEUzoQthF2TN3xXwu1"
	signSolanaVector(t, mustB58Priv(t, "9YtuoD4sH4h88CVM8DSnkfoAaLY7YeGC2TarDJ8eyMS5"), in, want)
}

// TWC test_solana_sign_create_token_account_5ktpn1 (different funder; token_address
// omitted here to exercise internal ATA derivation — the derived ATA must equal
// TWC's supplied one, so the pinned bytes prove derivation too).
func TestSignSolanaCreateTokenAccount5KtPn1(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "HxaCmxrXgzkzXYvDFTToENtf9rVKk7cbiuSUqnqNheHq",
		TransactionType: &txsolana.SigningInput_CreateTokenAccountTransaction{
			CreateTokenAccountTransaction: &txsolana.CreateTokenAccount{
				MainAddress:      "Eg5jqooyG6ySaXKbQUu4Lpvu2SqUPZrNkM4zXs9iUDLJ",
				TokenMintAddress: "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
			},
		},
	}
	const want = "EoJGDRFZdnjmx7rgwYSuDGTMTUdxCBeh8RggrQDzGht9bwzLPpCWkCrN4iQJqg3R6JxP7z2QZuf7dGCZcjMVBmmisYE8waRsohcvygRwmGr6nefbaujR5avm2x3EUvoTGyy8cMZJxX7URx45qQJyCgqFLNFCQzD1Kej3xCEPAJqCdGZgmqkryw2E2nkpGKXgRmbyEg2rFgd5kpvjG6jSLLYzGomxVnaKK2XyMQbcedkTMYJ8Ara71iWPRFUziWfgivZcA1qsQp92Fpao3FSsRprhoQz9u1VyAnh8zEM9jCKiE5s4dwCknqCJYeYsbMLn1be2vNP9bMQfu1jjGSHmbb9WR3E2vakTUEUByASXqSAJZuXYE5scopEzB28rC8nrC31ArLMZng5wWym3QbqEv2Syd6RHoEeoXR6vA5LPqvJKyvtH82p4hc4XbD18128aNrFG3GTD2P"
	signSolanaVector(t, mustHexTx(t, "4b9d6f57d28b06cbfa1d4cc710953e62d653caf853415c56ffd9d150acdeb7f7"), in, want)
}

// TWC test_solana_sign_create_token_account_for_other_3e6ufv (funder != owner).
func TestSignSolanaCreateTokenAccountForOther(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "HmWyvrif3QfZJnDiRyrojmH9iLr7eMxxqiC9RJWFeunr",
		TransactionType: &txsolana.SigningInput_CreateTokenAccountTransaction{
			CreateTokenAccountTransaction: &txsolana.CreateTokenAccount{
				MainAddress:      "3xJ3MoUVFPNFEHfWdtNFa8ajXUHsJPzXcBSWMKLd76ft",
				TokenMintAddress: "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
				TokenAddress:     "67BrwFYt7qUnbAcYBVx7sQ4jeD2KWN1ohP6bMikmmQV3",
			},
		},
	}
	const want = "4BsrHedHuForcKDhLdnLYDXgtQgQEj3EQVDtEhqa7o6ukFjW3shpTWv6PeKQdMp6af4ASjD4xQeZvXxLK5WUjguVMUf3xdJn7RnFeM7hdDJ56RDBM5PRJbRJVHjz6FJ7SVNTvr9y3gVYQtWx7NfKRxiyEAfq9JG7nqxSWaW6raMr9t35aVcdAVuXE9iXj3rzhVfCS69vVzy5KcFEK3mvDYG6L12V2CfviCydmeCvPw5r3zBUrZSQv7Ti4XFNBrPbk28gcqQwsBknBqasHxHqD9VUyPmBTuUyXq75QN8rhqN55NjxKBUw37tEUS1jKVpWnTeLFq1eRAMdXvjftNuQ5Bmm8Zc12PGWj9vdorBaYyvZXexJST5xNjR4SCkXvXZoRScETck95chv3VBn54jP8DpB4GGUmATFKSxpdtnNV64i1SQXW13KJwswthJvAaDiqevQLKLkvrTEAdb4BxEfPkFjDVti6P58rTZCMg5CTVLqdmWwpTSW5V"
	signSolanaVector(t, mustHexTx(t, "4b9d6f57d28b06cbfa1d4cc710953e62d653caf853415c56ffd9d150acdeb7f7"), in, want)
}

// A caller-supplied token_address that does not match the derived ATA is a
// fund-critical error (rent would fund a mismatched account).
func TestSignSolanaCreateTokenAccountMismatch(t *testing.T) {
	w, err := FromPrivateKeyBytes(mustB58Priv(t, "9YtuoD4sH4h88CVM8DSnkfoAaLY7YeGC2TarDJ8eyMS5"), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()
	in := &txsolana.SigningInput{
		RecentBlockhash: "9ipJh5xfyoyDaiq8trtrdqQeAhQbQkWy2eANizKvx75K",
		TransactionType: &txsolana.SigningInput_CreateTokenAccountTransaction{
			CreateTokenAccountTransaction: &txsolana.CreateTokenAccount{
				MainAddress:      "B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V",
				TokenMintAddress: "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
				// valid address, but NOT the ATA for (main, mint):
				TokenAddress: "ANVCrmRw7Ww7rTFfMbrjApSPXEEcZpBa6YEiBdf98pAf",
			},
		},
	}
	if _, err := w.SignTransaction(SOL, 0, in); !errors.Is(err, ErrTxInput) {
		t.Fatalf("mismatched token_address: err = %v, want ErrTxInput", err)
	}
}

// TWC test_solana_sign_create_and_transfer_token (explorer-confirmed).
func TestSignSolanaCreateAndTransferToken(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "DMmDdJP41M9mw8Z4586VSvxqGCrqPy5uciF6HsKUVDja",
		TransactionType: &txsolana.SigningInput_CreateAndTransferTokenTransaction{
			CreateAndTransferTokenTransaction: &txsolana.CreateAndTransferToken{
				RecipientMainAddress:  "71e8mDsh3PR6gN64zL1HjwuxyKpgRXrPDUJT7XXojsVd",
				TokenMintAddress:      "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
				RecipientTokenAddress: "EF6L8yJT1SoRoDCkAZfSVmaweqMzfhxZiptKi7Tgj5XY",
				SenderTokenAddress:    "ANVCrmRw7Ww7rTFfMbrjApSPXEEcZpBa6YEiBdf98pAf",
				Amount:                2900,
				Decimals:              6,
			},
		},
	}
	const want = "3Y2MVz2VVi7aEyC9q1awwdk1ModDBPHRSacKmTYnSgkmbbJeZ62Fub1bVPSHaTy4LUcQpzCQYhHAKtTKXUDYijEeLsMAUqPBEMAq1w8zCdqDpdXy6M4PuwNtYVV1WgqeiEsiMWpPp4BGWKfcziwFbmYueUGituacJq4wTnt92fho8mFi49XW64gEG4iNGScDtJkY7Geq8PKiLh1E9JMJoceiHxKbmxzCmmLTxEHdhySYHcDUSXnXWogZskeZNBMtR9dNjEMkCzEjrxRpBtJPtUNshciY45mDPNmw4j3xyLCBTRikyfFLc5g11r3UgyVD4YokoPRvrEXsgt6W3yjBshropBm6mY2eJYvfY2eZz4Yq8kLcUatCHVKtjcb1mP9Ww57KisJ9bRhipC8sodFaMYhZARMEa4a1u9eH4MyNUATRGNXarwQSBY46PWS3nKP6QBK7Dw7Ppp9MmYkdPcXKaLScbyLF3jKu6dHWMkHw3WdXSsM1wwXjXnWF9LxdwaEVcDmySWybj6aKD9QCWTU5kdncqJU56f7SYNRTN289WdUFGNDmSh56tj2v1"
	signSolanaVector(t, mustB58Priv(t, "66ApBuKpo2uSzpjGBraHq7HP8UZMUJzp3um8FdEjkC9c"), in, want)
}

// TWC test_solana_sign_create_and_transfer_token_2 (recipient_token_address
// omitted — internal derivation must reproduce TWC's bytes).
func TestSignSolanaCreateAndTransferToken2(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "AfzzEC8NVXoxKoHdjXLDVzqwqvvZmgPuqyJqjuHiPY1D",
		TransactionType: &txsolana.SigningInput_CreateAndTransferTokenTransaction{
			CreateAndTransferTokenTransaction: &txsolana.CreateAndTransferToken{
				RecipientMainAddress: "3WUX9wASxyScbA7brDipioKfXS1XEYkQ4vo3Kej9bKei",
				TokenMintAddress:     "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				SenderTokenAddress:   "5sS5Z8GAdVHqZKRqEvpDauHvvLgbDveiyfi81uh25mrf",
				Amount:               4000,
				Decimals:             6,
			},
		},
	}
	const want = "2qkvFTcMk9kPaHtd7idJ1gJc4zTkuYDUJsC67kXvHjv3zwEyUx92QyhhSeBjL6h3Zaisj2nvTWid2UD1N9hbg9Ty7vSHLc7mcFVvy3yJmN9tz99iLKsf15rEeKUk3crXWLtKZEpcXJurN7vrxKwjQJnVob2RjyxwVfho1oNZ72BHvqToRM1W2KbcYhxK4d9zB4QY5tR2dzgCHWqAjf9Yov3y9mPBYCQBtw2GewrVMDbg5TK81E9BaWer3BcEafc3NCnRfcFEp7ZUXsGAgJYx32uUoJPP8ByTqBsp2JWgHyZhoz1WUUYRqWKZthzotErVetjSik4h5GcXk9Nb6kzqEf4nKEZ22eyrP5dv3eZMuGUUpMYUT9uF16T72s4TTwqiWDPFkidD33tACx74JKGoDraHEvEeAPrv6iUmC675kMuAV4EtVspVc5SnKXgRWRxb4dcH3k7K4ckjSxYZwg8UhTXUgPxA936jBr2HeQuPLmNVn2muA1HfL2DnyrobUP9vHpbL3HHgM2fckeXy8LAcjnoE9TTaAKX32wo5xoMj9wJmmtcU6YbXN4KgZ"
	signSolanaVector(t, mustB58Priv(t, "9YtuoD4sH4h88CVM8DSnkfoAaLY7YeGC2TarDJ8eyMS5"), in, want)
}

// TWC test_solana_sign_create_and_transfer_token_with_durable_nonce.
func TestSignSolanaCreateAndTransferTokenDurableNonce(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "AaYfEmGQpfJWypZ8MNmBHTep1dwCHVYDRHuZ3gVFiJpY",
		NonceAccount:    "6vNrYDm6EHcvBALY7HywuDWpTSc6uGt3y2nf5MuG1TmJ",
		TransactionType: &txsolana.SigningInput_CreateAndTransferTokenTransaction{
			CreateAndTransferTokenTransaction: &txsolana.CreateAndTransferToken{
				RecipientMainAddress:  "3UVYmECPPMZSCqWKfENfuoTv51fTDTWicX9xmBD2euKe",
				TokenMintAddress:      "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
				RecipientTokenAddress: "93hbN3brRjZqRQTT9Xx6rAHVDFZFWD9ragFDXvDbTEjr",
				SenderTokenAddress:    "5sS5Z8GAdVHqZKRqEvpDauHvvLgbDveiyfi81uh25mrf",
				Amount:                4000,
				Decimals:              6,
			},
		},
	}
	const want = "388uZws6GfA9aiH1LPsYBijGBEfLEgqe6q5NWVYhsmjXjrgZB4cScGuvja6nBL3i6qg6HA4a8ptW6aHsNKVdcBWKhjZjaTPH5heEThzwEsMDfnH2PWAUbqfiFgMZQRCkhyCj57hGUR7hBFPELfz3DBw5qMz1tnP9gU6KTqHUomu5UaadLHb2v5mbgTRcsMm3yDp2tzMwrp53VqvFNmHSau4ot4kdNL1jqEJC68Fj4ku6fMQaFSPyAeLQRF45ofYsFCa65fmtb4gBpqWUdqWLv5Dy6xQUQUDsin8qpEVds6unXw5f63UjZeD7XQdC6Vz5aq3e6P9ug8L41xc1rbuRU3Kp4arUKyqTsHMQ2dxMhPwEJLkHd4mFqqUWpYFTdfLFaNGU22hEkvP1esHUzaaGDmzAozbS96oaFw2jbHRRJtL8VjoA1aokGFFThM6M6mExuy8GhUXdGjxDFU83Dan1URmHMGBRC4J9RMZip9s1sktJw9Rj5Std9KVT8T7m4MxTVTx4QoBw6KAf6PgNHyHPtZSc7kzoCxDYNo2Myxvy8D95zk9YMp1MxeZXTDQ2aJuhWvfHhhrwgcQasAxRzbnJ9oehebVUNEcZEFsfnCgYuUmxWUemoKZnE1bNMCvERVkT5fKQ36e1rt5vTC2iES9jzr3hDC1Pk1"
	signSolanaVector(t, mustB58Priv(t, "9YtuoD4sH4h88CVM8DSnkfoAaLY7YeGC2TarDJ8eyMS5"), in, want)
}

// CreateTokenAccount + durable nonce has no TWC vector → must be rejected.
func TestSignSolanaCreateTokenAccountNonceRejected(t *testing.T) {
	w, err := FromPrivateKeyBytes(mustB58Priv(t, "9YtuoD4sH4h88CVM8DSnkfoAaLY7YeGC2TarDJ8eyMS5"), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()
	in := &txsolana.SigningInput{
		RecentBlockhash: "9ipJh5xfyoyDaiq8trtrdqQeAhQbQkWy2eANizKvx75K",
		NonceAccount:    "6vNrYDm6EHcvBALY7HywuDWpTSc6uGt3y2nf5MuG1TmJ",
		TransactionType: &txsolana.SigningInput_CreateTokenAccountTransaction{
			CreateTokenAccountTransaction: &txsolana.CreateTokenAccount{
				MainAddress:      "B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V",
				TokenMintAddress: "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
			},
		},
	}
	if _, err := w.SignTransaction(SOL, 0, in); !errors.Is(err, ErrTxInput) {
		t.Fatalf("nonce on CreateTokenAccount: err = %v, want ErrTxInput", err)
	}
}
