package hdwallet

import (
	"crypto/ed25519"
	"testing"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// signSolanaVector runs SignTransaction(SOL) for a key-only wallet built from
// priv and asserts the base58-encoded result equals want (a TWC AnySigner
// vector from rust/tw_tests/tests/chains/solana/solana_sign.rs).
func signSolanaVector(t *testing.T, priv []byte, in *txsolana.SigningInput, want string) *txsolana.SigningOutput {
	t.Helper()
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()
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
	return so
}

func mustB58Priv(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base58Decode(base58BTC, s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad base58 private key (%v, len %d)", err, len(b))
	}
	return b
}

// TWC test_solana_sign_transfer_with_durable_nonce.
func TestSignSolanaTransferDurableNonce(t *testing.T) {
	priv := mustHexTx(t, "044014463e2ee3cc9c67a6f191dbac82288eb1d5c1111d21245bdc6a855082a1")
	in := &txsolana.SigningInput{
		RecentBlockhash: "5ycoKxPRpW2GdD4byZuMptHU3VU5MgUCh6NLGQ2U8VE5", // durable nonce VALUE
		NonceAccount:    "ALAaqqt4Cc8hWH22GT2L16xKNAn6gv7XCTF7JkbfWsc",
		TransactionType: &txsolana.SigningInput_TransferTransaction{
			TransferTransaction: &txsolana.Transfer{
				Recipient: "3UVYmECPPMZSCqWKfENfuoTv51fTDTWicX9xmBD2euKe",
				Value:     1000,
			},
		},
	}
	const want = "6zRqmNP5waeyartbf8GuQrWxdSy4SCYBTEmGhiXfYNxQTuUrvrBjia18YoCM367AQZWZ5yTjcN6FaXuaPWju7aVZNFjyqpuMZLNEbpm8ZNmKP4Na2VzR59iAdSPEZGTPuesZEniNMAD7ZSux6fayxgwrEwMWjeiskFQEwdvFzKNHfNLbjoVpdSTxhKiqfbwxnFBpBxNE4nqMj3bUR37cYJAFoDFokxy23HGpV93V9mbGG89aLBNQnd9LKTjpYFv49VMd48mptUd7uyrRwZLMneew2Bxq3PLsj9SaJyCWbsnqYj6bBahhsErz67PJTJepx4BEhqRxHGUSbpeNiL7qyERri1GZsXhN8fgU3nPiYr7tMMxuLAoUFRMJ79HCex7vxhf7SapvcP"
	signSolanaVector(t, priv, in, want)
}

// No TWC vector exists for TokenTransfer+nonce_account (TWC pins the
// CreateAndTransferToken+nonce combo instead — TestSignSolanaCreateAndTransferTokenDurableNonce).
// The advance-nonce insertion rule is byte-pinned by the two vectors above/below;
// here we anchor by structure: the expected MESSAGE is constructed by hand from
// the decoded-vector layout, and the ed25519 signature must verify over it.
func TestSignSolanaTokenTransferDurableNonceSelfConsistency(t *testing.T) {
	priv := mustHexTx(t, "044014463e2ee3cc9c67a6f191dbac82288eb1d5c1111d21245bdc6a855082a1")
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()
	owner, err := w.PublicKeyIndex(SOL, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}

	const (
		nonceAcct = "ALAaqqt4Cc8hWH22GT2L16xKNAn6gv7XCTF7JkbfWsc"
		source    = "5sS5Z8GAdVHqZKRqEvpDauHvvLgbDveiyfi81uh25mrf"
		dest      = "93hbN3brRjZqRQTT9Xx6rAHVDFZFWD9ragFDXvDbTEjr"
		mint      = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
		nonceVal  = "AaYfEmGQpfJWypZ8MNmBHTep1dwCHVYDRHuZ3gVFiJpY"
	)
	in := &txsolana.SigningInput{
		RecentBlockhash: nonceVal,
		NonceAccount:    nonceAcct,
		TransactionType: &txsolana.SigningInput_TokenTransferTransaction{
			TokenTransferTransaction: &txsolana.TokenTransfer{
				TokenMintAddress:      mint,
				SenderTokenAddress:    source,
				RecipientTokenAddress: dest,
				Amount:                4000,
				Decimals:              6,
			},
		},
	}
	out, err := w.SignTransaction(SOL, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	so := out.(*txsolana.SigningOutput)
	raw := so.GetRaw()
	if len(raw) < 1+64 || raw[0] != 1 {
		t.Fatalf("expected 1-signature tx, got %d bytes header %v", len(raw), raw[0])
	}
	sig, msg := raw[1:65], raw[65:]

	// Hand-built expected message from the pinned ordering rule:
	// keys: [owner, nonce, source, dest, sysvarRecentBlockhashes, mint, system, token]
	// header (1,0,4); instr0 advance [1,4,0] data 04000000;
	// instr1 transferChecked [2,5,3,0] data 0c+LE64(4000)+06.
	k := func(s string) []byte {
		b, err := base58DecodeFixed(s, 32)
		if err != nil {
			t.Fatalf("decode %s: %v", s, err)
		}
		return b
	}
	var want []byte
	want = append(want, 1, 0, 4)
	want = append(want, solanaCompactU16(8)...)
	for _, key := range [][]byte{
		owner, k(nonceAcct), k(source), k(dest),
		k(solanaSysvarRecentBlockhashesID), k(mint),
		solanaSystemProgramID, k(solanaTokenProgramID),
	} {
		want = append(want, key...)
	}
	want = append(want, k(nonceVal)...)
	want = append(want, solanaCompactU16(2)...)
	want = append(want, 6)
	want = append(want, solanaCompactU16(3)...)
	want = append(want, 1, 4, 0)
	want = append(want, solanaCompactU16(4)...)
	want = append(want, 4, 0, 0, 0)
	want = append(want, 7)
	want = append(want, solanaCompactU16(4)...)
	want = append(want, 2, 5, 3, 0)
	want = append(want, solanaCompactU16(10)...)
	want = append(want, 0x0c, 0xa0, 0x0f, 0, 0, 0, 0, 0, 0, 0x06)

	if string(msg) != string(want) {
		t.Fatalf("message mismatch:\n got  %x\n want %x", msg, want)
	}
	if !ed25519.Verify(ed25519.PublicKey(owner), msg, sig) {
		t.Fatal("ed25519 signature does not verify over the message")
	}
}

// TWC test_solana_sign_create_nonce_account (two signatures: payer + the new
// nonce account itself).
func TestSignSolanaCreateNonceAccount(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "mFmK2xFMhzJJaUN5cctfdCizE9dtgcSASSEDh1Yzmat",
		TransactionType: &txsolana.SigningInput_CreateNonceAccount{
			CreateNonceAccount: &txsolana.CreateNonceAccount{
				NonceAccountPrivateKey: mustHexTx(t, "2a9737aca3cde2dc0b4f3ae3487e3a90000490cb39fbc979da32b974ff5d7490"),
				Rent:                   10000000,
			},
		},
	}
	const want = "3wu6xJSbb2NysVgi7pdfMgwVBT1knAdeCr9NR8EktJLoByzM4s9SMto2PPmrnbRqPtHwnpAKxXkC4vqyWY2dRBgdGGCC1bep6qN5nSLVzpPYAWUSq5cd4gfYMAVriFYRRNHmYUnEq8vMn4vjiECmZoHrpabBj8HpXGqYBo87sbZa8ZPCxUcB71hxXiHWZHj2rovx2kr75Uuv1buWXyW6M8uR4UNvQcPPvzVbwBG82RjDYTuancMSAxmrVNR8GLBQNhrCCYrZyte3EWgEyMQxxfW8T3xNXqnbgdfvFJ3UjRBxXj3hrmv17xEivTjfs81aG2AAi24yiYrk8ep7eQqwDHVSArsrynnwVKVNUcCQCnSy7fuiuS7FweFX8DEN1K9BrfecHyWrF15fYzhkmWSs64aH6ZTYHWPv5znhFKYmAuopGwbsBEb2j5p8NS3iJZ2skb2wi47n1rpLZfoCHWKxNiikkDUJTGQNcSDrGUMfeW5aGubJrCfecPKEo9Wo9kd36iSsxYPYSWNKrz2HTooa1rCRhqjXD8dyX3bXGV8TK6W2sEgf4JkcDnNoWQLbindcP8XR"
	signSolanaVector(t, mustHexTx(t, "044014463e2ee3cc9c67a6f191dbac82288eb1d5c1111d21245bdc6a855082a1"), in, want)
}

// TWC test_solana_sign_create_nonce_account_with_durable_nonce (funding a NEW
// nonce account while consuming an EXISTING durable nonce).
func TestSignSolanaCreateNonceAccountDurableNonce(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "E6hvnoXU9QmfWaibMk9NuT6QRZdfzbs96WGc2hhttqXQ",
		NonceAccount:    "ALAaqqt4Cc8hWH22GT2L16xKNAn6gv7XCTF7JkbfWsc",
		TransactionType: &txsolana.SigningInput_CreateNonceAccount{
			CreateNonceAccount: &txsolana.CreateNonceAccount{
				NonceAccountPrivateKey: mustHexTx(t, "2a9737aca3cde2dc0b4f3ae3487e3a90000490cb39fbc979da32b974ff5d7490"),
				Rent:                   10000000,
			},
		},
	}
	const want = "Fr8FzXoH7h6Xo2La6SE49BEPzRX6f93Qn1cFA5E8n6z2GJtZdTU2BfyYGr1zv21Zkq7h68Z3Q96VnFyUVVd1hTWeq6tHDamF1JK5L23yEeUXpEWv1KziWvG9XbxfseHUyWETQck7SY2HbsT4KSjRX9suDaBh68Bu8c96CVN7KtgYPhUrKP62dAMHsf5qo7MESFN8wKJto94ANNCbQMzPmhig9nfiAfvfz9CqV4nbnSiqBGwo2XoyPknDK8RJ1UmA5ptfZ6w6Fy4UmJbQZWuZwpUrkEkfgLMNJ36McHkGAnjpyzq9gMtzb33xSjx1BqnbWXkKJdi8HyQAHTtvtqPz7DMsW9qx5fu3TNz6iC8YHG2HiynFCRjTtc2aH1rpJ9TLdFQEK8WrhdMFr3yW27cg6NB3JUFopUkDg2k5FwtzFyCdfifwebD7eswVNnqjoZxW59fHgY3BrBH8uNst8YAQWvRH77y5L6imVmFhezU5JUb5sF58gR1D8eAQhUcHueakZb5FkFCaMeioTpKrVGgcSNe9zkBMuquoUR3t4MVTiUSLa815qKoBCRmdexQDBt5RQbdQhYyVWn3ovjdhkwDGBU2zywRvottGCcEStQrUrSQDg1tMVKxX5G3sBtxYf"
	signSolanaVector(t, mustHexTx(t, "044014463e2ee3cc9c67a6f191dbac82288eb1d5c1111d21245bdc6a855082a1"), in, want)
}

// TWC test_solana_sign_withdraw_nonce_account.
func TestSignSolanaWithdrawNonceAccount(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "5ccb7sRth3CP8fghmarFycr6VQX3NcfyDJsMFtmdkdU8",
		TransactionType: &txsolana.SigningInput_WithdrawNonceAccount{
			WithdrawNonceAccount: &txsolana.WithdrawNonceAccount{
				NonceAccount: "6vNrYDm6EHcvBALY7HywuDWpTSc6uGt3y2nf5MuG1TmJ",
				Recipient:    "3UVYmECPPMZSCqWKfENfuoTv51fTDTWicX9xmBD2euKe",
				Value:        10000000,
			},
		},
	}
	const want = "7gdEdDymvtfPfVgVvCTPzafmZc1Z8Zu4uXgJDLm8KGpLyPHysxFGjtFzimZDmGtNhQCh22Ygv3ZtPZmSbANbafikR3S1tvujatHW9gMo35jveq7TxwcGoNSqc7tnH85hkEZwnDryVaiKRvtCeH3dgFE9YqPHxiBuZT5eChHJvVNb9iTTdMsJXMusRtzeRV45CvrLKUvsAH7SSWHYW6bGow5TbEJie4buuz2rnbeVG5cxaZ6vyG2nJWHNuDPWZJTRi1MFEwHoxst3a5jQPv9UrG9rNZFCw4uZizVcG6HEqHWgQBu8gVpYpzFCX5SrhjGPZpbK3YmHhUEMEpJx3Fn7jX7Kt4t3hhhrieXppoqKNuqjeNVjfEf3Q8dJRfuVMLdXYbmitCVTPQzYKWBR6ERqWLYoAVqjoAS2pRUw1nrqi1HR"
	signSolanaVector(t, mustHexTx(t, "044014463e2ee3cc9c67a6f191dbac82288eb1d5c1111d21245bdc6a855082a1"), in, want)
}

// TWC test_solana_sign_withdraw_nonce_account_to_self_with_durable_nonce
// (recipient == authority dedup + separate advance nonce).
func TestSignSolanaWithdrawNonceAccountToSelfDurableNonce(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "5EtRPR4sTWRSwNUE5a5SnKB46ZqTJH8vgF1qZFTKGHvw",
		NonceAccount:    "ALAaqqt4Cc8hWH22GT2L16xKNAn6gv7XCTF7JkbfWsc",
		TransactionType: &txsolana.SigningInput_WithdrawNonceAccount{
			WithdrawNonceAccount: &txsolana.WithdrawNonceAccount{
				NonceAccount: "6vNrYDm6EHcvBALY7HywuDWpTSc6uGt3y2nf5MuG1TmJ",
				Recipient:    "sp6VUqq1nDEuU83bU2hstmEYrJNipJYpwS7gZ7Jv7ZH",
				Value:        10000000,
			},
		},
	}
	const want = "3rxbwm6dSX4SbFa7yitVQnoUGWkmRuQtg3V13a2jEAPfZZACCXZX2UFgWFpPqE7KfZSYhd5QE9TLzyikCwcmSBHhKXjMp4oktQXwRT66YaCK8rJdNzBUuS1D9tgHMkLUWKAR7ZRyWd3XvtQhe7nWD6YF6TRGoKPSuwsZAArBxogA7YddmEUKPsr2qjSKbjg7X5BbNceFwjEFAiafuizdSt7eGJHB5m9zJeYct8LCanTwJwyEVu1T9HTsgjW9hqHehqhCiHP46KGo63o7WAoappZvM4EJZemu4GfM6F6H48bPXF2z1QJz17wE6BYeMXfXuGkCRt5jYxrjdKuqvTDYV34X1HjZYUdrkW6mQotWDY3bS6zyAt784Vwzk2uiA8ytmWMbC24coUVwPSPGwZ92WJ6BpVCCtGDxLzp4CkahRu78UNWzdcEwPG6AUf"
	signSolanaVector(t, mustHexTx(t, "044014463e2ee3cc9c67a6f191dbac82288eb1d5c1111d21245bdc6a855082a1"), in, want)
}

// TWC test_solana_sign_advance_nonce_account (standalone nonce refresh).
func TestSignSolanaAdvanceNonceAccount(t *testing.T) {
	in := &txsolana.SigningInput{
		RecentBlockhash: "4KQLRUfd7GEVXxAeDqwtuGTdwKd9zMfPycyAG3wJsdck",
		TransactionType: &txsolana.SigningInput_AdvanceNonceAccount{
			AdvanceNonceAccount: &txsolana.AdvanceNonceAccount{
				NonceAccount: "6vNrYDm6EHcvBALY7HywuDWpTSc6uGt3y2nf5MuG1TmJ",
			},
		},
	}
	const want = "7YPgNzjCnUd2zBb6ZC6bf1YaoLjhJPHixLUdTjqMjq1YdzADJCx2wsTTBFFrqDKSHXEL6ntRq8NVJTQMGzGH5AQRKwtKtutehxesmtzkZCPY9ADZ4ijFyveLmTt7kjZXX7ZWVoUmKAqiaYsPTex728uMBSRJpV4zRw2yKGdQRHTKy2QFEb9acwLjmrbEgoyzPCarxjPhw21QZnNcy8RiYJB2mzZ9nvhrD5d2jB5TtdiroQPgTSdKFzkNEd7hJUKpqUppjDFcNHGK73FE9pCP2dKxCLH8Wfaez8bLtopjmWun9cbikxo7LZsarYzMXvxwZmerRd1"
	signSolanaVector(t, mustB58Priv(t, "9YtuoD4sH4h88CVM8DSnkfoAaLY7YeGC2TarDJ8eyMS5"), in, want)
}
