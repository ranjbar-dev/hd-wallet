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
