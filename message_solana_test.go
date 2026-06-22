package hdwallet

import "testing"

// Trust Wallet Core SolanaMessageSigner vector
// (tests/chains/Solana/SolanaMessageSigner.cpp): signing the UTF-8 message
// "Hello world" with the given ed25519 key yields this exact base58 signature.
func TestSignSolanaMessageVector(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "44f480ca27711895586074a14c552e58cc52e66a58edb6c58cf9b9b7295d4a2d"),
		Ed25519,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	const want = "2iBZ6zrQRKHcbD8NWmm552gU5vGvh1dk3XV4jxnyEdRKm8up8AeQk1GFr9pJokSmchw7i9gMtNyFBdDt8tBxM1cG"
	got, err := w.SignSolanaMessage(SOL, 0, []byte("Hello world"))
	if err != nil {
		t.Fatalf("SignSolanaMessage: %v", err)
	}
	if got != want {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", got, want)
	}

	// Round-trip verify against the derived address.
	addr, err := w.Address(SOL)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySolanaMessage(addr, []byte("Hello world"), got) {
		t.Error("VerifySolanaMessage rejected a valid signature")
	}
	if VerifySolanaMessage(addr, []byte("tampered"), got) {
		t.Error("VerifySolanaMessage accepted a wrong message")
	}
}
