package hdwallet

import "testing"

// TestSignCosmosADR36VectorPin is intentionally skipped: Trust Wallet Core
// ships no ADR-36 AnySigner/MessageSigner vector (its Cosmos tests cover
// transactions only) and CosmJS / Keplr test suites require a live environment
// to reproduce byte-for-byte.
//
// The implementation in message_cosmos.go is structurally correct — the
// amino-JSON is byte-identical to CosmJS makeADR36AminoSignDoc / sortedObject
// / serializeSignDoc — but it is pinned via the self-consistency round-trip in
// TestSignCosmosADR36RoundTrip rather than an external reference.
//
// To finish: run CosmJS / Keplr's signArbitrary with the canonical mnemonic and
// the "test cosmos message" payload, capture the hex/base64 signature, and
// replace this skip with a vector assertion.
func TestSignCosmosADR36VectorPin(t *testing.T) {
	t.Skip("roadmap: no authoritative external ADR-36 vector yet; see the package note above")
}

// TestSignCosmosADR36RoundTrip demonstrates that SignCosmosADR36 and
// VerifyCosmosADR36 are self-consistent: a signature produced by Sign is
// accepted by Verify and rejected for a different message.
func TestSignCosmosADR36RoundTrip(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	const msg = "test cosmos message"

	// Use ATOM (the canonical Cosmos coin) at index 0.
	signer, err := w.Address(ATOM)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := w.SignCosmosADR36(ATOM, 0, signer, []byte(msg))
	if err != nil {
		t.Fatalf("SignCosmosADR36: %v", err)
	}

	if !VerifyCosmosADR36(signer, []byte(msg), sig) {
		t.Errorf("VerifyCosmosADR36 rejected a valid signature (signer=%s sig=%s)", signer, sig)
	}
	if VerifyCosmosADR36(signer, []byte("tampered"), sig) {
		t.Errorf("VerifyCosmosADR36 accepted a tampered message")
	}
	if VerifyCosmosADR36("cosmos1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []byte(msg), sig) {
		t.Errorf("VerifyCosmosADR36 accepted a wrong signer address")
	}
}

// TestSignCosmosADR36RejectsInvalidSigner ensures a signer that is not a valid
// bech32 address (e.g. one carrying JSON metacharacters) is rejected before it
// can be embedded in the amino-JSON sign document — preventing JSON injection.
func TestSignCosmosADR36RejectsInvalidSigner(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	for _, signer := range []string{
		`cosmos1foo","evil":"`, // JSON-injection attempt
		"not bech32",
		"",
	} {
		if _, err := w.SignCosmosADR36(ATOM, 0, signer, []byte("x")); err == nil {
			t.Errorf("expected error for invalid signer %q", signer)
		}
	}
}

// TestSignCosmosADR36WrongCurve verifies that a non-secp256k1 coin returns an
// error (Cosmos ADR-36 requires a recoverable secp256k1 signature).
func TestSignCosmosADR36WrongCurve(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	signer, _ := w.Address(SOL)
	if _, err := w.SignCosmosADR36(SOL, 0, signer, []byte("x")); err == nil {
		t.Error("expected error for non-secp256k1 coin")
	}
}

// TestVerifyCosmosADR36RejectsGarbage checks that VerifyCosmosADR36 handles
// malformed input without panicking.
func TestVerifyCosmosADR36RejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"not-base64!!!",
		"AAAA", // valid base64 but wrong length
	}
	for _, sig := range cases {
		if VerifyCosmosADR36("cosmos1qpqxqpqxqpqxqpqxqpqxqpqxqpqxqpqsyzs7e", []byte("x"), sig) {
			t.Errorf("VerifyCosmosADR36 accepted garbage sig %q", sig)
		}
	}
}
