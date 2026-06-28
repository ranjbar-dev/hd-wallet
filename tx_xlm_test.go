package hdwallet

import (
	"encoding/hex"
	"testing"

	txstellar "github.com/ranjbar-dev/hd-wallet/txproto/stellar"
)

// Stellar (XLM) transaction signing — vector-pinned test.
//
// Source: Trust Wallet Core TransactionTests.cpp, test "sign".
// https://github.com/trustwallet/wallet-core/blob/master/tests/chains/Stellar/TransactionTests.cpp
//
// The private key below is derived from mnemonic
// "indicate rival expand cave giant same grocery burden ugly rose tuna blood"
// at TWC Stellar path m/44'/148'/0'. We test via FromPrivateKeyBytes to isolate
// the signing logic from HD derivation (the SLIP-0010/BIP-39 path for XLM is
// covered by the address encoder tests).
//
// Wire summary:
//   - XDR-encoded TransactionEnvelope (ENVELOPE_TYPE_TX_V0 = 0; outer discriminant)
//   - networkId = SHA256("Public Global Stellar Network ; September 2015")
//   - sigHash   = SHA256(networkId || uint32(2) || uint32(0) || XDR(TransactionV0Body))
//     (uint32(2)=ENVELOPE_TYPE_TX preimage tag; uint32(0)=KEY_TYPE_ED25519 discriminant
//     inserted between the type tag and the V0 body in the preimage — TWC quirk; the
//     output envelope stays V0 with raw uint256 source account, no MuxedAccount header)
//   - ed25519 signs the 32-byte sigHash (raw message, hashed internally by ed25519)
//   - Output: base64(XDR(TransactionEnvelope))

// xlmTestPrivKey is the ed25519 private key seed for TWC's Stellar test vector.
// Derived from mnemonic "indicate rival expand cave giant same grocery burden ugly rose tuna blood"
// at path m/44'/148'/0'.
var xlmTestPrivKey, _ = hex.DecodeString("59a313f46ef1c23a9e4f71cea10fc0c56a2a6bb8a4b9ea3d5348823e5a478722")

// TestSignTxXLM pins the Stellar payment signer byte-for-byte to the TWC vector.
func TestSignTxXLM(t *testing.T) {
	w, err := FromPrivateKeyBytes(xlmTestPrivKey, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txstellar.SigningInput{
		Account:    "GAE2SZV4VLGBAPRYRFV2VY7YYLYGYIP5I7OU7BSP6DJT7GAZ35OKFDYI",
		Fee:        1000,
		Sequence:   2,
		Passphrase: "", // empty → mainnet default
		Operation: &txstellar.SigningInput_Payment{
			Payment: &txstellar.PaymentOp{
				Destination: "GDCYBNRRPIHLHG7X7TKPUPAZ7WVUXCN3VO7WCCK64RIFV5XM5V5K4A52",
				Amount:      10_000_000,
			},
		},
	}

	out, err := w.SignTransaction(XLM, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	got, ok := out.(*txstellar.SigningOutput)
	if !ok {
		t.Fatalf("expected *stellar.SigningOutput, got %T", out)
	}
	if got.Error != "" {
		t.Fatalf("signing error: %s", got.Error)
	}

	// Expected: TWC TransactionTests.cpp "sign" test assertion.
	const wantEncoded = "AAAAAAmpZryqzBA+OIlrquP4wvBsIf1H3U+GT/DTP5gZ31yiAAAD6AAAAAAAAAACAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAxYC2MXoOs5v3/NT6PBn9q0uJu6u/YQle5FBa9uzteq4AAAAAAAAAAACYloAAAAAAAAAAARnfXKIAAABAocQZwTnVvGMQlpdGacWvgenxN5ku8YB8yhEGrDfEV48yDqcj6QaePAitDj/N2gxfYD9Q2pJ+ZpkQMsZZG4ACAg=="
	if got.Encoded != wantEncoded {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantEncoded)
	}
}

// TestSignTxXLMNilInput verifies that a nil input returns an error (not a panic).
func TestSignTxXLMNilInput(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()

	_, err := w.SignTransaction(XLM, 0, nil)
	if err == nil {
		t.Fatal("expected error for nil input, got nil")
	}
}
