package hdwallet

import (
	"encoding/hex"
	"strings"
	"testing"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// Injective (eth_secp256k1) Cosmos direct-mode bank MsgSend signing, verified
// byte-for-byte against Trust Wallet Core's Injective vector
// (android/app/src/androidTest/java/com/trustwallet/core/app/blockchains/
// nativeinjective/TestNativeInjectiveSigner.kt — the canonical TWC AnySigner
// SignDirect test for chain TWCoinTypeNativeInjective).
//
// Injective differs from Evmos in two signed-byte–affecting ways beyond the
// shared keccak256(SignDoc) digest: it announces the signer key under
// "/injective.crypto.v1beta1.ethsecp256k1.PubKey" (not the ethermint URL) AND it
// announces the key UNCOMPRESSED (0x04‖X‖Y, 65 bytes) rather than compressed.
// Either difference changes the SignDoc and therefore the signature, so this test
// asserts the full serialized tx and the signature byte-for-byte.
func TestSignTxInjectiveEthermintMsgSend(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "9ee18daf8e463877aaf497282abc216852420101430482a28e246c179e2c5ef1"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txcosmos.SigningInput{
		AccountNumber: 17396,
		ChainId:       "injective-1",
		Sequence:      1,
		Memo:          "",
		Fee: &txcosmos.Fee{
			Amount: "100000000000000",
			Denom:  "inj",
			Gas:    110000,
		},
		Send: &txcosmos.SendCoinsMessage{
			FromAddress: "inj13u6g7vqgw074mgmf2ze2cadzvkz9snlwcrtq8a",
			ToAddress:   "inj1xmpkmxr4as00em23tc2zgmuyy2gr4h3wgcl6vd",
			Amount:      "10000000000",
			Denom:       "inj",
		},
	}

	const (
		// Authoritative TWC anchors. wantTxBytes is the SignDirect output's
		// tx_bytes (the serialized TxRaw, base64); wantSig is its 64-byte r||s
		// secp256k1 signature. The serialized tx embeds the signer's UNCOMPRESSED
		// pubkey (045a0c6b83...) under the Injective ethsecp256k1 type URL; a
		// deterministic ECDSA signature commits to the whole SignDoc, so the
		// signature match proves these are TWC's exact bytes.
		wantTxBytes = "Co8BCowBChwvY29zbW9zLmJhbmsudjFiZXRhMS5Nc2dTZW5kEmwKKmluajEzdTZnN3ZxZ3cwNzRtZ21mMnplMmNhZHp2a3o5c25sd2NydHE4YRIqaW5qMXhtcGtteHI0YXMwMGVtMjN0YzJ6Z211eXkyZ3I0aDN3Z2NsNnZkGhIKA2luahILMTAwMDAwMDAwMDASngEKfgp0Ci0vaW5qZWN0aXZlLmNyeXB0by52MWJldGExLmV0aHNlY3AyNTZrMS5QdWJLZXkSQwpBBFoMa4O4vZgn5QcnDK20mbfjqQlSRvaiITKB94PYd8mLJWdCdBsGOfMXdo/k9MJ2JmDCESKDp2hdgVUH3uMikXMSBAoCCAEYARIcChYKA2luahIPMTAwMDAwMDAwMDAwMDAwELDbBhpAx2vkplmzeK7n3puCFGPWhLd0l/ZC/CYkGl+stH+3S3hiCvIe7uwwMpUlNaSwvT8HwF1kNUp+Sx2m0Uo1x5xcFw=="
		wantSig     = "c76be4a659b378aee7de9b821463d684b77497f642fc26241a5facb47fb74b78620af21eeeec3032952535a4b0bd3f07c05d64354a7e4b1da6d14a35c79c5c17"
	)

	out, err := w.SignTransaction(INJ, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	co, ok := out.(*txcosmos.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *cosmos.SigningOutput", out)
	}
	if co.GetError() != "" {
		t.Fatalf("signing error: %s", co.GetError())
	}
	if got := hex.EncodeToString(co.GetSignature()); got != wantSig {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", got, wantSig)
	}
	if co.GetTxBytes() != wantTxBytes {
		t.Fatalf("tx_bytes mismatch:\n got  %s\n want %s", co.GetTxBytes(), wantTxBytes)
	}
	// tx_id is the Cosmos tx hash (same formula for Ethermint chains): upper-case
	// hex of sha256 over the (locked) TxRaw bytes.
	wantTxID := strings.ToUpper(hex.EncodeToString(sha256Sum(co.GetEncoded())))
	if co.GetTxId() != wantTxID {
		t.Fatalf("tx_id mismatch:\n got  %s\n want %s", co.GetTxId(), wantTxID)
	}
}
