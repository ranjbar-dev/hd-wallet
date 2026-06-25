package hdwallet

import (
	"encoding/hex"
	"strings"
	"testing"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// Ethermint (eth_secp256k1) Cosmos direct-mode bank MsgSend signing, verified
// byte-for-byte against Trust Wallet Core's Evmos vector
// (tests/chains/Evmos/TransactionCompilerTests.cpp). Unlike a standard Cosmos tx,
// the SignDoc is hashed with keccak256 and the pubkey is announced under
// "/ethermint.crypto.v1.ethsecp256k1.PubKey"; any wrong byte (type URL or digest)
// changes the signature. The expected preimage hash for these inputs is
// keccak256(SignDoc) = 9912eb629e215027b8d587939b1af72a9f70ae326bcaf48dfe77a729fc4ac632.
func TestSignTxEvmosEthermintMsgSend(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "727513ec3c54eb6fae24f2ff756bbc4c89b82945c6538bbd173613ae3de719d3"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txcosmos.SigningInput{
		AccountNumber: 106619981,
		ChainId:       "evmos_9001-2",
		Sequence:      0,
		Memo:          "",
		Fee: &txcosmos.Fee{
			Amount: "5513600000000000",
			Denom:  "aevmos",
			Gas:    137840,
		},
		Send: &txcosmos.SendCoinsMessage{
			FromAddress: "evmos1d0jkrsd09c7pule43y3ylrul43lwwcqa7vpy0g",
			ToAddress:   "evmos17dh3frt0m6kdd3m9lr6e6sr5zz0rz8cvxd7u5t",
			Amount:      "10000000000000000",
			Denom:       "aevmos",
		},
	}

	const (
		// NOTE: the signature below is the authoritative Trust Wallet Core anchor and
		// is asserted byte-for-byte. wantTxBytes is the same vector's serialized tx;
		// it embeds the signer's compressed pubkey (02088ac291..., independently
		// confirmed via btcec for this private key). A deterministic ECDSA signature
		// commits to the whole SignDoc, so the signature match proves these bytes are
		// TWC's exact output. (The pubkey's 3rd byte is 0x8a — an earlier source
		// transcription that read it as 0x82 was a one-char artifact, ruled out by the
		// signature + the independent btcec derivation.)
		wantTxBytes = "CpwBCpkBChwvY29zbW9zLmJhbmsudjFiZXRhMS5Nc2dTZW5kEnkKLGV2bW9zMWQwamtyc2QwOWM3cHVsZTQzeTN5bHJ1bDQzbHd3Y3FhN3ZweTBnEixldm1vczE3ZGgzZnJ0MG02a2RkM205bHI2ZTZzcjV6ejByejhjdnhkN3U1dBobCgZhZXZtb3MSETEwMDAwMDAwMDAwMDAwMDAwEnsKVwpPCigvZXRoZXJtaW50LmNyeXB0by52MS5ldGhzZWNwMjU2azEuUHViS2V5EiMKIQIIisKRmYfZJzaMsr4q3kTNDtNhZ0WpaZyuJks/xafDYBIECgIIARIgChoKBmFldm1vcxIQNTUxMzYwMDAwMDAwMDAwMBDwtAgaQKrmMaaSKnohf3ahyCOYdRJKBKJjr4WkkA/cbn6FRdF0Gd6FHSzBP8S4v4VNiy3KC47TD0C+sUBO413gCzjo8/U="
		wantSig     = "aae631a6922a7a217f76a1c8239875124a04a263af85a4900fdc6e7e8545d17419de851d2cc13fc4b8bf854d8b2dca0b8ed30f40beb1404ee35de00b38e8f3f5"
	)

	out, err := w.SignTransaction(EVMOS, 0, in)
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
