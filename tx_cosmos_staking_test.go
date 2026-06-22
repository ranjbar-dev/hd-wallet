package hdwallet

import (
	"encoding/hex"
	"testing"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// TestSignTxCosmosDelegate verifies a staking MsgDelegate (direct mode) against
// Trust Wallet Core's Cosmos StakingTests vector. The expected tx_bytes and
// signature pin the staking Any type_url, the MsgDelegate serialization, and the
// secp256k1-over-sha256 signature.
func TestSignTxCosmosDelegate(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "80e81ea269e66a0a05b11236df7919fb7fbeedba87452d667489d7403a02f005"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txcosmos.SigningInput{
		AccountNumber: 1037,
		ChainId:       "gaia-13003",
		Sequence:      7,
		Fee:           &txcosmos.Fee{Amount: "1018", Denom: "muon", Gas: 101721},
		Messages: []*txcosmos.Message{
			{MessageOneof: &txcosmos.Message_Delegate{Delegate: &txcosmos.MsgDelegate{
				DelegatorAddress: "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02",
				ValidatorAddress: "cosmosvaloper1zkupr83hrzkn3up5elktzcq3tuft8nxsmwdqgp",
				Amount:           "10",
				Denom:            "muon",
			}}},
		},
	}

	const (
		wantTxBytes = "CpsBCpgBCiMvY29zbW9zLnN0YWtpbmcudjFiZXRhMS5Nc2dEZWxlZ2F0ZRJxCi1jb3Ntb3MxaHNrNmpyeXlxamZocDVkaGM1NXRjOWp0Y2t5Z3gwZXBoNmRkMDISNGNvc21vc3ZhbG9wZXIxemt1cHI4M2hyemtuM3VwNWVsa3R6Y3EzdHVmdDhueHNtd2RxZ3AaCgoEbXVvbhICMTASZgpQCkYKHy9jb3Ntb3MuY3J5cHRvLnNlY3AyNTZrMS5QdWJLZXkSIwohAlcobsPzfTNVe7uqAAsndErJAjqplnyudaGB0f+R+p3FEgQKAggBGAcSEgoMCgRtdW9uEgQxMDE4ENmaBhpA8O9Jm/kL6Za2I3poDs5vpMowYJgNvYCJBRU/vxAjs0lNZYsq40qpTbwOTbORjJA5UjQ6auc40v6uCFT4q4z+uA=="
		wantSig     = "f0ef499bf90be996b6237a680ece6fa4ca3060980dbd808905153fbf1023b3494d658b2ae34aa94dbc0e4db3918c903952343a6ae738d2feae0854f8ab8cfeb8"
	)

	out, err := w.SignTransaction(ATOM, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	co := out.(*txcosmos.SigningOutput)
	if co.GetError() != "" {
		t.Fatalf("signing error: %s", co.GetError())
	}
	if got := hex.EncodeToString(co.GetSignature()); got != wantSig {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", got, wantSig)
	}
	if co.GetTxBytes() != wantTxBytes {
		t.Fatalf("tx_bytes mismatch:\n got  %s\n want %s", co.GetTxBytes(), wantTxBytes)
	}
}

// TestSignTxCosmosSendBackCompat confirms the new `messages` path produces the
// same bytes as the legacy single `send` field for a bank MsgSend (the original
// TWC MsgSend vector), so the refactor preserved back-compat.
func TestSignTxCosmosSendBackCompat(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "80e81ea269e66a0a05b11236df7919fb7fbeedba87452d667489d7403a02f005"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	base := func() *txcosmos.SigningInput {
		return &txcosmos.SigningInput{
			AccountNumber: 1037,
			ChainId:       "gaia-13003",
			Sequence:      8,
			Fee:           &txcosmos.Fee{Amount: "200", Denom: "muon", Gas: 200000},
		}
	}
	send := &txcosmos.SendCoinsMessage{
		FromAddress: "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02",
		ToAddress:   "cosmos1zt50azupanqlfam5afhv3hexwyutnukeh4c573",
		Amount:      "1",
		Denom:       "muon",
	}

	legacy := base()
	legacy.Send = send
	viaMessages := base()
	viaMessages.Messages = []*txcosmos.Message{{MessageOneof: &txcosmos.Message_Send{Send: send}}}

	outLegacy, err := w.SignTransaction(ATOM, 0, legacy)
	if err != nil {
		t.Fatalf("legacy SignTransaction: %v", err)
	}
	outMsgs, err := w.SignTransaction(ATOM, 0, viaMessages)
	if err != nil {
		t.Fatalf("messages SignTransaction: %v", err)
	}
	if outLegacy.(*txcosmos.SigningOutput).GetTxBytes() != outMsgs.(*txcosmos.SigningOutput).GetTxBytes() {
		t.Fatalf("messages path differs from legacy send path")
	}
}
