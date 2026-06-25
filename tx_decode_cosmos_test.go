package hdwallet

import (
	"testing"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// "What am I signing?" Cosmos decoder, proven by:
//   - round-trip: sign a TxRaw with the EXISTING signer (SignTransaction) and
//     assert DecodeCosmosTx recovers the same message fields, fee, gas, sequence,
//     memo and a 64-byte signature;
//   - a delegate round-trip to exercise the staking-message decode branch;
//   - malformed: truncated/garbage bytes return ErrTxDecode, never a panic.

// TestDecodeCosmosRoundTripMsgSend signs the TWC Cosmos MsgSend vector input and
// asserts the decoder reverses every surfaced field.
func TestDecodeCosmosRoundTripMsgSend(t *testing.T) {
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
		Sequence:      8,
		Fee: &txcosmos.Fee{
			Amount: "200",
			Denom:  "muon",
			Gas:    200000,
		},
		Send: &txcosmos.SendCoinsMessage{
			FromAddress: "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02",
			ToAddress:   "cosmos1zt50azupanqlfam5afhv3hexwyutnukeh4c573",
			Amount:      "1",
			Denom:       "muon",
		},
	}

	out, err := w.SignTransaction(ATOM, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	encoded := out.(*txcosmos.SigningOutput).GetEncoded()

	f, err := DecodeCosmosTx(encoded)
	if err != nil {
		t.Fatalf("DecodeCosmosTx: %v", err)
	}
	if len(f.Messages) != 1 {
		t.Fatalf("messages len = %d, want 1", len(f.Messages))
	}
	m := f.Messages[0]
	if m.TypeURL != cosmosMsgSendTypeURL {
		t.Fatalf("type_url = %s, want %s", m.TypeURL, cosmosMsgSendTypeURL)
	}
	if m.FromAddress != in.Send.FromAddress || m.ToAddress != in.Send.ToAddress {
		t.Fatalf("from/to = %s / %s", m.FromAddress, m.ToAddress)
	}
	if len(m.Amount) != 1 || m.Amount[0].Denom != "muon" || m.Amount[0].Amount != "1" {
		t.Fatalf("msg amount = %+v, want [{muon 1}]", m.Amount)
	}
	if len(f.FeeAmount) != 1 || f.FeeAmount[0].Denom != "muon" || f.FeeAmount[0].Amount != "200" {
		t.Fatalf("fee amount = %+v, want [{muon 200}]", f.FeeAmount)
	}
	if f.GasLimit != 200000 {
		t.Fatalf("gas = %d, want 200000", f.GasLimit)
	}
	if f.Sequence != 8 {
		t.Fatalf("sequence = %d, want 8", f.Sequence)
	}
	if f.Memo != "" {
		t.Fatalf("memo = %q, want empty", f.Memo)
	}
	if len(f.Signatures) != 1 || len(f.Signatures[0]) != 64 {
		t.Fatalf("signatures = %d entries (first len %d), want 1 of 64", len(f.Signatures), sigLen(f.Signatures))
	}
}

// TestDecodeCosmosRoundTripDelegate signs a MsgDelegate (via the repeated
// Messages set) and asserts the staking decode branch surfaces delegator,
// validator and the staked coin.
func TestDecodeCosmosRoundTripDelegate(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "80e81ea269e66a0a05b11236df7919fb7fbeedba87452d667489d7403a02f005"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	const (
		delegator = "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02"
		validator = "cosmosvaloper1zt50azupanqlfam5afhv3hexwyutnukeh4c573"
	)
	in := &txcosmos.SigningInput{
		AccountNumber: 1,
		ChainId:       "cosmoshub-4",
		Sequence:      2,
		Memo:          "stake",
		Fee:           &txcosmos.Fee{Amount: "1000", Denom: "uatom", Gas: 250000},
		Messages: []*txcosmos.Message{{
			MessageOneof: &txcosmos.Message_Delegate{Delegate: &txcosmos.MsgDelegate{
				DelegatorAddress: delegator,
				ValidatorAddress: validator,
				Amount:           "5000",
				Denom:            "uatom",
			}},
		}},
	}

	out, err := w.SignTransaction(ATOM, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	f, err := DecodeCosmosTx(out.(*txcosmos.SigningOutput).GetEncoded())
	if err != nil {
		t.Fatalf("DecodeCosmosTx: %v", err)
	}
	if len(f.Messages) != 1 {
		t.Fatalf("messages len = %d, want 1", len(f.Messages))
	}
	m := f.Messages[0]
	if m.TypeURL != cosmosMsgDelegateTypeURL {
		t.Fatalf("type_url = %s, want %s", m.TypeURL, cosmosMsgDelegateTypeURL)
	}
	if m.DelegatorAddress != delegator || m.ValidatorAddress != validator {
		t.Fatalf("delegator/validator = %s / %s", m.DelegatorAddress, m.ValidatorAddress)
	}
	if len(m.Amount) != 1 || m.Amount[0].Denom != "uatom" || m.Amount[0].Amount != "5000" {
		t.Fatalf("staked coin = %+v, want [{uatom 5000}]", m.Amount)
	}
	if f.Memo != "stake" {
		t.Fatalf("memo = %q, want stake", f.Memo)
	}
	if f.Sequence != 2 || f.GasLimit != 250000 {
		t.Fatalf("sequence/gas = %d / %d, want 2 / 250000", f.Sequence, f.GasLimit)
	}
}

// TestDecodeCosmosMalformed asserts truncated / garbage input returns an error
// (never a panic).
func TestDecodeCosmosMalformed(t *testing.T) {
	w, _ := FromPrivateKeyBytes(
		mustHexTx(t, "80e81ea269e66a0a05b11236df7919fb7fbeedba87452d667489d7403a02f005"),
		Secp256k1,
	)
	defer w.Destroy()
	in := &txcosmos.SigningInput{
		ChainId: "gaia-13003",
		Fee:     &txcosmos.Fee{Amount: "200", Denom: "muon", Gas: 200000},
		Send: &txcosmos.SendCoinsMessage{
			FromAddress: "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02",
			ToAddress:   "cosmos1zt50azupanqlfam5afhv3hexwyutnukeh4c573",
			Amount:      "1",
			Denom:       "muon",
		},
	}
	out, _ := w.SignTransaction(ATOM, 0, in)
	full := out.(*txcosmos.SigningOutput).GetEncoded()

	cases := map[string][]byte{
		"empty":            {},
		"truncated body":   full[:5],
		"truncated middle": full[:len(full)/2],
		"bad tag":          {0xff, 0xff, 0xff},
		"length overrun":   {0x0a, 0x7f}, // field 1 bytes, claims 127 bytes, none follow
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCosmosTx(b); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}

// sigLen returns the length of the first signature, or -1 if none, for clearer
// test failure messages.
func sigLen(sigs [][]byte) int {
	if len(sigs) == 0 {
		return -1
	}
	return len(sigs[0])
}
