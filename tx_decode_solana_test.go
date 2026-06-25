package hdwallet

import (
	"bytes"
	"testing"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// "What am I signing?" Solana decoder, proven by:
//   - round-trip: sign the TWC Solana transfer vector with the EXISTING signer and
//     assert DecodeSolanaTx recovers the header, account keys, blockhash and the
//     decoded system-transfer lamports;
//   - an SPL TransferChecked round-trip to exercise the token-transfer branch;
//   - malformed: truncated/garbage bytes return ErrTxDecode, never a panic.

const solSystemProgramB58 = "11111111111111111111111111111111"

func solanaTestWallet(t *testing.T) *HDWallet {
	t.Helper()
	priv, err := base58Decode(base58BTC, "A7psj2GW7ZMdY4E5hJq14KMeYg7HFjULSsWSrTXZLvYr")
	if err != nil {
		t.Fatalf("base58 decode private key: %v", err)
	}
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	return w
}

func TestDecodeSolanaRoundTripTransfer(t *testing.T) {
	w := solanaTestWallet(t)
	defer w.Destroy()

	const recipient = "EN2sCsJ1WDV8UFqsiTXHcUPUxQ4juE71eCknHYYMifkd"
	in := &txsolana.SigningInput{
		RecentBlockhash: solSystemProgramB58,
		TransactionType: &txsolana.SigningInput_TransferTransaction{
			TransferTransaction: &txsolana.Transfer{
				Recipient: recipient,
				Value:     42,
			},
		},
	}

	out, err := w.SignTransaction(SOL, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	raw := out.(*txsolana.SigningOutput).GetRaw()

	f, err := DecodeSolanaTx(raw)
	if err != nil {
		t.Fatalf("DecodeSolanaTx: %v", err)
	}
	if len(f.Signatures) != 1 || len(f.Signatures[0]) != 64 {
		t.Fatalf("signatures = %d entries", len(f.Signatures))
	}
	if f.NumRequiredSignatures != 1 || f.NumReadonlySigned != 0 || f.NumReadonlyUnsigned != 1 {
		t.Fatalf("header = %d/%d/%d, want 1/0/1", f.NumRequiredSignatures, f.NumReadonlySigned, f.NumReadonlyUnsigned)
	}
	sender, _ := w.Address(SOL)
	wantKeys := []string{sender, recipient, solSystemProgramB58}
	if len(f.AccountKeys) != 3 {
		t.Fatalf("account keys = %d, want 3", len(f.AccountKeys))
	}
	for i, k := range wantKeys {
		if f.AccountKeys[i] != k {
			t.Fatalf("account key[%d] = %s, want %s", i, f.AccountKeys[i], k)
		}
	}
	if f.RecentBlockhash != solSystemProgramB58 {
		t.Fatalf("blockhash = %s", f.RecentBlockhash)
	}
	if len(f.Instructions) != 1 {
		t.Fatalf("instructions = %d, want 1", len(f.Instructions))
	}
	ins := f.Instructions[0]
	if ins.Type != "systemTransfer" || ins.Lamports != 42 {
		t.Fatalf("instruction = %s lamports %d, want systemTransfer 42", ins.Type, ins.Lamports)
	}
	if ins.ProgramID != solSystemProgramB58 {
		t.Fatalf("program id = %s, want system program", ins.ProgramID)
	}
}

func TestDecodeSolanaRoundTripTokenTransfer(t *testing.T) {
	w := solanaTestWallet(t)
	defer w.Destroy()

	sender := base58Encode(base58BTC, bytes.Repeat([]byte{0x11}, 32))
	recipient := base58Encode(base58BTC, bytes.Repeat([]byte{0x22}, 32))
	mint := base58Encode(base58BTC, bytes.Repeat([]byte{0x33}, 32))

	in := &txsolana.SigningInput{
		RecentBlockhash: solSystemProgramB58,
		TransactionType: &txsolana.SigningInput_TokenTransferTransaction{
			TokenTransferTransaction: &txsolana.TokenTransfer{
				TokenMintAddress:      mint,
				SenderTokenAddress:    sender,
				RecipientTokenAddress: recipient,
				Amount:                12345,
				Decimals:              6,
			},
		},
	}

	out, err := w.SignTransaction(SOL, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	f, err := DecodeSolanaTx(out.(*txsolana.SigningOutput).GetRaw())
	if err != nil {
		t.Fatalf("DecodeSolanaTx: %v", err)
	}
	// Account order: owner, source, dest, mint, token program => header (1,0,2).
	if f.NumRequiredSignatures != 1 || f.NumReadonlyUnsigned != 2 {
		t.Fatalf("header = %d/%d/%d", f.NumRequiredSignatures, f.NumReadonlySigned, f.NumReadonlyUnsigned)
	}
	if len(f.AccountKeys) != 5 || f.AccountKeys[1] != sender || f.AccountKeys[2] != recipient || f.AccountKeys[3] != mint {
		t.Fatalf("account keys = %v", f.AccountKeys)
	}
	if len(f.Instructions) != 1 {
		t.Fatalf("instructions = %d, want 1", len(f.Instructions))
	}
	ins := f.Instructions[0]
	if ins.Type != "tokenTransferChecked" || ins.Amount != 12345 || ins.Decimals != 6 {
		t.Fatalf("instruction = %s amount %d decimals %d, want tokenTransferChecked 12345 6", ins.Type, ins.Amount, ins.Decimals)
	}
	if ins.ProgramID != solanaTokenProgramID {
		t.Fatalf("program id = %s, want token program", ins.ProgramID)
	}
}

func TestDecodeSolanaMalformed(t *testing.T) {
	w := solanaTestWallet(t)
	defer w.Destroy()
	in := &txsolana.SigningInput{
		RecentBlockhash: solSystemProgramB58,
		TransactionType: &txsolana.SigningInput_TransferTransaction{
			TransferTransaction: &txsolana.Transfer{Recipient: "EN2sCsJ1WDV8UFqsiTXHcUPUxQ4juE71eCknHYYMifkd", Value: 42},
		},
	}
	out, _ := w.SignTransaction(SOL, 0, in)
	full := out.(*txsolana.SigningOutput).GetRaw()

	cases := map[string][]byte{
		"empty":              {},
		"truncated sig":      full[:10],
		"truncated message":  full[:70],
		"trailing garbage":   append(append([]byte(nil), full...), 0xff),
		"huge sig count":     {0xff, 0xff, 0x03},
		"missing instr body": full[:len(full)-5],
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSolanaTx(b); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}
