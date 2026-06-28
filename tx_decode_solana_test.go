package hdwallet

import (
	"bytes"
	"encoding/binary"
	"testing"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// "What am I signing?" Solana decoder, proven by:
//   - round-trip: sign the TWC Solana transfer vector with the EXISTING signer
//     and assert DecodeSolanaTx recovers the header, account keys, blockhash and
//     the decoded system-transfer lamports;
//   - SPL TransferChecked round-trip: exercises the token-transfer branch and
//     verifies SourceToken/TokenMint/DestToken account resolution;
//   - Compute Budget: manually constructed tx asserts SetComputeUnitLimit decoding;
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
	if ins.Kind != SolanaInstructionSystemTransfer {
		t.Fatalf("kind = %v, want SolanaInstructionSystemTransfer", ins.Kind)
	}
	if ins.LamportAmount != 42 {
		t.Fatalf("lamports = %d, want 42", ins.LamportAmount)
	}
	if ins.ProgramID != solSystemProgramB58 {
		t.Fatalf("program id = %s, want system program", ins.ProgramID)
	}
	if ins.FromAccount != sender {
		t.Fatalf("from = %s, want %s", ins.FromAccount, sender)
	}
	if ins.ToAccount != recipient {
		t.Fatalf("to = %s, want %s", ins.ToAccount, recipient)
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
	if ins.Kind != SolanaInstructionSPLTransferChecked {
		t.Fatalf("kind = %v, want SolanaInstructionSPLTransferChecked", ins.Kind)
	}
	if ins.TokenAmount != 12345 {
		t.Fatalf("amount = %d, want 12345", ins.TokenAmount)
	}
	if ins.Decimals != 6 {
		t.Fatalf("decimals = %d, want 6", ins.Decimals)
	}
	// accounts[0]=source, accounts[1]=mint, accounts[2]=dest in TransferChecked order
	if ins.SourceToken != sender {
		t.Fatalf("source = %s, want %s", ins.SourceToken, sender)
	}
	if ins.TokenMint != mint {
		t.Fatalf("mint = %s, want %s", ins.TokenMint, mint)
	}
	if ins.DestToken != recipient {
		t.Fatalf("dest = %s, want %s", ins.DestToken, recipient)
	}
	if ins.ProgramID != solanaTokenProgramID {
		t.Fatalf("program id = %s, want token program", ins.ProgramID)
	}
}

// TestDecodeSolanaComputeBudget builds a minimal Solana tx containing a
// SetComputeUnitLimit instruction and asserts it decodes correctly.
func TestDecodeSolanaComputeBudget(t *testing.T) {
	fromKey := make([]byte, 32)
	fromKey[0] = 0x01

	cbKey, err := base58DecodeFixed(solanaComputeBudgetProgramID, 32)
	if err != nil {
		t.Fatalf("base58DecodeFixed compute budget: %v", err)
	}

	// Instruction data: SetComputeUnitLimit = [0x02][LE-u32(200000)]
	data := make([]byte, 5)
	data[0] = 2
	binary.LittleEndian.PutUint32(data[1:5], 200000)

	var msg []byte
	msg = append(msg, 1, 0, 1)                // header: 1 signer, 0 readonly signed, 1 readonly unsigned
	msg = append(msg, solanaCompactU16(2)...) // 2 account keys
	msg = append(msg, fromKey...)
	msg = append(msg, cbKey...)
	msg = append(msg, make([]byte, 32)...)    // recent blockhash (zeros)
	msg = append(msg, solanaCompactU16(1)...) // 1 instruction
	msg = append(msg, 1)                      // programIdIndex = 1 (compute budget)
	msg = append(msg, solanaCompactU16(0)...) // 0 accounts
	msg = append(msg, solanaCompactU16(5)...) // 5 bytes data
	msg = append(msg, data...)

	var tx []byte
	tx = append(tx, solanaCompactU16(1)...) // 1 signature
	tx = append(tx, make([]byte, 64)...)    // fake signature (zeros)
	tx = append(tx, msg...)

	f, err := DecodeSolanaTx(tx)
	if err != nil {
		t.Fatalf("DecodeSolanaTx: %v", err)
	}
	if len(f.Instructions) != 1 {
		t.Fatalf("instructions = %d, want 1", len(f.Instructions))
	}
	ins := f.Instructions[0]
	if ins.Kind != SolanaInstructionComputeBudgetSetLimit {
		t.Fatalf("kind = %v, want SolanaInstructionComputeBudgetSetLimit", ins.Kind)
	}
	if ins.ComputeUnits != 200000 {
		t.Fatalf("compute units = %d, want 200000", ins.ComputeUnits)
	}
	if ins.ProgramID != solanaComputeBudgetProgramID {
		t.Fatalf("program id = %s, want %s", ins.ProgramID, solanaComputeBudgetProgramID)
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
