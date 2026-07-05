package hdwallet

import (
	"encoding/hex"
	"testing"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// Solana v0 (versioned) message signing, verified against a Trust Wallet
// Core-style vector (test_solana_sign_transfer_v0): a native SOL transfer
// with v0_msg=true produces the identical legacy message body prefixed with
// the 0x80 version byte and suffixed with a single zero byte (compact-u16
// encoding of zero address-table lookups).
func TestSignTxSolanaTransferV0(t *testing.T) {
	priv, err := hex.DecodeString("833a053c59e78138a3ed090459bc6743cca6a9cbc2809a7bf5dbc7939b8775c8")
	if err != nil {
		t.Fatalf("hex decode private key: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("private key hex decoded to %d bytes, want 32", len(priv))
	}
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txsolana.SigningInput{
		RecentBlockhash: "HxKwWFTHixCu8aw35J1uxAX6yUhLHkFCdJJdK4y98Gyj",
		V0Msg:           true,
		TransactionType: &txsolana.SigningInput_TransferTransaction{
			TransferTransaction: &txsolana.Transfer{
				Recipient: "6pEfiZjMycJY4VA2FtAbKgYvRwzXDpxY58Xp4b7FQCz9",
				Value:     5000,
			},
		},
	}

	const want = "6NijVxwQoDjqt6A41HXCK9kXwNDp48uLgvRyE8uz6NY5dEzaEDLzjzuMnc5TGatHZZUXehKrzUGzbg9jPSdn6pVsMc9TXNH6JGe5RJLmHwWey3MC1p8Hs2zhjw5P439P57NToatraDX9ZwvBtK4EzZzRjWbyGdicheTPjeYKCzvPCLxDkTFtPCM9VZGGXSN2Bne92NLDvf6ntNm5pxsPkZGxPe4w9Eq26gkE83hZyrYXKaiDh8TbqbHatSkw"

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

	// Byte-level sanity: the message portion (raw[1+64:]) must start with the
	// 0x80 version-prefix byte and end with a single 0x00 (zero address-table
	// lookups).
	raw := so.GetRaw()
	if len(raw) < 1+64+1 {
		t.Fatalf("raw tx too short: %d bytes", len(raw))
	}
	message := raw[1+64:]
	if message[0] != 0x80 {
		t.Fatalf("message[0] = 0x%02x, want 0x80 (v0 version prefix)", message[0])
	}
	if message[len(message)-1] != 0x00 {
		t.Fatalf("message trailing byte = 0x%02x, want 0x00 (zero address-table lookups)", message[len(message)-1])
	}

	// Round-trip: decode the signer's own v0 output and confirm Version and
	// AddressTableLookups are recovered correctly, and the legacy body
	// (header/keys/blockhash/instruction) fields decode exactly as the
	// legacy-message case would.
	f, err := DecodeSolanaTx(raw)
	if err != nil {
		t.Fatalf("DecodeSolanaTx: %v", err)
	}
	if f.Version != 0 {
		t.Fatalf("Version = %d, want 0", f.Version)
	}
	if f.AddressTableLookups != 0 {
		t.Fatalf("AddressTableLookups = %d, want 0", f.AddressTableLookups)
	}
	if f.NumRequiredSignatures != 1 || f.NumReadonlySigned != 0 || f.NumReadonlyUnsigned != 1 {
		t.Fatalf("header = %d/%d/%d, want 1/0/1", f.NumRequiredSignatures, f.NumReadonlySigned, f.NumReadonlyUnsigned)
	}
	// This vector is a self-transfer (sender == recipient), so the compiled
	// message dedupes to two account keys: the shared signer/recipient key,
	// then the system program (readonly, non-signer).
	sender, _ := w.Address(SOL)
	if sender != "6pEfiZjMycJY4VA2FtAbKgYvRwzXDpxY58Xp4b7FQCz9" {
		t.Fatalf("sender = %s, want 6pEfiZjMycJY4VA2FtAbKgYvRwzXDpxY58Xp4b7FQCz9 (vector is a self-transfer)", sender)
	}
	wantKeys := []string{sender, solSystemProgramB58}
	if len(f.AccountKeys) != 2 {
		t.Fatalf("account keys = %d, want 2", len(f.AccountKeys))
	}
	for i, k := range wantKeys {
		if f.AccountKeys[i] != k {
			t.Fatalf("account key[%d] = %s, want %s", i, f.AccountKeys[i], k)
		}
	}
	if f.RecentBlockhash != "HxKwWFTHixCu8aw35J1uxAX6yUhLHkFCdJJdK4y98Gyj" {
		t.Fatalf("blockhash = %s", f.RecentBlockhash)
	}
	if len(f.Instructions) != 1 || f.Instructions[0].Kind != SolanaInstructionSystemTransfer {
		t.Fatalf("instructions = %+v", f.Instructions)
	}
	if f.Instructions[0].LamportAmount != 5000 {
		t.Fatalf("lamport amount = %d, want 5000", f.Instructions[0].LamportAmount)
	}

	// Regression: decoding a LEGACY (non-versioned) message must leave
	// Version at the -1 sentinel and AddressTableLookups at 0.
	legacyIn := &txsolana.SigningInput{
		RecentBlockhash: solSystemProgramB58,
		TransactionType: &txsolana.SigningInput_TransferTransaction{
			TransferTransaction: &txsolana.Transfer{
				Recipient: "6pEfiZjMycJY4VA2FtAbKgYvRwzXDpxY58Xp4b7FQCz9",
				Value:     42,
			},
		},
	}
	legacyOut, err := w.SignTransaction(SOL, 0, legacyIn)
	if err != nil {
		t.Fatalf("SignTransaction (legacy): %v", err)
	}
	legacyF, err := DecodeSolanaTx(legacyOut.(*txsolana.SigningOutput).GetRaw())
	if err != nil {
		t.Fatalf("DecodeSolanaTx (legacy): %v", err)
	}
	if legacyF.Version != -1 {
		t.Fatalf("legacy Version = %d, want -1", legacyF.Version)
	}
	if legacyF.AddressTableLookups != 0 {
		t.Fatalf("legacy AddressTableLookups = %d, want 0", legacyF.AddressTableLookups)
	}
}

// TestDecodeSolanaV0AddressTableLookups exercises the decode-side asymmetry:
// this library never SIGNS a v0 message with populated address-table
// lookups, but DecodeSolanaTx must still correctly parse one built by
// another signer (e.g. a DApp or another SDK), so it can be displayed
// without desyncing the byte cursor.
func TestDecodeSolanaV0AddressTableLookups(t *testing.T) {
	w := solanaTestWallet(t)
	defer w.Destroy()

	const recipient = "6pEfiZjMycJY4VA2FtAbKgYvRwzXDpxY58Xp4b7FQCz9"
	in := &txsolana.SigningInput{
		RecentBlockhash: solSystemProgramB58,
		V0Msg:           true,
		TransactionType: &txsolana.SigningInput_TransferTransaction{
			TransferTransaction: &txsolana.Transfer{
				Recipient: recipient,
				Value:     7,
			},
		},
	}
	out, err := w.SignTransaction(SOL, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	raw := out.(*txsolana.SigningOutput).GetRaw()

	// The signer produces a trailing single zero byte (0 lookups). Strip it
	// and append a synthetic single lookup entry: {32-byte key, 1 writable
	// index, 2 readonly indices}, to exercise the decoder's lookup-array
	// parsing on a message it never itself produces.
	body := raw[:len(raw)-1]
	lookupKey := make([]byte, 32)
	for i := range lookupKey {
		lookupKey[i] = byte(i + 1) // #nosec G115 -- test fixture, not a real key
	}
	synthetic := append([]byte{}, body...)
	synthetic = append(synthetic, 0x01)          // compact-u16(1) lookup
	synthetic = append(synthetic, lookupKey...)  // 32-byte account key
	synthetic = append(synthetic, 0x01, 0x05)    // compact-u16(1) writable count, index 5
	synthetic = append(synthetic, 0x02, 0x06, 7) // compact-u16(2) readonly count, indices 6,7

	f, err := DecodeSolanaTx(synthetic)
	if err != nil {
		t.Fatalf("DecodeSolanaTx: %v", err)
	}
	if f.Version != 0 {
		t.Fatalf("Version = %d, want 0", f.Version)
	}
	if f.AddressTableLookups != 1 {
		t.Fatalf("AddressTableLookups = %d, want 1", f.AddressTableLookups)
	}
}

// assertSolanaV0 is the shared structural check for the v0_msg smoke tests
// below: no TWC vector exists for these v0 + (token-transfer / ATA / durable
// nonce) combinations, so — following the TokenTransfer+nonce precedent in
// tx_solana_nonce_test.go — we anchor on structure rather than a byte-exact
// vector: the signer must not error, the message body must carry the 0x80
// v0 version prefix, and DecodeSolanaTx must round-trip Version == 0.
func assertSolanaV0(t *testing.T, so *txsolana.SigningOutput) *SolanaTxFields {
	t.Helper()
	if so.GetError() != "" {
		t.Fatalf("signing error: %s", so.GetError())
	}
	raw := so.GetRaw()
	if len(raw) < 1+64+1 {
		t.Fatalf("raw tx too short: %d bytes", len(raw))
	}
	message := raw[1+64:]
	if message[0] != 0x80 {
		t.Fatalf("message[0] = 0x%02x, want 0x80 (v0 version prefix)", message[0])
	}
	f, err := DecodeSolanaTx(raw)
	if err != nil {
		t.Fatalf("DecodeSolanaTx: %v", err)
	}
	if f.Version != 0 {
		t.Fatalf("Version = %d, want 0", f.Version)
	}
	return f
}

// No TWC vector exists for TokenTransfer+v0_msg. Structure-anchored smoke
// test (see assertSolanaV0): the same fixture as
// TestSignTxSolanaTokenTransfer, with v0_msg=true added.
func TestSignSolanaTokenTransferV0(t *testing.T) {
	priv, err := base58Decode(base58BTC, "9YtuoD4sH4h88CVM8DSnkfoAaLY7YeGC2TarDJ8eyMS5")
	if err != nil {
		t.Fatalf("decode priv: %v", err)
	}
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txsolana.SigningInput{
		RecentBlockhash: "CNaHfvqePgGYMvtYi9RuUdVxDYttr1zs4TWrTXYabxZi",
		V0Msg:           true,
		TransactionType: &txsolana.SigningInput_TokenTransferTransaction{
			TokenTransferTransaction: &txsolana.TokenTransfer{
				TokenMintAddress:      "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
				SenderTokenAddress:    "EDNd1ycsydWYwVmrYZvqYazFqwk1QjBgAUKFjBoz1jKP",
				RecipientTokenAddress: "3WUX9wASxyScbA7brDipioKfXS1XEYkQ4vo3Kej9bKei",
				Amount:                4000,
				Decimals:              6,
			},
		},
	}
	out, err := w.SignTransaction(SOL, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	so, ok := out.(*txsolana.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *solana.SigningOutput", out)
	}
	f := assertSolanaV0(t, so)
	if len(f.Instructions) != 1 || f.Instructions[0].Kind != SolanaInstructionSPLTransferChecked {
		t.Fatalf("instructions = %+v", f.Instructions)
	}
}

// No TWC vector exists for CreateAndTransferToken+v0_msg. Structure-anchored
// smoke test (see assertSolanaV0): the same fixture as
// TestSignSolanaCreateAndTransferToken, with v0_msg=true added.
func TestSignSolanaCreateAndTransferTokenV0(t *testing.T) {
	w, err := FromPrivateKeyBytes(mustB58Priv(t, "66ApBuKpo2uSzpjGBraHq7HP8UZMUJzp3um8FdEjkC9c"), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txsolana.SigningInput{
		RecentBlockhash: "DMmDdJP41M9mw8Z4586VSvxqGCrqPy5uciF6HsKUVDja",
		V0Msg:           true,
		TransactionType: &txsolana.SigningInput_CreateAndTransferTokenTransaction{
			CreateAndTransferTokenTransaction: &txsolana.CreateAndTransferToken{
				RecipientMainAddress:  "71e8mDsh3PR6gN64zL1HjwuxyKpgRXrPDUJT7XXojsVd",
				TokenMintAddress:      "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt",
				RecipientTokenAddress: "EF6L8yJT1SoRoDCkAZfSVmaweqMzfhxZiptKi7Tgj5XY",
				SenderTokenAddress:    "ANVCrmRw7Ww7rTFfMbrjApSPXEEcZpBa6YEiBdf98pAf",
				Amount:                2900,
				Decimals:              6,
			},
		},
	}
	out, err := w.SignTransaction(SOL, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	so, ok := out.(*txsolana.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *solana.SigningOutput", out)
	}
	assertSolanaV0(t, so)
}

// Durable nonce + v0_msg combination — no TWC vector exists for this either.
// Structure-anchored smoke test (see assertSolanaV0): the same fixture as
// TestSignSolanaTransferDurableNonce, with v0_msg=true added, confirming the
// AdvanceNonceAccount + transfer instruction pair still compiles correctly
// underneath the v0 version wrapper.
func TestSignSolanaTransferDurableNonceV0(t *testing.T) {
	priv := mustHexTx(t, "044014463e2ee3cc9c67a6f191dbac82288eb1d5c1111d21245bdc6a855082a1")
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txsolana.SigningInput{
		RecentBlockhash: "5ycoKxPRpW2GdD4byZuMptHU3VU5MgUCh6NLGQ2U8VE5", // durable nonce VALUE
		NonceAccount:    "ALAaqqt4Cc8hWH22GT2L16xKNAn6gv7XCTF7JkbfWsc",
		V0Msg:           true,
		TransactionType: &txsolana.SigningInput_TransferTransaction{
			TransferTransaction: &txsolana.Transfer{
				Recipient: "3UVYmECPPMZSCqWKfENfuoTv51fTDTWicX9xmBD2euKe",
				Value:     1000,
			},
		},
	}
	out, err := w.SignTransaction(SOL, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	so, ok := out.(*txsolana.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *solana.SigningOutput", out)
	}
	// AdvanceNonceAccount has no dedicated decode Kind (it decodes as
	// SolanaInstructionUnknown); the second instruction is the actual
	// transfer, confirming the advance-nonce insertion didn't clobber it.
	f := assertSolanaV0(t, so)
	if len(f.Instructions) != 2 || f.Instructions[1].Kind != SolanaInstructionSystemTransfer {
		t.Fatalf("instructions = %+v", f.Instructions)
	}
	if f.Instructions[1].LamportAmount != 1000 {
		t.Fatalf("lamport amount = %d, want 1000", f.Instructions[1].LamportAmount)
	}
}
