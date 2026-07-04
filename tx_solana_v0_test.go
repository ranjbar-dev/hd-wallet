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
