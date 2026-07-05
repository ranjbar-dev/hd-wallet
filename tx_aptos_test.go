package hdwallet

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	txaptos "github.com/ranjbar-dev/hd-wallet/txproto/aptos"
)

// Aptos transaction signing — vector-pinned test.
//
// Source: Trust Wallet Core TWAnySignerTests.cpp (Aptos), test "TxSign".
// https://github.com/trustwallet/wallet-core/blob/master/tests/chains/Aptos/TWAnySignerTests.cpp
//
// Wire summary:
//   - BCS-encoded RawTransaction
//   - domain    = SHA3-256("APTOS::RawTransaction")
//   - message   = domain || BCS(RawTransaction)
//   - ed25519 signs the full message (no pre-hash; ed25519 hashes internally)
//   - Output: BCS(RawTransaction) || auth_variant(0) || ULEB128(32) || pubkey || ULEB128(64) || sig

// aptosTestPrivKey is the ed25519 private key seed for the TWC Aptos test vector.
var aptosTestPrivKey, _ = hex.DecodeString("5d996aa76b3212142792d9130796cd2e11e3c445a93118c08414df4f66bc60ec")

// aptosZeroModuleAddr is the standard Aptos framework address 0x000...001.
var aptosZeroModuleAddr = func() []byte {
	addr := make([]byte, 32)
	addr[31] = 0x01
	return addr
}()

// aptosAmount1000LE encodes 1000 (uint64) as 8-byte little-endian for the transfer arg.
var aptosAmount1000LE = func() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, 1000)
	return b
}()

// aptosRecipient is the same as the sender in the TWC test (self-transfer).
var aptosRecipient, _ = hex.DecodeString("07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f30")

// TestSignTxAptos pins the Aptos entry-function signer byte-for-byte to the TWC vector.
func TestSignTxAptos(t *testing.T) {
	// FromPrivateKeyBytes wipes its input slice; copy the shared package-level
	// test key so other tests using aptosTestPrivKey are unaffected.
	privKey := append([]byte(nil), aptosTestPrivKey...)
	w, err := FromPrivateKeyBytes(privKey, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txaptos.SigningInput{
		SequenceNumber:          99,
		MaxGasAmount:            3296766,
		GasUnitPrice:            100,
		ExpirationTimestampSecs: 3664390082,
		ChainId:                 33,
		EntryFunction: &txaptos.EntryFunction{
			ModuleAddress: aptosZeroModuleAddr,
			ModuleName:    "aptos_account",
			FunctionName:  "transfer",
			TypeArgs:      nil,
			// arg0: recipient (32-byte address, passed as raw bytes — the signer
			// wraps with ULEB128(len)+bytes in BCS)
			// arg1: amount (u64 LE, 8 bytes)
			Args: [][]byte{aptosRecipient, aptosAmount1000LE},
		},
	}

	out, err := w.SignTransaction(APTOS, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	got, ok := out.(*txaptos.SigningOutput)
	if !ok {
		t.Fatalf("expected *aptos.SigningOutput, got %T", out)
	}
	if got.Error != "" {
		t.Fatalf("signing error: %s", got.Error)
	}

	// Expected: TWC TWAnySignerTests.cpp ASSERT_EQ(hex(output.encoded()), ...).
	const wantHex = "07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f3063000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e7366657200022007968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f3008e803000000000000fe4d3200000000006400000000000000c2276ada00000000210020ea526ba1710343d953461ff68641f1b7df5f23b9042ffa2d2a798d3adb3f3d6c405707246db31e2335edc4316a7a656a11691d1d1647f6e864d1ab12f43428aaaf806cf02120d0b608cdd89c5c904af7b137432aacdd60cc53f9fad7bd33578e01"
	if got.Encoded != wantHex {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantHex)
	}
}

// TestSignTxAptosTransferMessage verifies that the structured TransferMessage
// input (to/amount) synthesizes the exact same EntryFunction internally and
// therefore produces byte-identical output to the hand-built EntryFunction
// input in TestSignTxAptos, for the same recipient/amount.
func TestSignTxAptosTransferMessage(t *testing.T) {
	// FromPrivateKeyBytes wipes its input slice; copy the shared package-level
	// test key so other tests using aptosTestPrivKey are unaffected.
	privKey := append([]byte(nil), aptosTestPrivKey...)
	w, err := FromPrivateKeyBytes(privKey, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txaptos.SigningInput{
		SequenceNumber:          99,
		MaxGasAmount:            3296766,
		GasUnitPrice:            100,
		ExpirationTimestampSecs: 3664390082,
		ChainId:                 33,
		Transfer: &txaptos.TransferMessage{
			To:     "0x" + hex.EncodeToString(aptosRecipient),
			Amount: 1000,
		},
	}

	out, err := w.SignTransaction(APTOS, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	got, ok := out.(*txaptos.SigningOutput)
	if !ok {
		t.Fatalf("expected *aptos.SigningOutput, got %T", out)
	}
	if got.Error != "" {
		t.Fatalf("signing error: %s", got.Error)
	}

	// Same vector as TestSignTxAptos — must be byte-identical.
	const wantHex = "07968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f3063000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e7366657200022007968dab936c1bad187c60ce4082f307d030d780e91e694ae03aef16aba73f3008e803000000000000fe4d3200000000006400000000000000c2276ada00000000210020ea526ba1710343d953461ff68641f1b7df5f23b9042ffa2d2a798d3adb3f3d6c405707246db31e2335edc4316a7a656a11691d1d1647f6e864d1ab12f43428aaaf806cf02120d0b608cdd89c5c904af7b137432aacdd60cc53f9fad7bd33578e01"
	if got.Encoded != wantHex {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantHex)
	}
}

// TestSignTxAptosTransferAndEntryFunctionMutuallyExclusive verifies that
// setting both entry_function and transfer on the same SigningInput is
// rejected with ErrTxInput.
func TestSignTxAptosTransferAndEntryFunctionMutuallyExclusive(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()

	input := &txaptos.SigningInput{
		SequenceNumber:          99,
		MaxGasAmount:            3296766,
		GasUnitPrice:            100,
		ExpirationTimestampSecs: 3664390082,
		ChainId:                 33,
		EntryFunction: &txaptos.EntryFunction{
			ModuleAddress: aptosZeroModuleAddr,
			ModuleName:    "aptos_account",
			FunctionName:  "transfer",
			Args:          [][]byte{aptosRecipient, aptosAmount1000LE},
		},
		Transfer: &txaptos.TransferMessage{
			To:     "0x" + hex.EncodeToString(aptosRecipient),
			Amount: 1000,
		},
	}

	_, err := w.SignTransaction(APTOS, 0, input)
	if err == nil {
		t.Fatal("expected error when both entry_function and transfer are set")
	}
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("expected ErrTxInput, got %v", err)
	}
}

// TestSignTxAptosNilInput verifies that a nil input returns an error (not a panic).
func TestSignTxAptosNilInput(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()

	_, err := w.SignTransaction(APTOS, 0, nil)
	if err == nil {
		t.Fatal("expected error for nil input, got nil")
	}
}
