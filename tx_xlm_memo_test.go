package hdwallet

import (
	"encoding/hex"
	"testing"

	txstellar "github.com/ranjbar-dev/hd-wallet/txproto/stellar"
)

// Stellar memo support — vector-pinned tests (MEMO_TEXT / MEMO_ID / MEMO_HASH).
//
// Source: Trust Wallet Core TransactionTests.cpp (Stellar), same key/account/dest
// as TestSignTxXLM in tx_xlm_test.go, but with a memo attached to the payment.
//
// Wire summary (memo discriminant replaces the hardcoded MEMO_NONE(0)):
//   MEMO_TEXT(1): uint32(len) || bytes || zero-pad to 4-byte boundary
//   MEMO_ID(2):   uint64 big-endian
//   MEMO_HASH(3): 32 raw bytes

// xlmMemoTestWallet builds a fresh wallet from a fresh copy of the test private
// key. FromPrivateKeyBytes wipes its input slice, so each test needs its own
// copy rather than sharing the package-level xlmTestPrivKey slice.
func xlmMemoTestWallet(t *testing.T) *HDWallet {
	t.Helper()
	priv := make([]byte, len(xlmTestPrivKey))
	copy(priv, xlmTestPrivKey)
	w, err := FromPrivateKeyBytes(priv, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	return w
}

func xlmMemoBaseInput() *txstellar.SigningInput {
	return &txstellar.SigningInput{
		Account:    "GAE2SZV4VLGBAPRYRFV2VY7YYLYGYIP5I7OU7BSP6DJT7GAZ35OKFDYI",
		Fee:        1000,
		Sequence:   2,
		Passphrase: "", // empty -> mainnet default
		Operation: &txstellar.SigningInput_Payment{
			Payment: &txstellar.PaymentOp{
				Destination: "GDCYBNRRPIHLHG7X7TKPUPAZ7WVUXCN3VO7WCCK64RIFV5XM5V5K4A52",
				Amount:      10_000_000,
			},
		},
	}
}

// TestSignTxXLMMemoText pins MEMO_TEXT("Hello, world!") byte-for-byte to the TWC vector.
func TestSignTxXLMMemoText(t *testing.T) {
	w := xlmMemoTestWallet(t)
	defer w.Destroy()

	input := xlmMemoBaseInput()
	input.Memo = &txstellar.SigningInput_MemoText{
		MemoText: &txstellar.MemoText{Text: "Hello, world!"},
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

	const wantEncoded = "AAAAAAmpZryqzBA+OIlrquP4wvBsIf1H3U+GT/DTP5gZ31yiAAAD6AAAAAAAAAACAAAAAAAAAAEAAAANSGVsbG8sIHdvcmxkIQAAAAAAAAEAAAAAAAAAAQAAAADFgLYxeg6zm/f81Po8Gf2rS4m7q79hCV7kUFr27O16rgAAAAAAAAAAAJiWgAAAAAAAAAABGd9cogAAAEBQQldEkYJ6rMvOHilkwFCYyroGGUvrNeWVqr/sn3iFFqgz91XxgUT0ou7bMSPRgPROfBYDfQCFfFxbcDPrrCwB"
	if got.Encoded != wantEncoded {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantEncoded)
	}
}

// TestSignTxXLMMemoID pins MEMO_ID(1234567890) byte-for-byte to the TWC vector.
func TestSignTxXLMMemoID(t *testing.T) {
	w := xlmMemoTestWallet(t)
	defer w.Destroy()

	input := xlmMemoBaseInput()
	input.Memo = &txstellar.SigningInput_MemoId{
		MemoId: &txstellar.MemoId{Id: 1234567890},
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

	const wantEncoded = "AAAAAAmpZryqzBA+OIlrquP4wvBsIf1H3U+GT/DTP5gZ31yiAAAD6AAAAAAAAAACAAAAAAAAAAIAAAAASZYC0gAAAAEAAAAAAAAAAQAAAADFgLYxeg6zm/f81Po8Gf2rS4m7q79hCV7kUFr27O16rgAAAAAAAAAAAJiWgAAAAAAAAAABGd9cogAAAEAOJ8wwCizQPf6JmkCsCNZolQeqet2qN7fgLUUQlwx3TNzM0+/GJ6Qc2faTybjKy111rE60IlnfaPeMl/nyxKIB"
	if got.Encoded != wantEncoded {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantEncoded)
	}
}

// TestSignTxXLMMemoHash pins MEMO_HASH byte-for-byte to the TWC vector.
func TestSignTxXLMMemoHash(t *testing.T) {
	w := xlmMemoTestWallet(t)
	defer w.Destroy()

	memoHash, err := hex.DecodeString("315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3")
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	if len(memoHash) != 32 {
		t.Fatalf("test setup: expected 32-byte memo hash, got %d", len(memoHash))
	}

	input := xlmMemoBaseInput()
	input.Memo = &txstellar.SigningInput_MemoHash{
		MemoHash: &txstellar.MemoHash{Hash: memoHash},
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

	const wantEncoded = "AAAAAAmpZryqzBA+OIlrquP4wvBsIf1H3U+GT/DTP5gZ31yiAAAD6AAAAAAAAAACAAAAAAAAAAMxX1vbdtB4xDuKwAZOSgFkYSsfznfIaTRb/JTHWJTt0wAAAAEAAAAAAAAAAQAAAADFgLYxeg6zm/f81Po8Gf2rS4m7q79hCV7kUFr27O16rgAAAAAAAAAAAJiWgAAAAAAAAAABGd9cogAAAECIyh1BG+hER5W+dgHDKe49X6VEYRWIjajM4Ufq3DUG/yw7Xv1MMF4eax3U0TRi7Qwj2fio/DRD3+/Ljtvip2MD"
	if got.Encoded != wantEncoded {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantEncoded)
	}
}

// TestSignTxXLMMemoTextTooLong verifies memo_text > 28 bytes is rejected.
func TestSignTxXLMMemoTextTooLong(t *testing.T) {
	w := xlmMemoTestWallet(t)
	defer w.Destroy()

	input := xlmMemoBaseInput()
	input.Memo = &txstellar.SigningInput_MemoText{
		MemoText: &txstellar.MemoText{Text: "this text is way too long to fit in 28 bytes"},
	}

	_, err := w.SignTransaction(XLM, 0, input)
	if err == nil {
		t.Fatal("expected error for memo_text > 28 bytes, got nil")
	}
}

// TestSignTxXLMMemoHashWrongLength verifies memo_hash != 32 bytes is rejected.
func TestSignTxXLMMemoHashWrongLength(t *testing.T) {
	w := xlmMemoTestWallet(t)
	defer w.Destroy()

	input := xlmMemoBaseInput()
	input.Memo = &txstellar.SigningInput_MemoHash{
		MemoHash: &txstellar.MemoHash{Hash: []byte{1, 2, 3}},
	}

	_, err := w.SignTransaction(XLM, 0, input)
	if err == nil {
		t.Fatal("expected error for memo_hash != 32 bytes, got nil")
	}
}
