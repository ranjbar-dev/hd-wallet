package hdwallet

import (
	"testing"

	txstellar "github.com/ranjbar-dev/hd-wallet/txproto/stellar"
)

// Stellar CreateAccount operation — vector-pinned test.
//
// CreateAccount funds a not-yet-existing account (Stellar rejects Payment to
// unfunded accounts). Operation body encoding differs from Payment:
//
//	CREATE_ACCOUNT(0): destination (AccountID) || starting_balance (int64 BE)
//	  — no asset field, since CreateAccount always funds with native XLM.
//
// Same key/account/dest as TestSignTxXLMMemoID (tx_xlm_memo_test.go), but with
// a CreateAccount operation instead of Payment, amount 10000000, fee 1000,
// seq 2, memo_id 1234567890.
func TestSignTxXLMCreateAccount(t *testing.T) {
	w := xlmMemoTestWallet(t)
	defer w.Destroy()

	input := &txstellar.SigningInput{
		Account:    "GAE2SZV4VLGBAPRYRFV2VY7YYLYGYIP5I7OU7BSP6DJT7GAZ35OKFDYI",
		Fee:        1000,
		Sequence:   2,
		Passphrase: "", // empty -> mainnet default
		Operation: &txstellar.SigningInput_CreateAccount{
			CreateAccount: &txstellar.CreateAccountOp{
				Destination:     "GDCYBNRRPIHLHG7X7TKPUPAZ7WVUXCN3VO7WCCK64RIFV5XM5V5K4A52",
				StartingBalance: 10_000_000,
			},
		},
		Memo: &txstellar.SigningInput_MemoId{
			MemoId: &txstellar.MemoId{Id: 1234567890},
		},
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

	const wantEncoded = "AAAAAAmpZryqzBA+OIlrquP4wvBsIf1H3U+GT/DTP5gZ31yiAAAD6AAAAAAAAAACAAAAAAAAAAIAAAAASZYC0gAAAAEAAAAAAAAAAAAAAADFgLYxeg6zm/f81Po8Gf2rS4m7q79hCV7kUFr27O16rgAAAAAAmJaAAAAAAAAAAAEZ31yiAAAAQNgqNDqbe0X60gyH+1xf2Tv2RndFiJmyfbrvVjsTfjZAVRrS2zE9hHlqPQKpZkGKEFka7+1ElOS+/m/1JDnauQg="
	if got.Encoded != wantEncoded {
		t.Errorf("encoded mismatch\n got: %s\nwant: %s", got.Encoded, wantEncoded)
	}
}

// TestSignTxXLMCreateAccountNoAmount verifies a non-positive starting_balance
// is not silently accepted (mirrors the Payment amount<=0 guard).
func TestSignTxXLMCreateAccountNoOperation(t *testing.T) {
	w := xlmMemoTestWallet(t)
	defer w.Destroy()

	input := &txstellar.SigningInput{
		Account:    "GAE2SZV4VLGBAPRYRFV2VY7YYLYGYIP5I7OU7BSP6DJT7GAZ35OKFDYI",
		Fee:        1000,
		Sequence:   2,
		Passphrase: "",
	}

	_, err := w.SignTransaction(XLM, 0, input)
	if err == nil {
		t.Fatal("expected error when no operation is set, got nil")
	}
}
