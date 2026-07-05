package hdwallet

import (
	"context"
	"errors"
	"sort"
	"testing"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

const gap13Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// --- Feature 1: Chain Family Classification ---

func TestIsEVM(t *testing.T) {
	if !IsEVM(ETH) {
		t.Fatal("IsEVM(ETH) should be true")
	}
	if IsEVM(BTC) {
		t.Fatal("IsEVM(BTC) should be false")
	}
	if IsEVM(SOL) {
		t.Fatal("IsEVM(SOL) should be false")
	}
	if !IsEVM(BNB) {
		t.Fatal("IsEVM(BNB) should be true")
	}
}

func TestIsCosmosSDK(t *testing.T) {
	if !IsCosmosSDK(ATOM) {
		t.Fatal("IsCosmosSDK(ATOM) should be true")
	}
	if !IsCosmosSDK(EVMOS) {
		t.Fatal("IsCosmosSDK(EVMOS) should be true (ethermint)")
	}
	if IsCosmosSDK(ETH) {
		t.Fatal("IsCosmosSDK(ETH) should be false")
	}
	if IsCosmosSDK(BTC) {
		t.Fatal("IsCosmosSDK(BTC) should be false")
	}
}

func TestIsUTXO(t *testing.T) {
	if !IsUTXO(BTC) {
		t.Fatal("IsUTXO(BTC) should be true")
	}
	if !IsUTXO(LTC) {
		t.Fatal("IsUTXO(LTC) should be true")
	}
	if !IsUTXO(DOGE) {
		t.Fatal("IsUTXO(DOGE) should be true")
	}
	if IsUTXO(ETH) {
		t.Fatal("IsUTXO(ETH) should be false")
	}
	if IsUTXO(SOL) {
		t.Fatal("IsUTXO(SOL) should be false")
	}
}

func TestCoinDecimals(t *testing.T) {
	if d := CoinDecimals(BTC); d != 8 {
		t.Fatalf("CoinDecimals(BTC) = %d, want 8", d)
	}
	if d := CoinDecimals(ETH); d != 18 {
		t.Fatalf("CoinDecimals(ETH) = %d, want 18", d)
	}
	if d := CoinDecimals(ATOM); d != 6 {
		t.Fatalf("CoinDecimals(ATOM) = %d, want 6", d)
	}
	if d := CoinDecimals(Chain("NOPE")); d != 0 {
		t.Fatalf("CoinDecimals(unknown) = %d, want 0", d)
	}
}

func TestCoinFamily(t *testing.T) {
	cases := []struct {
		sym  Chain
		want string
	}{
		{ETH, "evm"},
		{BNB, "evm"},
		{BTC, "bitcoin-utxo"},
		{LTC, "bitcoin-utxo"},
		{DOGE, "bitcoin-utxo"},
		{ATOM, "cosmos"},
		{EVMOS, "cosmos"},
		{INJ, "cosmos"},
		{SOL, "solana"},
		{TRX, "tron"},
		{XRP, "ripple"},
		{XLM, "stellar"},
	}
	for _, c := range cases {
		if got := CoinFamily(c.sym); got != c.want {
			t.Errorf("CoinFamily(%s) = %q, want %q", c.sym, got, c.want)
		}
	}
}

// --- Feature 2: context.Context variants ---

func TestAllAddressesCtxCancelled(t *testing.T) {
	w, err := FromMnemonic(gap13Mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	result, err := w.AllAddressesCtx(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("AllAddressesCtx cancelled: want context.Canceled, got %v", err)
	}
	// partial (possibly empty) map
	if result == nil {
		t.Fatal("expected non-nil partial map")
	}
}

func TestAllAddressesAtCtxSuccess(t *testing.T) {
	w, err := FromMnemonic(gap13Mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	result, err := w.AllAddressesAtCtx(context.Background(), 0)
	if err != nil {
		t.Fatalf("AllAddressesAtCtx: unexpected error %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
}

// --- Feature 3: AllAddressResults ---

func TestAllAddressResultsMnemonic(t *testing.T) {
	w, err := FromMnemonic(gap13Mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	results := w.AllAddressResults(0)
	if len(results) == 0 {
		t.Fatal("expected non-empty results")
	}
	for sym, r := range results {
		if r.Err != nil {
			t.Errorf("AllAddressResults[%s].Err = %v, want nil", sym, r.Err)
		}
		if r.Address == "" {
			t.Errorf("AllAddressResults[%s].Address is empty", sym)
		}
	}
}

// --- Feature 4: ValidateSigningInput ---

func TestValidateSigningInputEVM(t *testing.T) {
	// Zero-value input → missing gas_limit
	in := &txeth.SigningInput{}
	err := ValidateSigningInput(ETH, in)
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("ValidateSigningInput(ETH, zero): want ErrTxInput, got %v", err)
	}
	if err != nil && !containsStr(err.Error(), "gas_limit") {
		t.Fatalf("error %q should mention gas_limit", err)
	}

	// gas_limit set but no gas price → still invalid
	in.GasLimit = []byte{0x52, 0x08}
	err = ValidateSigningInput(ETH, in)
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("ValidateSigningInput(ETH, no gas_price): want ErrTxInput, got %v", err)
	}

	// Both set → valid
	in.GasPrice = []byte{0x09, 0xc4}
	if err := ValidateSigningInput(ETH, in); err != nil {
		t.Fatalf("ValidateSigningInput(ETH, valid): unexpected error %v", err)
	}
}

func TestValidateSigningInputUnsupported(t *testing.T) {
	err := ValidateSigningInput(Chain("NOPE"), &txeth.SigningInput{})
	if !errors.Is(err, ErrTxUnsupported) {
		t.Fatalf("ValidateSigningInput(NOPE): want ErrTxUnsupported, got %v", err)
	}
}

// --- Feature 5: ErrTxUnsupported wrapping (already implemented) ---

func TestErrTxUnsupportedWrapped(t *testing.T) {
	w, err := FromMnemonic(gap13Mnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	_, txErr := w.SignTransaction(Chain("NOPE"), 0, &txeth.SigningInput{})
	if !errors.Is(txErr, ErrTxUnsupported) {
		t.Fatalf("SignTransaction(NOPE): want errors.Is ErrTxUnsupported, got %v", txErr)
	}
}

// --- Feature 6: SupportedTxCoins ---

func TestSupportedTxCoins(t *testing.T) {
	coins := SupportedTxCoins()
	if len(coins) == 0 {
		t.Fatal("SupportedTxCoins returned empty slice")
	}
	// Must be sorted
	sorted := make([]Chain, len(coins))
	copy(sorted, coins)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	for i, s := range coins {
		if s != sorted[i] {
			t.Fatalf("SupportedTxCoins not sorted: got %v", coins)
		}
	}

	inSet := func(sym Chain) bool {
		for _, s := range coins {
			if s == sym {
				return true
			}
		}
		return false
	}

	for _, want := range []Chain{ETH, BTC, SOL, TRX, XRP, ATOM} {
		if !inSet(want) {
			t.Errorf("SupportedTxCoins missing %s", want)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
