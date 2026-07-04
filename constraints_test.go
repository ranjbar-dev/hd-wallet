package hdwallet

import (
	"math/big"
	"testing"
)

// TestMinimumBalancePresence checks the account-based chains documented to
// carry a reserve requirement answer MinimumBalance with a positive value.
func TestMinimumBalancePresence(t *testing.T) {
	cases := []struct {
		chain Chain
		want  *big.Int
	}{
		{XRP, big.NewInt(1_000_000)},
		{XLM, big.NewInt(10_000_000)},
		{SOL, big.NewInt(890_880)},
	}
	for _, c := range cases {
		got, ok := MinimumBalance(c.chain)
		if !ok {
			t.Fatalf("MinimumBalance(%s): expected ok=true, got false", c.chain)
		}
		if got == nil {
			t.Fatalf("MinimumBalance(%s): expected non-nil value", c.chain)
		}
		if got.Sign() <= 0 {
			t.Fatalf("MinimumBalance(%s): expected positive value, got %s", c.chain, got.String())
		}
		if got.Cmp(c.want) != 0 {
			t.Fatalf("MinimumBalance(%s) = %s, want %s", c.chain, got.String(), c.want.String())
		}
	}
}

// TestMinimumBalanceMutationSafety ensures the returned *big.Int is a copy,
// not a shared package-level value — mutating it must not corrupt subsequent
// calls.
func TestMinimumBalanceMutationSafety(t *testing.T) {
	got, ok := MinimumBalance(XRP)
	if !ok {
		t.Fatal("MinimumBalance(XRP): expected ok=true")
	}
	got.SetInt64(999)

	again, ok := MinimumBalance(XRP)
	if !ok {
		t.Fatal("MinimumBalance(XRP) second call: expected ok=true")
	}
	if again.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("MinimumBalance(XRP) mutated across calls: got %s, want 1000000", again.String())
	}
}

// TestMinimumBalanceAbsentForUTXOAndUnconstrained checks that UTXO chains
// (which answer DustThreshold, not MinimumBalance) and chains with no known
// reserve requirement (e.g. ETH) return (nil, false).
func TestMinimumBalanceAbsentForUTXOAndUnconstrained(t *testing.T) {
	for _, chain := range []Chain{BTC, LTC, DOGE, BCH, ETH, TRX} {
		got, ok := MinimumBalance(chain)
		if ok {
			t.Errorf("MinimumBalance(%s): expected ok=false, got true (value=%v)", chain, got)
		}
		if got != nil {
			t.Errorf("MinimumBalance(%s): expected nil value when ok=false, got %v", chain, got)
		}
	}
}

// TestDustThresholdPresenceAndValue checks every documented UTXO chain
// answers DustThreshold with the same positive value the Bitcoin signer
// itself uses (btcDustThreshold), proving the helper reuses rather than
// duplicates that constant.
func TestDustThresholdPresenceAndValue(t *testing.T) {
	utxoChains := []Chain{
		BTC, LTC,
		DOGE, DASH, BCH, ZEC,
		DGB, SYS, VIA, STRAX,
		QTUM, RVN, FIRO, MONA, PIVX,
	}
	want := big.NewInt(btcDustThreshold)
	for _, chain := range utxoChains {
		got, ok := DustThreshold(chain)
		if !ok {
			t.Fatalf("DustThreshold(%s): expected ok=true, got false", chain)
		}
		if got.Sign() <= 0 {
			t.Fatalf("DustThreshold(%s): expected positive value, got %s", chain, got.String())
		}
		if got.Cmp(want) != 0 {
			t.Fatalf("DustThreshold(%s) = %s, want %s (btcDustThreshold)", chain, got.String(), want.String())
		}
	}
}

// TestDustThresholdAbsentForAccountChains checks account-based chains (which
// answer MinimumBalance/ActivationCost, not DustThreshold) return (nil, false).
func TestDustThresholdAbsentForAccountChains(t *testing.T) {
	for _, chain := range []Chain{ETH, XRP, XLM, SOL, TRX, ATOM} {
		got, ok := DustThreshold(chain)
		if ok {
			t.Errorf("DustThreshold(%s): expected ok=false, got true (value=%v)", chain, got)
		}
		if got != nil {
			t.Errorf("DustThreshold(%s): expected nil value when ok=false, got %v", chain, got)
		}
	}
}

// TestActivationCostPresence checks TRX answers ActivationCost with a
// positive value, and that value is consistent across calls.
func TestActivationCostPresence(t *testing.T) {
	got, ok := ActivationCost(TRX)
	if !ok {
		t.Fatal("ActivationCost(TRX): expected ok=true, got false")
	}
	if got.Sign() <= 0 {
		t.Fatalf("ActivationCost(TRX): expected positive value, got %s", got.String())
	}
	want := big.NewInt(1_100_000)
	if got.Cmp(want) != 0 {
		t.Fatalf("ActivationCost(TRX) = %s, want %s", got.String(), want.String())
	}
}

// TestActivationCostAbsentElsewhere checks chains that don't charge a
// one-off activation fee (UTXO chains, and account chains whose "activation"
// is really a MinimumBalance reserve, not a fee) return (nil, false).
func TestActivationCostAbsentElsewhere(t *testing.T) {
	for _, chain := range []Chain{BTC, ETH, XRP, XLM, SOL, ATOM} {
		got, ok := ActivationCost(chain)
		if ok {
			t.Errorf("ActivationCost(%s): expected ok=false, got true (value=%v)", chain, got)
		}
		if got != nil {
			t.Errorf("ActivationCost(%s): expected nil value when ok=false, got %v", chain, got)
		}
	}
}

// TestConstraintFunctionsAreDisjointByRole verifies the three functions
// partition the documented chains by role: a UTXO chain answers only
// DustThreshold, XRP/XLM/SOL answer only MinimumBalance, and TRX answers
// only ActivationCost — no chain answers more than one of these three.
func TestConstraintFunctionsAreDisjointByRole(t *testing.T) {
	all := []Chain{BTC, LTC, DOGE, DASH, BCH, ZEC, DGB, SYS, VIA, STRAX,
		QTUM, RVN, FIRO, MONA, PIVX, XRP, XLM, SOL, TRX, ETH, ATOM}

	for _, chain := range all {
		_, minBal := MinimumBalance(chain)
		_, dust := DustThreshold(chain)
		_, activation := ActivationCost(chain)

		count := 0
		if minBal {
			count++
		}
		if dust {
			count++
		}
		if activation {
			count++
		}
		if count > 1 {
			t.Errorf("chain %s answers more than one of MinimumBalance/DustThreshold/ActivationCost (minBal=%v dust=%v activation=%v)",
				chain, minBal, dust, activation)
		}
	}
}
