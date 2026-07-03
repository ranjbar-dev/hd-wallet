package hdwallet

import "testing"

// TestCoinDecimalsRepresentative pins a representative set of native-unit decimals
// against the values Trust Wallet Core's registry.json publishes. A wrong decimals
// value mis-formats balances, so these anchors guard the bulk edit.
func TestCoinDecimalsRepresentative(t *testing.T) {
	want := map[Symbol]uint8{
		BTC:  8,
		ETH:  18,
		SOL:  9,
		ATOM: 6,
		XRP:  6,
		XLM:  7,
		TRX:  6,
		BNB:  18,
	}
	for sym, dec := range want {
		coin, ok := CoinInfo(sym)
		if !ok {
			t.Fatalf("CoinInfo(%s): not registered", sym)
		}
		if coin.Decimals != dec {
			t.Errorf("%s decimals = %d, want %d", sym, coin.Decimals, dec)
		}
	}
}

// TestCoinDecimalsDocumented asserts every registered coin carries a deliberate
// decimals value (> 0), except for the few networks whose native unit is genuinely
// indivisible. This catches any positional struct literal that was left with a
// zero-valued (forgotten) Decimals field.
func TestCoinDecimalsDocumented(t *testing.T) {
	// Coins whose native unit legitimately has 0 fractional digits.
	zeroDecimals := map[Symbol]bool{}
	for _, sym := range SupportedCoins() {
		coin, _ := CoinInfo(sym)
		if coin.Decimals == 0 && !zeroDecimals[sym] {
			t.Errorf("%s has Decimals == 0 but is not a known indivisible coin", sym)
		}
	}
}

// TestChainIDMatchesEVMSet asserts the EVM-only invariant: every chain in
// evmTxChains carries a non-zero ChainID, and every other coin has ChainID == 0.
// VeChain is the one documented exception — it is EVM-keyed but does not use
// EIP-155 chain ids, so its ChainID is intentionally 0.
func TestChainIDMatchesEVMSet(t *testing.T) {
	evmExceptions := map[Symbol]bool{
		VET: true, // EVM-keyed but no EIP-155 chain id (32-byte chainTag scheme)
	}
	for _, sym := range SupportedCoins() {
		coin, _ := CoinInfo(sym)
		_, isEVM := evmTxChains[sym]
		switch {
		case isEVM && !evmExceptions[sym]:
			if coin.ChainID == 0 {
				t.Errorf("%s is in evmTxChains but ChainID == 0", sym)
			}
		case isEVM && evmExceptions[sym]:
			if coin.ChainID != 0 {
				t.Errorf("%s is a documented EVM exception, want ChainID == 0, got %d", sym, coin.ChainID)
			}
		default: // non-EVM
			if coin.ChainID != 0 {
				t.Errorf("%s is not an EVM chain but ChainID = %d (want 0)", sym, coin.ChainID)
			}
		}
	}
}

// TestSLIP44 pins the SLIP-44 coin type derived from each coin's Path.
func TestSLIP44(t *testing.T) {
	want := map[Symbol]uint32{
		BTC:  0,
		ETH:  60,
		SOL:  501,
		ATOM: 118,
		DOGE: 3,
	}
	for sym, ct := range want {
		coin, ok := CoinInfo(sym)
		if !ok {
			t.Fatalf("CoinInfo(%s): not registered", sym)
		}
		if got := coin.SLIP44(); got != ct {
			t.Errorf("%s SLIP44() = %d, want %d", sym, got, ct)
		}
	}
}
