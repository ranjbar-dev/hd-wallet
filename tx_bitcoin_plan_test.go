package hdwallet

// Tests for PlanBitcoinTx, the coin-selection preview API, and for the new
// input-selector / dust-policy fields added to SigningInput.

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// p2wpkhScript is a convenience helper that returns the 22-byte P2WPKH
// scriptPubKey for a compressed public key.
func p2wpkhScript(pub []byte) []byte {
	return append([]byte{0x00, 0x14}, btcutil.Hash160(pub)...)
}

// TestPlanBitcoinTxSelectOrder verifies that SELECT_ASCENDING and
// SELECT_DESCENDING pick different UTXOs when the inputs have varying amounts.
// With a send amount that a single large UTXO can cover (descending picks it
// first) but requires two small UTXOs when sorted ascending, the two plans
// must select different numbers of inputs.
func TestPlanBitcoinTxSelectOrder(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(BTC, 0)
	script := p2wpkhScript(pub)
	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	// Three UTXOs: 2000, 5000, 8000 sat.
	// Descending order: 8000 alone covers 6000+fee (~141 sat).
	// Ascending order:  2000 alone is not enough; 2000+5000=7000 is required.
	utxos := []*txbtc.UnspentTransaction{
		{OutPointHash: mustHex(t, dummyPrevTxid), OutPointIndex: 0, OutPointSequence: 0xffffffff, Amount: 5000, Script: script},
		{OutPointHash: mustHex(t, dummyPrevTxid), OutPointIndex: 1, OutPointSequence: 0xffffffff, Amount: 2000, Script: script},
		{OutPointHash: mustHex(t, dummyPrevTxid), OutPointIndex: 2, OutPointSequence: 0xffffffff, Amount: 8000, Script: script},
	}

	// --- SELECT_ASCENDING ---
	planAsc, err := PlanBitcoinTx(BTC, &txbtc.SigningInput{
		Amount: 6000, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: utxos, InputSelector: txbtc.InputSelector_SELECT_ASCENDING,
	})
	if err != nil {
		t.Fatalf("PlanBitcoinTx ascending: %v", err)
	}

	// --- SELECT_DESCENDING ---
	planDesc, err := PlanBitcoinTx(BTC, &txbtc.SigningInput{
		Amount: 6000, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: utxos, InputSelector: txbtc.InputSelector_SELECT_DESCENDING,
	})
	if err != nil {
		t.Fatalf("PlanBitcoinTx descending: %v", err)
	}

	// Ascending needs more UTXOs than descending.
	if len(planAsc.SelectedUTXO) <= len(planDesc.SelectedUTXO) {
		t.Fatalf("ascending plan should select more UTXOs than descending: asc=%d desc=%d",
			len(planAsc.SelectedUTXO), len(planDesc.SelectedUTXO))
	}
	if len(planAsc.SelectedUTXO) != 2 {
		t.Fatalf("ascending selected %d UTXOs, want 2 (2000+5000)", len(planAsc.SelectedUTXO))
	}
	if len(planDesc.SelectedUTXO) != 1 {
		t.Fatalf("descending selected %d UTXOs, want 1 (8000)", len(planDesc.SelectedUTXO))
	}

	// Ascending: first UTXO picked is the smallest (2000 sat).
	if planAsc.SelectedUTXO[0].GetAmount() != 2000 {
		t.Fatalf("ascending first UTXO = %d sat, want 2000", planAsc.SelectedUTXO[0].GetAmount())
	}
	// Descending: first (and only) UTXO picked is the largest (8000 sat).
	if planDesc.SelectedUTXO[0].GetAmount() != 8000 {
		t.Fatalf("descending first UTXO = %d sat, want 8000", planDesc.SelectedUTXO[0].GetAmount())
	}

	// AvailableAmount must equal the sum of all UTXOs regardless of selection.
	const wantAvail = 5000 + 2000 + 8000
	if planAsc.AvailableAmount != wantAvail {
		t.Fatalf("ascending AvailableAmount = %d, want %d", planAsc.AvailableAmount, wantAvail)
	}
	if planDesc.AvailableAmount != wantAvail {
		t.Fatalf("descending AvailableAmount = %d, want %d", planDesc.AvailableAmount, wantAvail)
	}
}

// TestPlanBitcoinTxUseAll verifies that the USE_ALL input_selector (and the
// equivalent use_max_utxo flag) selects every UTXO while still producing a
// normal change output.
func TestPlanBitcoinTxUseAll(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(BTC, 0)
	script := p2wpkhScript(pub)
	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	utxos := []*txbtc.UnspentTransaction{
		{OutPointHash: mustHex(t, dummyPrevTxid), OutPointIndex: 0, OutPointSequence: 0xffffffff, Amount: 3000, Script: script},
		{OutPointHash: mustHex(t, dummyPrevTxid), OutPointIndex: 1, OutPointSequence: 0xffffffff, Amount: 4000, Script: script},
	}

	// USE_ALL selector: select every UTXO, produce change.
	plan, err := PlanBitcoinTx(BTC, &txbtc.SigningInput{
		Amount: 2000, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: utxos, InputSelector: txbtc.InputSelector_USE_ALL,
	})
	if err != nil {
		t.Fatalf("PlanBitcoinTx USE_ALL: %v", err)
	}
	if len(plan.SelectedUTXO) != 2 {
		t.Fatalf("USE_ALL selected %d UTXOs, want 2", len(plan.SelectedUTXO))
	}
	// Change must be positive (total=7000 − amount=2000 − fee).
	if plan.Change <= 0 {
		t.Fatalf("USE_ALL: expected change > 0, got %d", plan.Change)
	}

	// use_max_utxo=true with default selector must behave identically to USE_ALL.
	plan2, err := PlanBitcoinTx(BTC, &txbtc.SigningInput{
		Amount: 2000, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: utxos, UseMaxUtxo: true,
	})
	if err != nil {
		t.Fatalf("PlanBitcoinTx use_max_utxo: %v", err)
	}
	if len(plan2.SelectedUTXO) != 2 {
		t.Fatalf("use_max_utxo selected %d UTXOs, want 2", len(plan2.SelectedUTXO))
	}
	if plan2.Change != plan.Change {
		t.Fatalf("USE_ALL vs use_max_utxo change mismatch: %d vs %d", plan.Change, plan2.Change)
	}
}

// TestPlanBitcoinTxDustControls verifies the dust-threshold controls.
// The UTXO/amount are chosen so that the natural change falls below 546 sat
// (the default threshold) but above zero, making it possible to test all
// three dust-policy variants.
func TestPlanBitcoinTxDustControls(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(BTC, 0)
	script := p2wpkhScript(pub)
	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	chg, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	// 1 P2WPKH input + 2 P2WPKH outputs → fee ≈ 141 sat at 1 sat/vbyte.
	// amount=9700, utxo=10000 → change = 10000−9700−141 = 159 (below 546 dust threshold).
	utxo := []*txbtc.UnspentTransaction{{
		OutPointHash: mustHex(t, dummyPrevTxid), OutPointSequence: 0xffffffff,
		Amount: 10000, Script: script,
	}}

	// Default: sub-threshold change is folded into the fee → Change = 0.
	planDefault, err := PlanBitcoinTx(BTC, &txbtc.SigningInput{
		Amount: 9700, ByteFee: 1, ToAddress: to, ChangeAddress: chg, Utxo: utxo,
	})
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	if planDefault.Change != 0 {
		t.Fatalf("default: expected dust folded into fee (Change=0), got Change=%d", planDefault.Change)
	}
	// Fee absorbs the dust: total − amount = 10000−9700 = 300 sat.
	if planDefault.Fee != 300 {
		t.Fatalf("default: fee = %d, want 300 (dust folded)", planDefault.Fee)
	}

	// disable_dust_filter = true: change is emitted even though it is < 546.
	planNoFilter, err := PlanBitcoinTx(BTC, &txbtc.SigningInput{
		Amount: 9700, ByteFee: 1, ToAddress: to, ChangeAddress: chg, Utxo: utxo,
		DisableDustFilter: true,
	})
	if err != nil {
		t.Fatalf("disable_dust_filter plan: %v", err)
	}
	if planNoFilter.Change <= 0 {
		t.Fatalf("disable_dust_filter: expected Change > 0, got %d", planNoFilter.Change)
	}
	// Fee should be lower (no folded dust) since the change output is real.
	if planNoFilter.Fee >= planDefault.Fee {
		t.Fatalf("disable_dust_filter: expected lower fee than default (%d >= %d)",
			planNoFilter.Fee, planDefault.Fee)
	}

	// fixed_dust_threshold = 1: any positive change passes → emitted.
	planLowDust, err := PlanBitcoinTx(BTC, &txbtc.SigningInput{
		Amount: 9700, ByteFee: 1, ToAddress: to, ChangeAddress: chg, Utxo: utxo,
		FixedDustThreshold: 1,
	})
	if err != nil {
		t.Fatalf("fixed_dust_threshold=1 plan: %v", err)
	}
	if planLowDust.Change <= 0 {
		t.Fatalf("fixed_dust_threshold=1: expected Change > 0, got %d", planLowDust.Change)
	}

	// fixed_dust_threshold = 10000: change (159 sat) < threshold → folded.
	planHighDust, err := PlanBitcoinTx(BTC, &txbtc.SigningInput{
		Amount: 9700, ByteFee: 1, ToAddress: to, ChangeAddress: chg, Utxo: utxo,
		FixedDustThreshold: 10000,
	})
	if err != nil {
		t.Fatalf("fixed_dust_threshold=10000 plan: %v", err)
	}
	if planHighDust.Change != 0 {
		t.Fatalf("fixed_dust_threshold=10000: expected dust folded (Change=0), got %d", planHighDust.Change)
	}
}

// TestPlanBitcoinTxConsistency checks that PlanBitcoinTx returns values
// consistent with the subsequent SignTransaction call: Fee and SelectedUTXO
// must be identical, and Change+Fee+Amount == selected UTXO total.
func TestPlanBitcoinTxConsistency(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(BTC, 0)
	script := p2wpkhScript(pub)
	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	in := &txbtc.SigningInput{
		Amount: 5000, ByteFee: 2, ToAddress: to, ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{
			{OutPointHash: mustHex(t, dummyPrevTxid), OutPointIndex: 0, OutPointSequence: 0xffffffff, Amount: 10000, Script: script},
		},
	}

	plan, err := PlanBitcoinTx(BTC, in)
	if err != nil {
		t.Fatalf("PlanBitcoinTx: %v", err)
	}

	outMsg, err := w.SignTransaction(BTC, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	out := outMsg.(*txbtc.SigningOutput)

	// Fee must match exactly.
	if plan.Fee != out.Fee {
		t.Fatalf("plan.Fee = %d, out.Fee = %d", plan.Fee, out.Fee)
	}
	// SelectedUTXO count and amounts must match UsedUtxo.
	if len(plan.SelectedUTXO) != len(out.UsedUtxo) {
		t.Fatalf("SelectedUTXO count = %d, out.UsedUtxo = %d", len(plan.SelectedUTXO), len(out.UsedUtxo))
	}
	for i := range plan.SelectedUTXO {
		if plan.SelectedUTXO[i].GetAmount() != out.UsedUtxo[i].GetAmount() {
			t.Fatalf("SelectedUTXO[%d].Amount = %d, want %d",
				i, plan.SelectedUTXO[i].GetAmount(), out.UsedUtxo[i].GetAmount())
		}
	}
	// AvailableAmount = sum of all provided UTXOs.
	if plan.AvailableAmount != 10000 {
		t.Fatalf("AvailableAmount = %d, want 10000", plan.AvailableAmount)
	}
	// Accounting identity: Change + Fee + Amount = selected total.
	var selTotal int64
	for _, u := range plan.SelectedUTXO {
		selTotal += u.GetAmount()
	}
	if plan.Change+plan.Fee+in.GetAmount() != selTotal {
		t.Fatalf("Change(%d) + Fee(%d) + Amount(%d) = %d, want %d (selected total)",
			plan.Change, plan.Fee, in.GetAmount(),
			plan.Change+plan.Fee+in.GetAmount(), selTotal)
	}
}

// TestPlanBitcoinTxDefaultOracleRegression guards the default (SELECT_IN_ORDER,
// no dust/utxo flags) path against a byte-identical re-sign with btcd,
// confirming that the plan fields are consistent with the signed output and
// that no existing oracle test was broken by the refactor.
func TestPlanBitcoinTxDefaultOracleRegression(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(BTC, 0)
	script := p2wpkhScript(pub)
	to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
	change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

	in := &txbtc.SigningInput{
		HashType: 0x01, Amount: 1500, ByteFee: 1, ToAddress: to, ChangeAddress: change,
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash: mustHex(t, dummyPrevTxid), OutPointIndex: 0,
			OutPointSequence: 0xffffffff, Amount: 10000, Script: script,
		}},
	}

	// Sign and byte-compare against the btcd oracle — same check as
	// TestSignTxBitcoinP2WPKH, verifying the refactor did not alter bytes.
	outMsg, err := w.SignTransaction(BTC, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	out := outMsg.(*txbtc.SigningOutput)
	want, _ := btcOracleResign(t, w, out.Encoded, in.Utxo)
	if out.EncodedHex != want {
		t.Fatalf("default path regression: tx hex mismatch\n got: %s\nwant: %s", out.EncodedHex, want)
	}

	// PlanBitcoinTx must agree with the signed output.
	plan, err := PlanBitcoinTx(BTC, in)
	if err != nil {
		t.Fatalf("PlanBitcoinTx: %v", err)
	}
	if plan.Fee != out.Fee {
		t.Fatalf("plan.Fee = %d, out.Fee = %d", plan.Fee, out.Fee)
	}
	if len(plan.SelectedUTXO) != len(out.UsedUtxo) {
		t.Fatalf("SelectedUTXO count = %d, out.UsedUtxo = %d",
			len(plan.SelectedUTXO), len(out.UsedUtxo))
	}
}
