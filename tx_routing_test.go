package hdwallet

import (
	"bytes"
	"errors"
	"regexp"
	"testing"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// canonicalSeedWallet builds a seed wallet from the canonical test mnemonic.
func canonicalSeedWallet(t *testing.T) *HDWallet {
	t.Helper()
	w, err := FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	return w
}

// TestTxFamilyRouting asserts the data-driven routing covers every EVM and
// standard-Cosmos chain, keeps the single-chain families, and deliberately
// excludes the ethermint-keyed Cosmos chains.
func TestTxFamilyRouting(t *testing.T) {
	for s := range evmTxChains {
		if got := txFamilyOf(s); got != familyEthereum {
			t.Errorf("txFamilyOf(%s) = %v, want familyEthereum", s, got)
		}
	}
	for s := range cosmosTxChains {
		if got := txFamilyOf(s); got != familyCosmos {
			t.Errorf("txFamilyOf(%s) = %v, want familyCosmos", s, got)
		}
	}
	// EVMOS is the one vector-verified ethermint-keyed Cosmos chain.
	if got := txFamilyOf(EVMOS); got != familyCosmosEthermint {
		t.Errorf("txFamilyOf(EVMOS) = %v, want familyCosmosEthermint", got)
	}
	// The remaining ethermint-keyed chains stay unrouted pending their own vectors
	// (Injective uses a different pubkey type URL; see tx_families.go).
	for _, s := range []Symbol{INJ, CANTO, ZETA, ONE} {
		if got := txFamilyOf(s); got != familyNone {
			t.Errorf("txFamilyOf(%s) = %v, want familyNone (ethermint, no vector yet)", s, got)
		}
	}
	// Single-chain families.
	for s, want := range map[Symbol]txFamily{TRX: familyTron, XRP: familyRipple, SOL: familySolana, BTC: familyBitcoin, LTC: familyBitcoin} {
		if got := txFamilyOf(s); got != want {
			t.Errorf("txFamilyOf(%s) = %v, want %v", s, got, want)
		}
	}
}

// TestEVMRoutingProducesIdenticalBytes proves a newly-routed EVM chain (ZKSYNC,
// same m/44'/60' path as ETH) signs to exactly the same bytes as ETH for an
// identical input — i.e. the builder is correct and symbol-agnostic.
func TestEVMRoutingProducesIdenticalBytes(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()

	newInput := func() *txeth.SigningInput {
		return &txeth.SigningInput{
			ChainId:   mustHexTx(t, "01"),
			Nonce:     mustHexTx(t, "09"),
			TxMode:    0,
			GasPrice:  mustHexTx(t, "04a817c800"),
			GasLimit:  mustHexTx(t, "5208"),
			ToAddress: "0x3535353535353535353535353535353535353535",
			Transaction: &txeth.Transaction{
				TransactionOneof: &txeth.Transaction_Transfer_{
					Transfer: &txeth.Transaction_Transfer{Amount: mustHexTx(t, "0de0b6b3a7640000")},
				},
			},
		}
	}

	ethOut, err := w.SignTransaction(ETH, 0, newInput())
	if err != nil {
		t.Fatalf("ETH SignTransaction: %v", err)
	}
	zkOut, err := w.SignTransaction(ZKSYNC, 0, newInput())
	if err != nil {
		t.Fatalf("ZKSYNC SignTransaction (newly routed): %v", err)
	}
	if !bytes.Equal(ethOut.(*txeth.SigningOutput).GetEncoded(), zkOut.(*txeth.SigningOutput).GetEncoded()) {
		t.Fatalf("ZKSYNC encoded tx differs from ETH for identical input")
	}
}

// TestCosmosRoutingProducesIdenticalBytes proves a newly-routed standard Cosmos
// chain (STARS, same m/44'/118' path as ATOM) signs to the same bytes as ATOM.
func TestCosmosRoutingProducesIdenticalBytes(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()

	newInput := func() *txcosmos.SigningInput {
		return &txcosmos.SigningInput{
			AccountNumber: 1,
			ChainId:       "test-1",
			Sequence:      0,
			Fee:           &txcosmos.Fee{Amount: "200", Denom: "uatom", Gas: 200000},
			Send: &txcosmos.SendCoinsMessage{
				FromAddress: "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02",
				ToAddress:   "cosmos1zt50azupanqlfam5afhv3hexwyutnukeh4c573",
				Amount:      "1",
				Denom:       "uatom",
			},
		}
	}

	atomOut, err := w.SignTransaction(ATOM, 0, newInput())
	if err != nil {
		t.Fatalf("ATOM SignTransaction: %v", err)
	}
	starsOut, err := w.SignTransaction(STARS, 0, newInput())
	if err != nil {
		t.Fatalf("STARS SignTransaction (newly routed): %v", err)
	}
	if !bytes.Equal(atomOut.(*txcosmos.SigningOutput).GetEncoded(), starsOut.(*txcosmos.SigningOutput).GetEncoded()) {
		t.Fatalf("STARS encoded tx differs from ATOM for identical input")
	}
}

// TestEthermintCosmosUnsupported confirms the deliberate exclusion: signing for
// an ethermint-keyed Cosmos chain returns ErrTxUnsupported rather than emitting
// an on-chain-invalid (wrong pubkey type) transaction.
func TestEthermintCosmosUnsupported(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()
	_, err := w.SignTransaction(INJ, 0, &txcosmos.SigningInput{
		Fee:  &txcosmos.Fee{Amount: "1", Denom: "inj", Gas: 1},
		Send: &txcosmos.SendCoinsMessage{FromAddress: "a", ToAddress: "b", Amount: "1", Denom: "inj"},
	})
	if !errors.Is(err, ErrTxUnsupported) {
		t.Fatalf("INJ SignTransaction error = %v, want ErrTxUnsupported", err)
	}
}

// TestEVMRoutingDriftGuard catches a future registry EVM chain (0x-address) that
// is not added to evmTxChains: every coin whose index-0 address is a 0x + 40-hex
// Ethereum address must route to the EVM family.
func TestEVMRoutingDriftGuard(t *testing.T) {
	w := canonicalSeedWallet(t)
	defer w.Destroy()

	ethAddr := regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	for _, s := range SupportedCoins() {
		addr, err := w.Address(s)
		if err != nil {
			t.Fatalf("Address(%s): %v", s, err)
		}
		if !ethAddr.MatchString(addr) {
			continue
		}
		if _, ok := evmTxChains[s]; !ok {
			// Ethermint-keyed Cosmos chains also produce 0x... addresses but are
			// intentionally not EVM-tx chains; skip those.
			switch s {
			case EVMOS, INJ, CANTO, ZETA, ONE:
				continue
			}
			t.Errorf("%s has an Ethereum-format address (%s) but is not in evmTxChains", s, addr)
		}
	}
}
