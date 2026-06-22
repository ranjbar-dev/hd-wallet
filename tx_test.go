package hdwallet

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

const txTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// TestSignTransactionUnsupportedCoin verifies that a symbol with no transaction
// family returns ErrTxUnsupported.
func TestSignTransactionUnsupportedCoin(t *testing.T) {
	w, err := FromMnemonic(txTestMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	// NEO has no transaction builder family.
	_, err = w.SignTransaction(NEO, 0, &txeth.SigningInput{})
	if !errors.Is(err, ErrTxUnsupported) {
		t.Fatalf("NEO SignTransaction error = %v, want ErrTxUnsupported", err)
	}
}

// TestSignTransactionWrongInputType verifies that passing the wrong SigningInput
// proto for a family returns ErrTxInput.
func TestSignTransactionWrongInputType(t *testing.T) {
	w, err := FromMnemonic(txTestMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	// ETH is the Ethereum family, but we hand it a Tron input.
	_, err = w.SignTransaction(ETH, 0, &txtron.SigningInput{})
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("ETH with tron input error = %v, want ErrTxInput", err)
	}
}

// TestSignTransactionEVMAliasesShareEthereum verifies that an EVM alias (BNB)
// routes through the Ethereum family and produces a valid signed legacy tx.
func TestSignTransactionEVMAliasesShareEthereum(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "38"), // BNB Smart Chain id 56
		Nonce:     mustHexTx(t, "00"),
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
	out, err := w.SignTransaction(BNB, 0, in)
	if err != nil {
		t.Fatalf("BNB SignTransaction: %v", err)
	}
	eo, ok := out.(*txeth.SigningOutput)
	if !ok || len(eo.GetEncoded()) == 0 {
		t.Fatalf("BNB output = %T (encoded %d bytes), want non-empty *ethereum.SigningOutput", out, len(eo.GetEncoded()))
	}
	// EIP-155 v for chain 56 = recid + 56*2 + 35 = 147 or 148.
	if v := eo.GetV(); len(v) == 0 || (v[0] != 147 && v[0] != 148) {
		t.Fatalf("BNB v = %x, want 0x93 or 0x94 (EIP-155 chain 56)", v)
	}
}

// TestSignTransactionDestroyedWallet verifies a destroyed wallet is rejected.
func TestSignTransactionDestroyedWallet(t *testing.T) {
	w, err := FromMnemonic(txTestMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "01"),
		Nonce:     mustHexTx(t, "00"),
		GasPrice:  mustHexTx(t, "04a817c800"),
		GasLimit:  mustHexTx(t, "5208"),
		ToAddress: "0x3535353535353535353535353535353535353535",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{Amount: mustHexTx(t, "01")},
			},
		},
	}
	if _, err := w.SignTransaction(ETH, 0, in); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("destroyed wallet error = %v, want ErrDestroyed", err)
	}
}

// TestSignTransactionInputValidation exercises the per-family input guards: each
// must return ErrTxInput (not a partial/guessed transaction) for malformed input.
func TestSignTransactionInputValidation(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	cases := []struct {
		name   string
		symbol Symbol
		input  proto.Message
	}{
		{"eth missing transaction", ETH, &txeth.SigningInput{ToAddress: "0x3535353535353535353535353535353535353535"}},
		{"eth bad to_address", ETH, &txeth.SigningInput{
			ToAddress: "0xnothex",
			Transaction: &txeth.Transaction{TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{Amount: mustHexTx(t, "01")},
			}},
		}},
		{"eth erc20 bad recipient", ETH, &txeth.SigningInput{
			ToAddress: "0x6b175474e89094c44da98b954eedeac495271d0f",
			Transaction: &txeth.Transaction{TransactionOneof: &txeth.Transaction_Erc20Transfer{
				Erc20Transfer: &txeth.Transaction_ERC20Transfer{To: "0xbad", Amount: mustHexTx(t, "01")},
			}},
		}},
		{"eth unsupported tx_mode", ETH, &txeth.SigningInput{
			TxMode:    3, // 0 legacy, 1 eip-2930, 2 eip-1559 are valid; 3 is not
			ToAddress: "0x3535353535353535353535353535353535353535",
			Transaction: &txeth.Transaction{TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{Amount: mustHexTx(t, "01")},
			}},
		}},
		{"tron missing transaction", TRX, &txtron.SigningInput{}},
		{"tron bad owner", TRX, &txtron.SigningInput{Transaction: &txtron.Transaction{
			ContractOneof: &txtron.Transaction_Transfer{Transfer: &txtron.TransferContract{OwnerAddress: "zzz", ToAddress: "zzz", Amount: 1}},
		}}},
		{"ripple missing payment", XRP, &txripple.SigningInput{}},
		{"ripple bad account", XRP, &txripple.SigningInput{Account: "notxrp", Payment: &txripple.Payment{Destination: "rU893viamSnsfP3zjzM2KPxjqZjXSXK6VF", Amount: 1}}},
		{"cosmos missing send", ATOM, &txcosmos.SigningInput{Fee: &txcosmos.Fee{Denom: "muon", Amount: "1", Gas: 1}}},
		{"cosmos missing fee", ATOM, &txcosmos.SigningInput{Send: &txcosmos.SendCoinsMessage{FromAddress: "a", ToAddress: "b", Denom: "muon", Amount: "1"}}},
		{"solana missing transfer", SOL, &txsolana.SigningInput{RecentBlockhash: "11111111111111111111111111111111"}},
		{"solana bad recipient", SOL, &txsolana.SigningInput{
			RecentBlockhash: "11111111111111111111111111111111",
			TransactionType: &txsolana.SigningInput_TransferTransaction{TransferTransaction: &txsolana.Transfer{Recipient: "0", Value: 1}},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Each family validates with its own curve-appropriate wallet where the
			// key matters; for pure input-shape guards the ETH key-only wallet is
			// rejected on curve mismatch for non-secp256k1 coins, so build a fresh
			// seed wallet for those.
			tw := w
			if tc.symbol == SOL {
				sw, err := FromMnemonic(txTestMnemonic)
				if err != nil {
					t.Fatalf("FromMnemonic: %v", err)
				}
				defer sw.Destroy()
				tw = sw
			}
			_, err := tw.SignTransaction(tc.symbol, 0, tc.input)
			if !errors.Is(err, ErrTxInput) {
				t.Fatalf("%s: error = %v, want ErrTxInput", tc.name, err)
			}
		})
	}
}
