package hdwallet

import (
	"encoding/hex"
	"strings"
	"testing"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// TestSignTxUserOpV06_SelfConsistency signs a v0.6 UserOp for a Transfer inner
// transaction and verifies that ecrecover from the userOpHash returns the wallet's
// ETH address at index 0. This is a self-consistency test; no standalone TWC
// SimpleAccount v0.6 AnySigner vector was found (BarzTests use Barz-specific keys).
func TestSignTxUserOpV06_SelfConsistency(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	// Known ETH address for canonicalMnemonic at index 0.
	const wantAddr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

	// Use a known EntryPoint v0.6 address.
	entryPoint := "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"

	in := &txeth.SigningInput{
		ChainId:               []byte{0x01},
		Nonce:                 []byte{0x00},
		TxMode:                5,                              // EthTxModeUserOp
		GasLimit:              []byte{0x01, 0x86, 0xa0},       // 100000 callGasLimit
		MaxFeePerGas:          []byte{0x3b, 0x9a, 0xca, 0x00}, // 1 Gwei
		MaxInclusionFeePerGas: []byte{0x3b, 0x9a, 0xca, 0x00},
		ToAddress:             "0x1111111111111111111111111111111111111111",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: []byte{0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00}, // 1e18
				},
			},
		},
		UserOperation: &txeth.UserOperationV0_6{
			EntryPoint:           entryPoint,
			Sender:               "0xb16Db98B365B1f89191996942612B14F1Da4Bd5f",
			InitCode:             nil,
			PreVerificationGas:   []byte{0xb7, 0x08},       // 46856
			VerificationGasLimit: []byte{0x01, 0x86, 0xa0}, // 100000
			PaymasterAndData:     nil,
		},
	}

	out, err := w.SignTransaction(ETH, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	so, ok := out.(*txeth.SigningOutput)
	if !ok {
		t.Fatalf("unexpected output type %T", out)
	}

	// Encoded = 65-byte signature.
	sig := so.GetEncoded()
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65", len(sig))
	}
	v := sig[64]
	if v != 27 && v != 28 {
		t.Fatalf("v = %d, want 27 or 28", v)
	}

	// TxId = "0x" + userOpHash hex (32 bytes → 64 hex chars + "0x" prefix = 66).
	if len(so.GetTxId()) != 66 {
		t.Fatalf("tx_id len = %d, want 66", len(so.GetTxId()))
	}
	hashHex := strings.TrimPrefix(so.GetTxId(), "0x")
	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != 32 {
		t.Fatalf("bad tx_id: %v", err)
	}

	// ecrecover must return the wallet's ETH address.
	recovered, err := RecoverEthereumAddress(hash, sig)
	if err != nil {
		t.Fatalf("RecoverEthereumAddress: %v", err)
	}
	if !strings.EqualFold(recovered, wantAddr) {
		t.Fatalf("recovered %s, want %s", recovered, wantAddr)
	}
}

// TestSignTxUserOpV06_MissingMeta ensures UserOp mode returns an error when
// user_operation is absent.
func TestSignTxUserOpV06_MissingMeta(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()
	in := &txeth.SigningInput{
		ChainId: []byte{0x01}, TxMode: 5,
		GasLimit: []byte{0x01},
		Transaction: &txeth.Transaction{TransactionOneof: &txeth.Transaction_Transfer_{
			Transfer: &txeth.Transaction_Transfer{Amount: []byte{0x01}},
		}},
	}
	_, err = w.SignTransaction(ETH, 0, in)
	if err == nil {
		t.Fatal("expected error for missing user_operation, got nil")
	}
}
