package hdwallet

import (
	"strings"
	"testing"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// scWalletWallet returns a wallet for the canonical mnemonic and asserts the
// ETH address matches the expected value, confirming derivation is correct.
func scWalletWallet(t *testing.T) *HDWallet {
	t.Helper()
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	addr, err := w.Address(ETH)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	const wantAddr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
	if !strings.EqualFold(addr, wantAddr) {
		t.Fatalf("ETH address = %s, want %s", addr, wantAddr)
	}
	return w
}

// signSCWalletTx signs the input and decodes the resulting tx.
// It asserts the outer tx.to == wantTo (the smart wallet address).
func signSCWalletTx(t *testing.T, w *HDWallet, in *txeth.SigningInput, wantTo string) *txeth.SigningOutput {
	t.Helper()
	out, err := w.SignTransaction(ETH, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	so := out.(*txeth.SigningOutput)
	encoded := so.GetEncoded()
	if len(encoded) == 0 {
		t.Fatal("encoded is empty")
	}
	dec, err := DecodeEthereumTx(encoded)
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if !strings.EqualFold(dec.To, wantTo) {
		t.Fatalf("outer tx.to = %s, want smart wallet %s", dec.To, wantTo)
	}
	// Value on the outer tx must be zero (inner value goes into calldata).
	if dec.Value != nil && dec.Value.Sign() != 0 {
		t.Fatalf("outer tx.value = %s, want 0", dec.Value)
	}
	return so
}

const scSmartWallet = "0xb16Db98B365B1f89191996942612B14F1Da4Bd5f"

// TestSCWalletExecute_SimpleAccount signs a single-call SimpleAccount execute tx
// and verifies structural correctness (self-consistency; no standalone TWC vector).
func TestSCWalletExecute_SimpleAccount(t *testing.T) {
	w := scWalletWallet(t)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               []byte{0x01},
		Nonce:                 []byte{0x01},
		TxMode:                2, // EIP-1559
		GasLimit:              []byte{0x01, 0x86, 0xa0},
		MaxFeePerGas:          []byte{0x3b, 0x9a, 0xca, 0x00},
		MaxInclusionFeePerGas: []byte{0x3b, 0x9a, 0xca, 0x00},
		ToAddress:             scSmartWallet,
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_ScWalletExecute{
				ScWalletExecute: &txeth.SCWalletExecute{
					WalletType:     txeth.SCWalletType_SC_SIMPLE_ACCOUNT,
					InnerToAddress: "0x1111111111111111111111111111111111111111",
					Transaction: &txeth.Transaction{
						TransactionOneof: &txeth.Transaction_Transfer_{
							Transfer: &txeth.Transaction_Transfer{
								Amount: []byte{0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00},
							},
						},
					},
				},
			},
		},
	}
	so := signSCWalletTx(t, w, in, scSmartWallet)
	// Data must begin with execute() selector.
	execSel := ABIFunctionSelector("execute", []string{"address", "uint256", "bytes"})
	dec, _ := DecodeEthereumTx(so.GetEncoded())
	if len(dec.Data) < 4 {
		t.Fatal("data too short to contain selector")
	}
	for i, b := range execSel {
		if dec.Data[i] != b {
			t.Fatalf("selector mismatch at byte %d: got 0x%02x want 0x%02x", i, dec.Data[i], b)
		}
	}
}

// TestSCWalletExecute_Biz4337 verifies the BIZ_4337 executeBatch selector path
// with a single inner call (wraps into executeBatch(address[],bytes[])).
func TestSCWalletExecute_Biz4337(t *testing.T) {
	w := scWalletWallet(t)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               []byte{0x01},
		Nonce:                 []byte{0x02},
		TxMode:                2,
		GasLimit:              []byte{0x02, 0x00, 0x00},
		MaxFeePerGas:          []byte{0x3b, 0x9a, 0xca, 0x00},
		MaxInclusionFeePerGas: []byte{0x3b, 0x9a, 0xca, 0x00},
		ToAddress:             scSmartWallet,
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_ScWalletExecute{
				ScWalletExecute: &txeth.SCWalletExecute{
					WalletType:     txeth.SCWalletType_BIZ_4337,
					InnerToAddress: "0x2222222222222222222222222222222222222222",
					Transaction: &txeth.Transaction{
						TransactionOneof: &txeth.Transaction_Transfer_{
							Transfer: &txeth.Transaction_Transfer{
								Amount: []byte{0x01},
							},
						},
					},
				},
			},
		},
	}
	so := signSCWalletTx(t, w, in, scSmartWallet)
	execBatchSel := ABIFunctionSelector("executeBatch", []string{"address[]", "bytes[]"})
	dec, _ := DecodeEthereumTx(so.GetEncoded())
	if len(dec.Data) < 4 {
		t.Fatal("data too short")
	}
	for i, b := range execBatchSel {
		if dec.Data[i] != b {
			t.Fatalf("selector mismatch at byte %d: got 0x%02x want 0x%02x", i, dec.Data[i], b)
		}
	}
}

// TestSCWalletBatch_SimpleAccount signs a two-call SimpleAccount executeBatch tx.
func TestSCWalletBatch_SimpleAccount(t *testing.T) {
	w := scWalletWallet(t)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               []byte{0x01},
		Nonce:                 []byte{0x03},
		TxMode:                2,
		GasLimit:              []byte{0x03, 0x00, 0x00},
		MaxFeePerGas:          []byte{0x3b, 0x9a, 0xca, 0x00},
		MaxInclusionFeePerGas: []byte{0x3b, 0x9a, 0xca, 0x00},
		ToAddress:             scSmartWallet,
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_ScWalletBatch{
				ScWalletBatch: &txeth.SCWalletBatch{
					WalletType: txeth.SCWalletType_SC_SIMPLE_ACCOUNT,
					Calls: []*txeth.BatchedCall{
						{
							Address: "0x1111111111111111111111111111111111111111",
							Amount:  []byte{0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00},
							Payload: nil,
						},
						{
							Address: "0x2222222222222222222222222222222222222222",
							Amount:  []byte{0x01},
							Payload: []byte{0xca, 0xfe},
						},
					},
				},
			},
		},
	}
	so := signSCWalletTx(t, w, in, scSmartWallet)
	execBatchSel := ABIFunctionSelector("executeBatch", []string{"address[]", "uint256[]", "bytes[]"})
	dec, _ := DecodeEthereumTx(so.GetEncoded())
	if len(dec.Data) < 4 {
		t.Fatal("data too short")
	}
	for i, b := range execBatchSel {
		if dec.Data[i] != b {
			t.Fatalf("selector mismatch at byte %d: got 0x%02x want 0x%02x", i, dec.Data[i], b)
		}
	}
}

// TestSCWalletBatch_Biz4337 exercises BIZ_4337 executeBatch(address[],bytes[]).
func TestSCWalletBatch_Biz4337(t *testing.T) {
	w := scWalletWallet(t)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               []byte{0x01},
		Nonce:                 []byte{0x04},
		TxMode:                2,
		GasLimit:              []byte{0x04, 0x00, 0x00},
		MaxFeePerGas:          []byte{0x3b, 0x9a, 0xca, 0x00},
		MaxInclusionFeePerGas: []byte{0x3b, 0x9a, 0xca, 0x00},
		ToAddress:             scSmartWallet,
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_ScWalletBatch{
				ScWalletBatch: &txeth.SCWalletBatch{
					WalletType: txeth.SCWalletType_BIZ_4337,
					Calls: []*txeth.BatchedCall{
						{
							Address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
							Amount:  nil,
							Payload: []byte{0xde, 0xad, 0xbe, 0xef},
						},
					},
				},
			},
		},
	}
	so := signSCWalletTx(t, w, in, scSmartWallet)
	execBatchSel := ABIFunctionSelector("executeBatch", []string{"address[]", "bytes[]"})
	dec, _ := DecodeEthereumTx(so.GetEncoded())
	if len(dec.Data) < 4 {
		t.Fatal("data too short")
	}
	for i, b := range execBatchSel {
		if dec.Data[i] != b {
			t.Fatalf("selector mismatch at byte %d: got 0x%02x want 0x%02x", i, dec.Data[i], b)
		}
	}
}

// TestSCWalletBatch_Biz exercises BIZ executeBatch(address[],uint256[],bytes[]).
func TestSCWalletBatch_Biz(t *testing.T) {
	w := scWalletWallet(t)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               []byte{0x01},
		Nonce:                 []byte{0x05},
		TxMode:                2,
		GasLimit:              []byte{0x05, 0x00, 0x00},
		MaxFeePerGas:          []byte{0x3b, 0x9a, 0xca, 0x00},
		MaxInclusionFeePerGas: []byte{0x3b, 0x9a, 0xca, 0x00},
		ToAddress:             scSmartWallet,
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_ScWalletBatch{
				ScWalletBatch: &txeth.SCWalletBatch{
					WalletType: txeth.SCWalletType_BIZ,
					Calls: []*txeth.BatchedCall{
						{
							Address: "0x3333333333333333333333333333333333333333",
							Amount:  []byte{0x0a},
							Payload: []byte{0x01, 0x02},
						},
						{
							Address: "0x4444444444444444444444444444444444444444",
							Amount:  nil,
							Payload: nil,
						},
					},
				},
			},
		},
	}
	so := signSCWalletTx(t, w, in, scSmartWallet)
	execBatchSel := ABIFunctionSelector("executeBatch", []string{"address[]", "uint256[]", "bytes[]"})
	dec, _ := DecodeEthereumTx(so.GetEncoded())
	if len(dec.Data) < 4 {
		t.Fatal("data too short")
	}
	for i, b := range execBatchSel {
		if dec.Data[i] != b {
			t.Fatalf("selector mismatch at byte %d: got 0x%02x want 0x%02x", i, dec.Data[i], b)
		}
	}
}
