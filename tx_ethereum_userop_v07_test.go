package hdwallet

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// TestSignTxUserOpV07_SelfConsistency signs a v0.7 UserOp and verifies ecrecover
// returns the wallet's ETH address at index 0.
// No standalone TWC SimpleAccount v0.7 AnySigner vector was found; this is a
// self-consistency test.
func TestSignTxUserOpV07_SelfConsistency(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	const wantAddr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

	in := &txeth.SigningInput{
		ChainId:               []byte{0x01},
		Nonce:                 []byte{0x00},
		TxMode:                6,                        // EthTxModeUserOpV07
		GasLimit:              []byte{0x01, 0x86, 0xa0}, // callGasLimit 100000
		MaxFeePerGas:          []byte{0x3b, 0x9a, 0xca, 0x00},
		MaxInclusionFeePerGas: []byte{0x3b, 0x9a, 0xca, 0x00},
		ToAddress:             "0x1111111111111111111111111111111111111111",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: []byte{0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00},
				},
			},
		},
		UserOperationV0_7: &txeth.UserOperationV0_7{
			EntryPoint:                    "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
			Sender:                        "0xb16Db98B365B1f89191996942612B14F1Da4Bd5f",
			PreVerificationGas:            []byte{0xb7, 0x08},
			VerificationGasLimit:          []byte{0x01, 0x86, 0xa0},
			PaymasterVerificationGasLimit: []byte{0x00},
			PaymasterPostOpGasLimit:       []byte{0x00},
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
	sig := so.GetEncoded()
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65", len(sig))
	}
	if v := sig[64]; v != 27 && v != 28 {
		t.Fatalf("v = %d, want 27/28", v)
	}
	hashHex := strings.TrimPrefix(so.GetTxId(), "0x")
	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != 32 {
		t.Fatalf("bad tx_id: %v", err)
	}
	recovered, err := RecoverEthereumAddress(hash, sig)
	if err != nil {
		t.Fatalf("RecoverEthereumAddress: %v", err)
	}
	if !strings.EqualFold(recovered, wantAddr) {
		t.Fatalf("recovered %s, want %s", recovered, wantAddr)
	}
}

// TestSignTxUserOpV07_MissingMeta ensures mode 6 returns error without meta.
func TestSignTxUserOpV07_MissingMeta(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()
	in := &txeth.SigningInput{
		ChainId: []byte{0x01}, TxMode: 6,
		GasLimit: []byte{0x01},
		Transaction: &txeth.Transaction{TransactionOneof: &txeth.Transaction_Transfer_{
			Transfer: &txeth.Transaction_Transfer{Amount: []byte{0x01}},
		}},
	}
	_, err = w.SignTransaction(ETH, 0, in)
	if err == nil {
		t.Fatal("expected error for missing user_operation_v0_7, got nil")
	}
}

// TestUserOpV07HashDeterminism verifies userOpV07Hash is stable and that different
// chainIDs give different hashes.
func TestUserOpV07HashDeterminism(t *testing.T) {
	sender := make([]byte, 20)
	sender[19] = 0xaa
	ep := make([]byte, 20)
	ep[19] = 0xee
	zero := new(big.Int)
	one := big.NewInt(1)

	h1 := userOpV07Hash(sender, ep, zero, nil, nil, []byte{0xca, 0xfe},
		one, one, zero, one, one, nil, zero, zero, nil, big.NewInt(1))
	h2 := userOpV07Hash(sender, ep, zero, nil, nil, []byte{0xca, 0xfe},
		one, one, zero, one, one, nil, zero, zero, nil, big.NewInt(1))
	if string(h1) != string(h2) {
		t.Fatal("not deterministic")
	}
	h3 := userOpV07Hash(sender, ep, zero, nil, nil, []byte{0xca, 0xfe},
		one, one, zero, one, one, nil, zero, zero, nil, big.NewInt(137))
	if string(h1) == string(h3) {
		t.Fatal("different chainID should give different hash")
	}
	if len(h1) != 32 {
		t.Fatalf("hash len = %d, want 32", len(h1))
	}
}
