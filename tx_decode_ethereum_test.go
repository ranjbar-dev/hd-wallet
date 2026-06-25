package hdwallet

import (
	"bytes"
	"math/big"
	"testing"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// "What am I signing?" EVM decoder, proven three ways:
//   - round-trip: sign a tx with the EXISTING signer (SignTransaction) and assert
//     DecodeEthereumTx returns the same to/value/nonce/gas the SigningInput held;
//   - external vector: decode published go-ethereum / TWC reference raw txs (the
//     same byte-for-byte hex the signer tests pin) and assert the fields, incl. an
//     ERC-20 transfer whose calldata decodes to the right recipient/amount;
//   - malformed: truncated/garbage bytes return ErrTxDecode, never a panic.

// bigHex parses a (0x-optional) hex string as a big.Int via the existing helper.
func bigHex(t *testing.T, s string) *big.Int {
	t.Helper()
	return new(big.Int).SetBytes(mustHexTx(t, s))
}

// eqBig compares two big.Ints, treating a nil as 0 (the signer drops a 0 quantity
// to the empty RLP string, which decodes back to 0).
func eqBig(a, b *big.Int) bool {
	az := a == nil || a.Sign() == 0
	bz := b == nil || b.Sign() == 0
	if az || bz {
		return az && bz
	}
	return a.Cmp(b) == 0
}

func mustBig(t *testing.T, got, want *big.Int, field string) {
	t.Helper()
	if !eqBig(got, want) {
		t.Fatalf("%s mismatch: got %v want %v", field, got, want)
	}
}

// TestDecodeEthereumRoundTripLegacy signs a legacy native transfer with the real
// signer and asserts the decoder recovers the same fields.
func TestDecodeEthereumRoundTripLegacy(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "01"),
		Nonce:     mustHexTx(t, "09"),
		TxMode:    EthTxModeLegacy,
		GasPrice:  mustHexTx(t, "04a817c800"),
		GasLimit:  mustHexTx(t, "5208"),
		ToAddress: "0x3535353535353535353535353535353535353535",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{Amount: mustHexTx(t, "0de0b6b3a7640000")},
			},
		},
	}
	out, err := w.SignTransaction(ETH, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	encoded := out.(*txeth.SigningOutput).GetEncoded()

	f, err := DecodeEthereumTx(encoded)
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if f.Type != EthTxLegacy {
		t.Fatalf("type = %v, want legacy", f.Type)
	}
	if f.To != "0x3535353535353535353535353535353535353535" {
		t.Fatalf("to = %s", f.To)
	}
	mustBig(t, f.Nonce, bigHex(t, "09"), "nonce")
	mustBig(t, f.GasPrice, bigHex(t, "04a817c800"), "gasPrice")
	mustBig(t, f.GasLimit, bigHex(t, "5208"), "gasLimit")
	mustBig(t, f.Value, bigHex(t, "0de0b6b3a7640000"), "value")
	mustBig(t, f.ChainID, big.NewInt(1), "chainId")
	if f.R == nil || f.S == nil || f.V == nil {
		t.Fatalf("missing signature scalars")
	}
}

// TestDecodeEthereumRoundTrip1559 signs a type-2 native transfer with data and a
// non-empty access list, then decodes and checks every field including the list.
func TestDecodeEthereumRoundTrip1559(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "07"),
		TxMode:                EthTxModeEIP1559,
		GasLimit:              mustHexTx(t, "0320c8"),
		MaxInclusionFeePerGas: mustHexTx(t, "3b9aca00"),
		MaxFeePerGas:          mustHexTx(t, "067ef83700"),
		ToAddress:             "0x2cac916b2a963bf162f076c0a8a4a8200bcfbfb4",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: mustHexTx(t, "2386f26fc10000"),
					Data:   mustHexTx(t, "d0e30db0"),
				},
			},
		},
		AccessList: accessListFixture(),
	}
	out, err := w.SignTransaction(ETH, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	encoded := out.(*txeth.SigningOutput).GetEncoded()

	f, err := DecodeEthereumTx(encoded)
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if f.Type != EthTxEIP1559 {
		t.Fatalf("type = %v, want eip-1559", f.Type)
	}
	mustBig(t, f.ChainID, big.NewInt(1), "chainId")
	mustBig(t, f.Nonce, big.NewInt(7), "nonce")
	mustBig(t, f.MaxPriorityFeePerGas, bigHex(t, "3b9aca00"), "maxPriority")
	mustBig(t, f.MaxFeePerGas, bigHex(t, "067ef83700"), "maxFee")
	mustBig(t, f.GasLimit, bigHex(t, "0320c8"), "gasLimit")
	mustBig(t, f.Value, bigHex(t, "2386f26fc10000"), "value")
	if !bytes.Equal(f.Data, mustHexTx(t, "d0e30db0")) {
		t.Fatalf("data = %x", f.Data)
	}
	if len(f.AccessList) != 1 {
		t.Fatalf("access list len = %d, want 1", len(f.AccessList))
	}
	if f.AccessList[0].Address != "0x0000000000000000000000000000000000000001" {
		t.Fatalf("access addr = %s", f.AccessList[0].Address)
	}
	if len(f.AccessList[0].StorageKeys) != 2 {
		t.Fatalf("storage keys = %d, want 2", len(f.AccessList[0].StorageKeys))
	}
}

// TestDecodeEthereumVectorLegacy decodes the canonical Vitalik legacy tx hex
// (the pinned TWC/go-ethereum vector) and asserts the fields.
func TestDecodeEthereumVectorLegacy(t *testing.T) {
	const raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
	f, err := DecodeEthereumTx(mustHexTx(t, raw))
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if f.Type != EthTxLegacy {
		t.Fatalf("type = %v", f.Type)
	}
	mustBig(t, f.Nonce, big.NewInt(9), "nonce")
	mustBig(t, f.GasPrice, bigHex(t, "04a817c800"), "gasPrice")
	mustBig(t, f.GasLimit, big.NewInt(21000), "gasLimit")
	mustBig(t, f.Value, bigHex(t, "0de0b6b3a7640000"), "value")
	if f.To != "0x3535353535353535353535353535353535353535" {
		t.Fatalf("to = %s", f.To)
	}
	mustBig(t, f.ChainID, big.NewInt(1), "chainId") // v=0x25=37 => (37-35)/2 = 1
	if f.ERC20 != nil {
		t.Fatalf("native transfer should not decode as ERC-20")
	}
}

// TestDecodeEthereumVectorERC20 decodes the pinned legacy ERC-20 DAI transfer and
// asserts the calldata decodes to the right method/recipient/amount.
func TestDecodeEthereumVectorERC20(t *testing.T) {
	const raw = "f8aa808509c7652400830130b9946b175474e89094c44da98b954eedeac495271d0f80b844a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec8000025a0724c62ad4fbf47346b02de06e603e013f26f26b56fdc0be7ba3d6273401d98cea0032131cae15da7ddcda66963e8bef51ca0d9962bfef0547d3f02597a4a58c931"
	f, err := DecodeEthereumTx(mustHexTx(t, raw))
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	// The DAI contract is the `to`; native value is 0.
	if f.To != "0x6b175474e89094c44da98b954eedeac495271d0f" {
		t.Fatalf("to (contract) = %s", f.To)
	}
	mustBig(t, f.Value, big.NewInt(0), "value")
	if f.ERC20 == nil {
		t.Fatalf("expected ERC-20 call to be recognised")
	}
	if f.ERC20.Method != "transfer" {
		t.Fatalf("method = %s, want transfer", f.ERC20.Method)
	}
	if f.ERC20.Recipient != "0x5322b34c88ed0691971bf52a7047448f0f4efc84" {
		t.Fatalf("recipient = %s", f.ERC20.Recipient)
	}
	mustBig(t, f.ERC20.Amount, bigHex(t, "1bc16d674ec80000"), "erc20 amount")
}

// TestDecodeEthereumVector1559 decodes the pinned EIP-1559 ERC-20 transfer.
func TestDecodeEthereumVector1559(t *testing.T) {
	const raw = "02f8b00180847735940084b2d05e00830130b9946b175474e89094c44da98b954eedeac495271d0f80b844a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec80000c080a0adfcfdf98d4ed35a8967a0c1d78b42adb7c5d831cf5a3272654ec8f8bcd7be2ea011641e065684f6aa476f4fd250aa46cd0b44eccdb0a6e1650d658d1998684cdf"
	f, err := DecodeEthereumTx(mustHexTx(t, raw))
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if f.Type != EthTxEIP1559 {
		t.Fatalf("type = %v, want eip-1559", f.Type)
	}
	mustBig(t, f.ChainID, big.NewInt(1), "chainId")
	mustBig(t, f.Nonce, big.NewInt(0), "nonce")
	mustBig(t, f.MaxPriorityFeePerGas, bigHex(t, "77359400"), "maxPriority")
	mustBig(t, f.MaxFeePerGas, bigHex(t, "b2d05e00"), "maxFee")
	mustBig(t, f.GasLimit, bigHex(t, "0130b9"), "gasLimit")
	if len(f.AccessList) != 0 {
		t.Fatalf("access list should be empty, got %d", len(f.AccessList))
	}
	if f.ERC20 == nil || f.ERC20.Method != "transfer" {
		t.Fatalf("expected ERC-20 transfer")
	}
	mustBig(t, f.ERC20.Amount, bigHex(t, "1bc16d674ec80000"), "erc20 amount")
}

// TestDecodeEthereumVector2930 decodes the pinned EIP-2930 access-list tx and
// checks the access list shape.
func TestDecodeEthereumVector2930(t *testing.T) {
	const raw = "01f8ca01098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080f85bf859940000000000000000000000000000000000000001f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000701a0f58c03fa733a8858a5bb0a200f806b3330413d0e23c63085b7c31edf71b7c2b1a02c374fbb0e16af843dd6cbfb43c79d5edae27198f9e47395ec0cbed9de31c2d8"
	f, err := DecodeEthereumTx(mustHexTx(t, raw))
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if f.Type != EthTxEIP2930 {
		t.Fatalf("type = %v, want eip-2930", f.Type)
	}
	mustBig(t, f.ChainID, big.NewInt(1), "chainId")
	mustBig(t, f.GasPrice, bigHex(t, "04a817c800"), "gasPrice")
	mustBig(t, f.Value, bigHex(t, "0de0b6b3a7640000"), "value")
	if len(f.AccessList) != 1 || len(f.AccessList[0].StorageKeys) != 2 {
		t.Fatalf("access list shape wrong: %+v", f.AccessList)
	}
	if f.AccessList[0].Address != "0x0000000000000000000000000000000000000001" {
		t.Fatalf("access addr = %s", f.AccessList[0].Address)
	}
}

// TestDecodeEthereumContractCreation decodes a tx with an empty `to` (deploy) and
// asserts To is empty.
func TestDecodeEthereumContractCreation(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()
	in := &txeth.SigningInput{
		ChainId:  mustHexTx(t, "01"),
		Nonce:    mustHexTx(t, "00"),
		TxMode:   EthTxModeLegacy,
		GasPrice: mustHexTx(t, "04a817c800"),
		GasLimit: mustHexTx(t, "0186a0"),
		// no to_address => contract creation
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_ContractGeneric_{
				ContractGeneric: &txeth.Transaction_ContractGeneric{Data: mustHexTx(t, "600160005401600055")},
			},
		},
	}
	out, err := w.SignTransaction(ETH, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	f, err := DecodeEthereumTx(out.(*txeth.SigningOutput).GetEncoded())
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if f.To != "" {
		t.Fatalf("contract creation `to` should be empty, got %q", f.To)
	}
	if !bytes.Equal(f.Data, mustHexTx(t, "600160005401600055")) {
		t.Fatalf("init code mismatch: %x", f.Data)
	}
}

// TestDecodeEthereumMalformed asserts truncated / garbage input returns an error
// (never a panic).
func TestDecodeEthereumMalformed(t *testing.T) {
	full := mustHexTx(t, "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
	cases := map[string][]byte{
		"empty":                  {},
		"truncated legacy":       full[:20],
		"truncated 1559":         {0x02, 0xf8, 0xb0, 0x01},
		"bad prefix (string)":    {0x80},
		"low byte not a list":    {0x42, 0x43},
		"1559 payload not list":  {0x02, 0x05},
		"legacy wrong field cnt": mustHexTx(t, "c50102030405"), // 5-item list
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeEthereumTx(b); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}
