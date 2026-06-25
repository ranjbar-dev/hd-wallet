package hdwallet

import (
	"encoding/hex"
	"testing"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// Ethereum / EVM transaction signing verified against Trust Wallet Core's
// AnySigner test vectors. Each case signs with TWC's fixed test private key and
// asserts the encoded signed transaction equals TWC's exact hex output. A wrong
// preimage, RLP layout, v value or signature would change the bytes, so these
// pin correctness to an authoritative external source.

// mustHexTx decodes a hex string (optionally 0x-prefixed, any case, odd-length
// padded) into bytes or fails the test. Distinct from slip10_test.go's mustHex,
// which uses strict even-length hex.DecodeString.
func mustHexTx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hexToBytes(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// ethWallet builds a key-only wallet from a TWC fixed test private key.
func ethWallet(t *testing.T, privHex string) *HDWallet {
	t.Helper()
	w, err := FromPrivateKeyBytes(mustHexTx(t, privHex), Secp256k1)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	return w
}

// TWC Ethereum SignerTests.cpp / TestEthereumTransactionSigner.kt: legacy
// (EIP-155) native transfer of 1 ETH. The canonical Vitalik test vector.
func TestSignTxEthereumLegacyNative(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "01"),
		Nonce:     mustHexTx(t, "09"),
		TxMode:    0,
		GasPrice:  mustHexTx(t, "04a817c800"),
		GasLimit:  mustHexTx(t, "5208"),
		ToAddress: "0x3535353535353535353535353535353535353535",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: mustHexTx(t, "0de0b6b3a7640000"),
				},
			},
		},
	}
	const want = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
	assertEthSigned(t, w, in, want)
}

// TWC legacy ERC-20 DAI transfer.
func TestSignTxEthereumLegacyERC20(t *testing.T) {
	w := ethWallet(t, "0x608dcb1742bb3fb7aec002074e3420e4fab7d00cced79ccdac53ed5b27138151")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "01"),
		Nonce:     mustHexTx(t, "00"),
		TxMode:    0,
		GasPrice:  mustHexTx(t, "09c7652400"),
		GasLimit:  mustHexTx(t, "0130B9"),
		ToAddress: "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI contract
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Erc20Transfer{
				Erc20Transfer: &txeth.Transaction_ERC20Transfer{
					To:     "0x5322b34c88ed0691971bf52a7047448f0f4efc84",
					Amount: mustHexTx(t, "1bc16d674ec80000"),
				},
			},
		},
	}
	const want = "f8aa808509c7652400830130b9946b175474e89094c44da98b954eedeac495271d0f80b844a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec8000025a0724c62ad4fbf47346b02de06e603e013f26f26b56fdc0be7ba3d6273401d98cea0032131cae15da7ddcda66963e8bef51ca0d9962bfef0547d3f02597a4a58c931"
	assertEthSigned(t, w, in, want)
}

// TWC EIP-1559 (type-2) ERC-20 DAI transfer.
func TestSignTxEthereumEIP1559ERC20(t *testing.T) {
	w := ethWallet(t, "0x608dcb1742bb3fb7aec002074e3420e4fab7d00cced79ccdac53ed5b27138151")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "00"),
		TxMode:                2,
		GasLimit:              mustHexTx(t, "0130B9"),
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "B2D05E00"),
		ToAddress:             "0x6b175474e89094c44da98b954eedeac495271d0f",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Erc20Transfer{
				Erc20Transfer: &txeth.Transaction_ERC20Transfer{
					To:     "0x5322b34c88ed0691971bf52a7047448f0f4efc84",
					Amount: mustHexTx(t, "1bc16d674ec80000"),
				},
			},
		},
	}
	const want = "02f8b00180847735940084b2d05e00830130b9946b175474e89094c44da98b954eedeac495271d0f80b844a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec80000c080a0adfcfdf98d4ed35a8967a0c1d78b42adb7c5d831cf5a3272654ec8f8bcd7be2ea011641e065684f6aa476f4fd250aa46cd0b44eccdb0a6e1650d658d1998684cdf"
	assertEthSigned(t, w, in, want)
}

// TWC EIP-1559 native transfer WITH data (swift testSignStakeRocketPool):
// value transfer of 0.01 ETH plus a 0xd0e30db0 deposit() call. Exercises the
// type-2 native path and the optional data field together.
func TestSignTxEthereumEIP1559NativeWithData(t *testing.T) {
	w := ethWallet(t, "9f56448d33de406db1561aae15fce64bdf0e9706ff15c45d4409e8fcbfd1a498")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "01"),
		TxMode:                2,
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
	}
	const want = "02f8770101843b9aca0085067ef83700830320c8942cac916b2a963bf162f076c0a8a4a8200bcfbfb4872386f26fc1000084d0e30db0c080a0fb39e5079d7a0598ec45785d73a06b91fe1db707b9c6a150c87ffce2492c66d6a07fbd43a6f4733b2b4f98ad1bc4678ea2615f5edf56ad91408337adec2f07c0ac"
	assertEthSigned(t, w, in, want)
}

// accessListFixture is the single EIP-2930 access tuple shared by the
// access-list vectors below: address 0x..01 with storage keys 0x..00 and 0x..07.
func accessListFixture() []*txeth.Access {
	return []*txeth.Access{{
		Address: "0x0000000000000000000000000000000000000001",
		StoredKeys: [][]byte{
			make([]byte, 32),
			append(make([]byte, 31), 0x07),
		},
	}}
}

// EIP-2930 (type-1) access-list native transfer. Vector generated from the
// reference EVM implementation (go-ethereum types.SignTx + NewLondonSigner) with
// the canonical 0x4646…46 key — the same byte-for-byte oracle role TWC plays for
// the other vectors. A wrong access-list RLP, envelope byte or v would change it.
func TestSignTxEthereumEIP2930AccessList(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "01"),
		Nonce:     mustHexTx(t, "09"),
		TxMode:    1,
		GasPrice:  mustHexTx(t, "04a817c800"),
		GasLimit:  mustHexTx(t, "5208"),
		ToAddress: "0x3535353535353535353535353535353535353535",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: mustHexTx(t, "0de0b6b3a7640000"),
				},
			},
		},
		AccessList: accessListFixture(),
	}
	const want = "01f8ca01098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080f85bf859940000000000000000000000000000000000000001f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000701a0f58c03fa733a8858a5bb0a200f806b3330413d0e23c63085b7c31edf71b7c2b1a02c374fbb0e16af843dd6cbfb43c79d5edae27198f9e47395ec0cbed9de31c2d8"
	assertEthSigned(t, w, in, want)
}

// EIP-1559 (type-2) transfer WITH a non-empty access list. Same go-ethereum
// oracle and key. Confirms the access list is serialized identically in the
// type-2 payload and signed bytes.
func TestSignTxEthereumEIP1559AccessList(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "00"),
		TxMode:                2,
		GasLimit:              mustHexTx(t, "0130B9"),
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "B2D05E00"),
		ToAddress:             "0x6b175474e89094c44da98b954eedeac495271d0f",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: nil, // 0
				},
			},
		},
		AccessList: accessListFixture(),
	}
	const want = "02f8c70180847735940084b2d05e00830130b9946b175474e89094c44da98b954eedeac495271d0f8080f85bf859940000000000000000000000000000000000000001f842a00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000780a0486b96125b97b2584a07d47f3e640d41c764757ade8a0ee38e6dd05bef32384ba05825a0ee2dcd37a75435169ef1d493a2c91f2b0ead092cba36ca0d87ce579fd8"
	assertEthSigned(t, w, in, want)
}

// An empty/absent access list must reproduce the existing no-access-list type-2
// vector byte-for-byte (the access-list refactor must not alter prior output).
func TestSignTxEthereumEIP1559EmptyAccessListUnchanged(t *testing.T) {
	w := ethWallet(t, "0x608dcb1742bb3fb7aec002074e3420e4fab7d00cced79ccdac53ed5b27138151")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "00"),
		TxMode:                2,
		GasLimit:              mustHexTx(t, "0130B9"),
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "B2D05E00"),
		ToAddress:             "0x6b175474e89094c44da98b954eedeac495271d0f",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Erc20Transfer{
				Erc20Transfer: &txeth.Transaction_ERC20Transfer{
					To:     "0x5322b34c88ed0691971bf52a7047448f0f4efc84",
					Amount: mustHexTx(t, "1bc16d674ec80000"),
				},
			},
		},
		AccessList: nil, // empty
	}
	const want = "02f8b00180847735940084b2d05e00830130b9946b175474e89094c44da98b954eedeac495271d0f80b844a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec80000c080a0adfcfdf98d4ed35a8967a0c1d78b42adb7c5d831cf5a3272654ec8f8bcd7be2ea011641e065684f6aa476f4fd250aa46cd0b44eccdb0a6e1650d658d1998684cdf"
	assertEthSigned(t, w, in, want)
}

// assertEthSigned signs in for ETH and asserts the encoded hex equals want.
func assertEthSigned(t *testing.T, w *HDWallet, in *txeth.SigningInput, want string) {
	t.Helper()
	out, err := w.SignTransaction(ETH, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	eo, ok := out.(*txeth.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *ethereum.SigningOutput", out)
	}
	if eo.GetError() != "" {
		t.Fatalf("signing error: %s", eo.GetError())
	}
	if got := hex.EncodeToString(eo.GetEncoded()); got != want {
		t.Fatalf("encoded mismatch:\n got  %s\n want %s", got, want)
	}
	if eo.GetEncodedHex() != want {
		t.Fatalf("encoded_hex mismatch:\n got  %s\n want %s", eo.GetEncodedHex(), want)
	}
	// tx_id is the canonical Ethereum tx hash over the (already locked) encoded
	// bytes: "0x" + hex(keccak256(encoded)). Derived from the pinned output, so
	// it both pins the field and proves it is wired for every tx mode.
	wantTxID := "0x" + hex.EncodeToString(keccak256(eo.GetEncoded()))
	if eo.GetTxId() != wantTxID {
		t.Fatalf("tx_id mismatch:\n got  %s\n want %s", eo.GetTxId(), wantTxID)
	}
}
