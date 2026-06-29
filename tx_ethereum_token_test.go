package hdwallet

import (
	"testing"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// TWC-vector-pinned tests for ERC-20 Approve, ERC-721 Transfer, and ERC-1155
// Transfer transaction types. Private key and expected hex are taken verbatim
// from Trust Wallet Core TWAnySignerTests.cpp.

const twcTokenPrivKey = "608dcb1742bb3fb7aec002074e3420e4fab7d00cced79ccdac53ed5b27138151"

// Vector 1: ERC-20 approve, legacy (EIP-155).
func TestSignTxERC20ApproveLegacy(t *testing.T) {
	w := ethWallet(t, twcTokenPrivKey)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "01"),
		Nonce:     mustHexTx(t, "00"),
		TxMode:    EthTxModeLegacy,
		GasPrice:  mustHexTx(t, "09c7652400"),
		GasLimit:  mustHexTx(t, "0130b9"),
		ToAddress: "0x6b175474e89094c44da98b954eedeac495271d0f",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Erc20Approve{
				Erc20Approve: &txeth.Transaction_ERC20Approve{
					Spender: "0x5322b34c88ed0691971bf52a7047448f0f4efc84",
					Amount:  mustHexTx(t, "1bc16d674ec80000"),
				},
			},
		},
	}
	const want = "f8aa808509c7652400830130b9946b175474e89094c44da98b954eedeac495271d0f80b844095ea7b30000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec8000025a0d8136d66da1e0ba8c7208d5c4f143167f54b89a0fe2e23440653bcca28b34dc1a049222a79339f1a9e4641cb4ad805c49c225ae704299ffc10627bf41c035c464a"
	assertEthSigned(t, w, in, want)
}

// Vector 2: ERC-20 approve, EIP-1559 (type-2).
func TestSignTxERC20ApproveEIP1559(t *testing.T) {
	w := ethWallet(t, twcTokenPrivKey)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "00"),
		TxMode:                EthTxModeEIP1559,
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "b2d05e00"),
		GasLimit:              mustHexTx(t, "0130b9"),
		ToAddress:             "0x6b175474e89094c44da98b954eedeac495271d0f",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Erc20Approve{
				Erc20Approve: &txeth.Transaction_ERC20Approve{
					Spender: "0x5322b34c88ed0691971bf52a7047448f0f4efc84",
					Amount:  mustHexTx(t, "1bc16d674ec80000"),
				},
			},
		},
	}
	const want = "02f8b00180847735940084b2d05e00830130b9946b175474e89094c44da98b954eedeac495271d0f80b844095ea7b30000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec80000c080a05a43dda3dc193480ee532a5ed67ba8fbd2e3afb9eee218f4fb955b415d592925a01300e5b5f51c8cd5bf80f018cea3fb347fae589e65355068ac44ffc996313c60"
	assertEthSigned(t, w, in, want)
}

// Vector 3: ERC-721 transferFrom, legacy (EIP-155).
func TestSignTxERC721TransferLegacy(t *testing.T) {
	w := ethWallet(t, twcTokenPrivKey)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "01"),
		Nonce:     mustHexTx(t, "00"),
		TxMode:    EthTxModeLegacy,
		GasPrice:  mustHexTx(t, "09c7652400"),
		GasLimit:  mustHexTx(t, "0130b9"),
		ToAddress: "0x4e45e92ed38f885d39a733c14f1817217a89d425",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Erc721Transfer{
				Erc721Transfer: &txeth.Transaction_ERC721Transfer{
					From:    "0x718046867b5b1782379a14eA4fc0c9b724DA94Fc",
					To:      "0x5322b34c88ed0691971bf52a7047448f0f4efc84",
					TokenId: mustHexTx(t, "23c47ee5"),
				},
			},
		},
	}
	const want = "f8ca808509c7652400830130b9944e45e92ed38f885d39a733c14f1817217a89d42580b86423b872dd000000000000000000000000718046867b5b1782379a14ea4fc0c9b724da94fc0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000000000000023c47ee526a0d38440a4dc140a4100d301eb49fcc35b64439e27d1d8dd9b55823dca04e6e659a03b5f56a57feabc3406f123d6f8198cd7d7e2ced7e2d58d375f076952ecd9ce88"
	assertEthSigned(t, w, in, want)
}

// Vector 4: ERC-721 transferFrom, EIP-1559 (type-2).
func TestSignTxERC721TransferEIP1559(t *testing.T) {
	w := ethWallet(t, twcTokenPrivKey)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "00"),
		TxMode:                EthTxModeEIP1559,
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "b2d05e00"),
		GasLimit:              mustHexTx(t, "0130b9"),
		ToAddress:             "0x4e45e92ed38f885d39a733c14f1817217a89d425",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Erc721Transfer{
				Erc721Transfer: &txeth.Transaction_ERC721Transfer{
					From:    "0x718046867b5b1782379a14eA4fc0c9b724DA94Fc",
					To:      "0x5322b34c88ed0691971bf52a7047448f0f4efc84",
					TokenId: mustHexTx(t, "23c47ee5"),
				},
			},
		},
	}
	const want = "02f8d00180847735940084b2d05e00830130b9944e45e92ed38f885d39a733c14f1817217a89d42580b86423b872dd000000000000000000000000718046867b5b1782379a14ea4fc0c9b724da94fc0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000000000000023c47ee5c080a0dbd591d1eac39bad62d7c158d5e1d55e7014d2218998f8980462e2f283f42d4aa05acadb904484a0fb5526a4c64b8addb8aac4f6548f90199e40eb787b79faed4a"
	assertEthSigned(t, w, in, want)
}

// Vector 5: ERC-1155 safeTransferFrom, legacy (EIP-155).
func TestSignTxERC1155TransferLegacy(t *testing.T) {
	w := ethWallet(t, twcTokenPrivKey)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "01"),
		Nonce:     mustHexTx(t, "00"),
		TxMode:    EthTxModeLegacy,
		GasPrice:  mustHexTx(t, "09c7652400"),
		GasLimit:  mustHexTx(t, "0130b9"),
		ToAddress: "0x4e45e92ed38f885d39a733c14f1817217a89d425",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Erc1155Transfer{
				Erc1155Transfer: &txeth.Transaction_ERC1155Transfer{
					From:    "0x718046867b5b1782379a14eA4fc0c9b724DA94Fc",
					To:      "0x5322b34c88ed0691971bf52a7047448f0f4efc84",
					TokenId: mustHexTx(t, "23c47ee5"),
					Value:   mustHexTx(t, "1bc16d674ec80000"),
					Data:    mustHexTx(t, "01020304"),
				},
			},
		},
	}
	const want = "f9014a808509c7652400830130b9944e45e92ed38f885d39a733c14f1817217a89d42580b8e4f242432a000000000000000000000000718046867b5b1782379a14ea4fc0c9b724da94fc0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000000000000023c47ee50000000000000000000000000000000000000000000000001bc16d674ec8000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000004010203040000000000000000000000000000000000000000000000000000000026a010315488201ac801ce346bffd1570de147615462d7e7db3cf08cf558465c6b79a06643943b24593bc3904a9fda63bb169881730994c973ab80f07d66a698064573"
	assertEthSigned(t, w, in, want)
}

// Vector 6: ERC-1155 safeTransferFrom, EIP-1559 (type-2).
func TestSignTxERC1155TransferEIP1559(t *testing.T) {
	w := ethWallet(t, twcTokenPrivKey)
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "00"),
		TxMode:                EthTxModeEIP1559,
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "b2d05e00"),
		GasLimit:              mustHexTx(t, "0130b9"),
		ToAddress:             "0x4e45e92ed38f885d39a733c14f1817217a89d425",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Erc1155Transfer{
				Erc1155Transfer: &txeth.Transaction_ERC1155Transfer{
					From:    "0x718046867b5b1782379a14eA4fc0c9b724DA94Fc",
					To:      "0x5322b34c88ed0691971bf52a7047448f0f4efc84",
					TokenId: mustHexTx(t, "23c47ee5"),
					Value:   mustHexTx(t, "1bc16d674ec80000"),
					Data:    mustHexTx(t, "01020304"),
				},
			},
		},
	}
	const want = "02f901500180847735940084b2d05e00830130b9944e45e92ed38f885d39a733c14f1817217a89d42580b8e4f242432a000000000000000000000000718046867b5b1782379a14ea4fc0c9b724da94fc0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000000000000023c47ee50000000000000000000000000000000000000000000000001bc16d674ec8000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000040102030400000000000000000000000000000000000000000000000000000000c080a0533df41dda5540c57257b7fe89c29cefff0155c333e063220df2bf9680fcc15aa036a844fd20de5a51de96ceaaf078558e87d86426a4a5d4b215ee1fd0fa397f8a"
	assertEthSigned(t, w, in, want)
}
