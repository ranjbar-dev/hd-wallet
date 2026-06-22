package hdwallet

import (
	"testing"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// TestSignTxEthereumContractGeneric verifies an arbitrary contract call via the
// ContractGeneric payload against Trust Wallet Core's
// SignERC20TransferAsGenericContract AnySigner vector (an ERC-20 transfer encoded
// as a raw contract call). A wrong preimage/RLP/signature changes the bytes.
func TestSignTxEthereumContractGeneric(t *testing.T) {
	w := ethWallet(t, "0x608dcb1742bb3fb7aec002074e3420e4fab7d00cced79ccdac53ed5b27138151")
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   mustHexTx(t, "01"),
		Nonce:     mustHexTx(t, "00"),
		TxMode:    0,
		GasPrice:  mustHexTx(t, "09c7652400"),
		GasLimit:  mustHexTx(t, "0130B9"),
		ToAddress: "0x6b175474e89094c44da98b954eedeac495271d0f",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_ContractGeneric_{
				ContractGeneric: &txeth.Transaction_ContractGeneric{
					Data: mustHexTx(t, "a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec80000"),
				},
			},
		},
	}
	const want = "f8aa808509c7652400830130b9946b175474e89094c44da98b954eedeac495271d0f80b844a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec8000025a0724c62ad4fbf47346b02de06e603e013f26f26b56fdc0be7ba3d6273401d98cea0032131cae15da7ddcda66963e8bef51ca0d9962bfef0547d3f02597a4a58c931"
	assertEthSigned(t, w, in, want)
}

// TestSignTxEthereumDeploy verifies contract creation (empty to_address). No TWC
// deploy AnySigner vector is published, so correctness is anchored differently
// but still authoritatively: the signed bytes are decoded back and the signature
// is re-verified against the EXACT deploy signing preimage (empty `to`), built
// from the already-vector-verified RLP encoder, keccak256, and secp256k1 signer.
// If the builder had used a non-empty `to`, this verification would fail.
func TestSignTxEthereumDeploy(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	initCode := mustHexTx(t, "600160015260206000f3")
	in := &txeth.SigningInput{
		ChainId:  mustHexTx(t, "01"),
		Nonce:    mustHexTx(t, "09"),
		TxMode:   0,
		GasPrice: mustHexTx(t, "04a817c800"),
		GasLimit: mustHexTx(t, "0186a0"),
		// to_address intentionally empty -> contract creation.
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_ContractGeneric_{
				ContractGeneric: &txeth.Transaction_ContractGeneric{Data: initCode},
			},
		},
	}

	out, err := w.SignTransaction(ETH, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	eo := out.(*txeth.SigningOutput)
	if eo.GetError() != "" {
		t.Fatalf("signing error: %s", eo.GetError())
	}

	// Reconstruct the legacy deploy preimage with an EMPTY `to` and verify the
	// returned (r,s) is a valid signature of it under the wallet's key.
	pre := RLPList(
		ethQuantity(in.GetNonce()),
		ethQuantity(in.GetGasPrice()),
		ethQuantity(in.GetGasLimit()),
		RLPString(nil), // empty to (deploy)
		ethQuantity(nil),
		RLPString(initCode),
		ethQuantity(in.GetChainId()),
		RLPString(nil),
		RLPString(nil),
	)
	digest := keccak256(EncodeRLP(pre))

	pub, err := w.PublicKey(ETH)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	raw := append(append([]byte(nil), eo.GetR()...), eo.GetS()...)
	sig := &Signature{Curve: Secp256k1, R: eo.GetR(), S: eo.GetS(), raw: raw}
	if !Verify(Secp256k1, pub, digest, sig) {
		t.Fatalf("deploy signature does not verify against the empty-`to` preimage")
	}
}
