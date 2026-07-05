package hdwallet

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	txalgo "github.com/ranjbar-dev/hd-wallet/txproto/algorand"
)

// Algorand ASA (asset) transfer + opt-in — vector-pinned tests.
//
// Source: Trust Wallet Core SignerTests.cpp (Algorand):
//   TEST(AlgorandSigner, SignAsset)
//   TEST(AlgorandSigner, SignAssetOptIn)
//   TEST(AlgorandSigner, SignAssetNFTTransfer)
// https://github.com/trustwallet/wallet-core/blob/master/tests/chains/Algorand/SignerTests.cpp
//
// Wire summary (canonical msgpack, keys alphabetical, zero-values omitted):
//   axfer map keys: aamt (omit if 0), arcv, fee, fv, gen, gh, lv, note (omit
//   if empty), snd, type="axfer", xaid.
//   Opt-in: arcv = sender's own pubkey, no aamt key at all.

func mustParseALGOAddress(t *testing.T, addr string) []byte {
	t.Helper()
	pub, err := ParseAddress(ALGO, addr)
	if err != nil {
		t.Fatalf("ParseAddress(%s): %v", addr, err)
	}
	return pub
}

// TestSignTxALGOAsset pins the AssetTransfer (axfer) signer to the TWC
// SignAsset vector.
func TestSignTxALGOAsset(t *testing.T) {
	key, _ := hex.DecodeString("5a6a3cfe5ff4cc44c19381d15a0d16de2a76ee5c9b9d83b232e38cb5a2c84b04")
	genesisHash, _ := base64.StdEncoding.DecodeString("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")

	w, err := FromPrivateKeyBytes(key, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	to := mustParseALGOAddress(t, "GJIWJSX2EU5RC32LKTDDXWLA2YICBHKE35RV2ZPASXZYKWUWXFLKNFSS4U")

	input := &txalgo.SigningInput{
		GenesisHash: genesisHash,
		GenesisId:   "testnet-v1.0",
		FirstValid:  15775683,
		LastValid:   15776683,
		Fee:         2340,
		AssetTransfer: &txalgo.AssetTransfer{
			AssetId: 13379146,
			Amount:  1000000,
			To:      to,
		},
	}

	out, err := w.SignTransaction(ALGO, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	got, ok := out.(*txalgo.SigningOutput)
	if !ok {
		t.Fatalf("expected *algorand.SigningOutput, got %T", out)
	}
	if got.Error != "" {
		t.Fatalf("signing error: %s", got.Error)
	}

	const wantHex = "82a3736967c440412720eff99a17280a437bdb8eeba7404b855d6433fffd5dde7f7966c1f9ae531a1af39e18b8a58b4a6c6acb709cca92f8a18c36d8328be9520c915311027005a374786e8aa461616d74ce000f4240a461726376c420325164cafa253b116f4b54c63bd960d610209d44df635d65e095f3855a96b956a3666565cd0924a26676ce00f0b7c3a367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76ce00f0bbaba3736e64c42082872d60c338cb928006070e02ec0942addcb79e7fbd01c76458aea526899bd3a474797065a56178666572a478616964ce00cc264a"
	if got.EncodedHex != wantHex {
		t.Errorf("encoded_hex mismatch\n got: %s\nwant: %s", got.EncodedHex, wantHex)
	}
}

// TestSignTxALGOAssetOptIn pins the AssetOptIn (0-amount axfer to self)
// signer to the TWC SignAssetOptIn vector.
func TestSignTxALGOAssetOptIn(t *testing.T) {
	key, _ := hex.DecodeString("5a6a3cfe5ff4cc44c19381d15a0d16de2a76ee5c9b9d83b232e38cb5a2c84b04")
	genesisHash, _ := base64.StdEncoding.DecodeString("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")

	w, err := FromPrivateKeyBytes(key, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txalgo.SigningInput{
		GenesisHash: genesisHash,
		GenesisId:   "testnet-v1.0",
		FirstValid:  15775553,
		LastValid:   15776553,
		Fee:         2340,
		AssetOptIn: &txalgo.AssetOptIn{
			AssetId: 13379146,
		},
	}

	out, err := w.SignTransaction(ALGO, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	got, ok := out.(*txalgo.SigningOutput)
	if !ok {
		t.Fatalf("expected *algorand.SigningOutput, got %T", out)
	}
	if got.Error != "" {
		t.Fatalf("signing error: %s", got.Error)
	}

	const wantHex = "82a3736967c440f3a29d9a40271c00b542b38ab2ccb4967015ae6609368d4b8eb2f5e2b5348577cf9e0f62b0777ccb2d8d9b943b15c24c0cf1db312cb01a3c198d9d9c6c5bb00ba374786e89a461726376c42082872d60c338cb928006070e02ec0942addcb79e7fbd01c76458aea526899bd3a3666565cd0924a26676ce00f0b741a367656eac746573746e65742d76312e30a26768c4204863b518a4b3c84ec810f22d4f1081cb0f71f059a7ac20dec62f7f70e5093a22a26c76ce00f0bb29a3736e64c42082872d60c338cb928006070e02ec0942addcb79e7fbd01c76458aea526899bd3a474797065a56178666572a478616964ce00cc264a"
	if got.EncodedHex != wantHex {
		t.Errorf("encoded_hex mismatch\n got: %s\nwant: %s", got.EncodedHex, wantHex)
	}
}

// TestSignTxALGOAssetNFTTransfer pins an AssetTransfer of an NFT (amount=1,
// with a note) to the TWC SignAssetNFTTransfer vector.
func TestSignTxALGOAssetNFTTransfer(t *testing.T) {
	key, _ := hex.DecodeString("dc6051ffc7b3ec601bde432f6dea34d40fe3855e4181afa0f0524c42194a6da7")
	genesisHash, _ := base64.StdEncoding.DecodeString("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=")
	note, _ := base64.StdEncoding.DecodeString("VFdUIFRPIFRIRSBNT09O")

	w, err := FromPrivateKeyBytes(key, Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	to := mustParseALGOAddress(t, "362T7CSXNLIOBX6J3H2SCPS4LPYFNV6DDWE6G64ZEUJ6SY5OJIR6SB5CVE")

	input := &txalgo.SigningInput{
		GenesisHash: genesisHash,
		GenesisId:   "mainnet-v1.0",
		FirstValid:  27963950,
		LastValid:   27964950,
		Fee:         1000,
		Note:        note,
		AssetTransfer: &txalgo.AssetTransfer{
			AssetId: 989643841,
			Amount:  1,
			To:      to,
		},
	}

	out, err := w.SignTransaction(ALGO, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}

	got, ok := out.(*txalgo.SigningOutput)
	if !ok {
		t.Fatalf("expected *algorand.SigningOutput, got %T", out)
	}
	if got.Error != "" {
		t.Fatalf("signing error: %s", got.Error)
	}

	const wantHex = "82a3736967c4409d742c0c7d62946dc3228d95426e6d7582977bda39f7dca076a8a49913a966235702f41e2b76af26a823339a3e881c8276aeae3b195bbde0f25662fd9d9c7106a374786e8ba461616d7401a461726376c420dfb53f8a576ad0e0dfc9d9f5213e5c5bf056d7c31d89e37b992513e963ae4a23a3666565cd03e8a26676ce01aab22ea367656eac6d61696e6e65742d76312e30a26768c420c061c4d8fc1dbdded2d7604be4568e3f6d041987ac37bde4b620b5ab39248adfa26c76ce01aab616a46e6f7465c40f54575420544f20544845204d4f4f4ea3736e64c420ca40799dacdb564d1096611d9da6ca7a6a4916f6d681383860725aedafe91617a474797065a56178666572a478616964ce3afcc441"
	if got.EncodedHex != wantHex {
		t.Errorf("encoded_hex mismatch\n got: %s\nwant: %s", got.EncodedHex, wantHex)
	}
}
