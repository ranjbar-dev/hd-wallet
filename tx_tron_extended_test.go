package hdwallet

import (
	"encoding/hex"
	"testing"

	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// Shared block header fixture (same as the TRX transfer test, block 3111739).
func tronTestBlockHeader(t *testing.T) *txtron.BlockHeader {
	t.Helper()
	return &txtron.BlockHeader{
		Timestamp:      1539295479000,
		TxTrieRoot:     mustHexTx(t, "64288c2db0641316762a99dbb02ef7c90f968b60f9f2e410835980614332f86d"),
		ParentHash:     mustHexTx(t, "00000000002f7b3af4f5f8b9e23a30c530f719f165b742e7358536b280eead2d"),
		Number:         3111739,
		WitnessAddress: mustHexTx(t, "415863f6091b8e71766da808b1dd3159790f61de7d"),
		Version:        3,
	}
}

// tronTestWallet builds a wallet from the same private key used in TestSignTxTronTransfer.
func tronTestWallet(t *testing.T) *HDWallet {
	t.Helper()
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "ba005cd605d8a02e3d5dfd04234cef3a3ee4f76bfbad2722d1fb5af8e12e6764"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	return w
}

// assertTronOutput signs, checks no error, asserts txID == sha256(raw_data), and
// returns the signed output (for callers that want to pin exact bytes).
func assertTronOutput(t *testing.T, w *HDWallet, in *txtron.SigningInput) *txtron.SigningOutput {
	t.Helper()
	out, err := w.SignTransaction(TRX, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	to, ok := out.(*txtron.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *tron.SigningOutput", out)
	}
	if to.GetError() != "" {
		t.Fatalf("signing error: %s", to.GetError())
	}
	// txID must equal sha256(raw_data).
	want := sha256Sum(to.GetRawData())
	if got := to.GetId(); hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("txID != sha256(raw_data):\n got  %x\n want %x", got, want)
	}
	if len(to.GetSignature()) != 65 {
		t.Fatalf("signature length = %d, want 65", len(to.GetSignature()))
	}
	return to
}

// assertTronRoundTrip decodes the raw_data from the output and checks the
// contract type and owner address survive the round-trip.
func assertTronRoundTrip(t *testing.T, out *txtron.SigningOutput, wantType int32, wantOwner string) *TronContract {
	t.Helper()
	fields, err := DecodeTronTx(out.GetRawData())
	if err != nil {
		t.Fatalf("DecodeTronTx: %v", err)
	}
	if len(fields.Contracts) != 1 {
		t.Fatalf("contracts = %d, want 1", len(fields.Contracts))
	}
	c := &fields.Contracts[0]
	if c.Type != wantType {
		t.Fatalf("contract type = %d, want %d", c.Type, wantType)
	}
	if c.OwnerAddress != wantOwner {
		t.Fatalf("owner = %s, want %s", c.OwnerAddress, wantOwner)
	}
	return c
}

// TestSignTxTronTransferAsset tests TRC-10 token transfer (TransferAssetContract,
// contract type 2). Vectors are derived from the same private key / block header
// used by TestSignTxTronTransfer and anchored to sha256(raw_data) correctness.
func TestSignTxTronTransferAsset(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_TransferAsset{
				TransferAsset: &txtron.TransferAssetContract{
					AssetName:    "1000001",
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					ToAddress:    "41521ea197907927725ef36d70f25f850d1659c7c7",
					Amount:       100,
				},
			},
		},
	}

	// Vectors anchored to sha256(raw_data) correctness and RFC-6979 determinism.
	const (
		wantID  = "a02bb81911a41a5126cced164a7fe9f78d2ea580c31354dfd0d434134fe2bbfb"
		wantSig = "33e46be19108b489ebf8e4e9f9d8613a0bf33d338ee607ea4c8c4167e0f2299325424b395c8acd3cd15dc47c59eedcc02413f5bd68fb03bffb9b2f3a050461ed00"
	)

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronTransferAssetType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
	if c.AssetName != "1000001" {
		t.Fatalf("asset_name = %q, want %q", c.AssetName, "1000001")
	}
	if c.Amount != 100 {
		t.Fatalf("amount = %d, want 100", c.Amount)
	}

	if got := hex.EncodeToString(out.GetId()); got != wantID {
		t.Fatalf("txID mismatch:\n got  %s\n want %s", got, wantID)
	}
	if got := hex.EncodeToString(out.GetSignature()); got != wantSig {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", got, wantSig)
	}
}

// TestSignTxTronFreezeBalanceV2 tests Stake 2.0 freeze (FreezeBalanceV2Contract,
// contract type 54). Freezes 1 TRX (1,000,000 SUN) for BANDWIDTH.
func TestSignTxTronFreezeBalanceV2(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_FreezeBalanceV2{
				FreezeBalanceV2: &txtron.FreezeBalanceV2Contract{
					OwnerAddress:  "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					FrozenBalance: 1_000_000, // 1 TRX in SUN
					Resource:      txtron.ResourceCode_BANDWIDTH,
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronFreezeBalanceV2Type, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
	if c.FrozenBalance != 1_000_000 {
		t.Fatalf("frozen_balance = %d, want 1000000", c.FrozenBalance)
	}
	if c.Resource != 0 {
		t.Fatalf("resource = %d, want 0 (BANDWIDTH)", c.Resource)
	}
}

// TestSignTxTronFreezeBalanceV2Energy tests FreezeBalanceV2 for ENERGY resources.
func TestSignTxTronFreezeBalanceV2Energy(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_FreezeBalanceV2{
				FreezeBalanceV2: &txtron.FreezeBalanceV2Contract{
					OwnerAddress:  "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					FrozenBalance: 2_000_000,
					Resource:      txtron.ResourceCode_ENERGY,
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronFreezeBalanceV2Type, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
	if c.Resource != 1 {
		t.Fatalf("resource = %d, want 1 (ENERGY)", c.Resource)
	}
	if c.FrozenBalance != 2_000_000 {
		t.Fatalf("frozen_balance = %d, want 2000000", c.FrozenBalance)
	}
}

// TestSignTxTronUnfreezeBalanceV2 tests Stake 2.0 unfreeze (UnfreezeBalanceV2Contract,
// contract type 55).
func TestSignTxTronUnfreezeBalanceV2(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_UnfreezeBalanceV2{
				UnfreezeBalanceV2: &txtron.UnfreezeBalanceV2Contract{
					OwnerAddress:    "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					UnfreezeBalance: 1_000_000,
					Resource:        txtron.ResourceCode_BANDWIDTH,
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronUnfreezeBalanceV2Type, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
	if c.UnfreezeBalance != 1_000_000 {
		t.Fatalf("unfreeze_balance = %d, want 1000000", c.UnfreezeBalance)
	}
}

// TestSignTxTronDelegateResource tests DelegateResourceContract (type 57).
func TestSignTxTronDelegateResource(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_DelegateResource{
				DelegateResource: &txtron.DelegateResourceContract{
					OwnerAddress:    "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					Resource:        txtron.ResourceCode_ENERGY,
					Balance:         5_000_000,
					ReceiverAddress: "41521ea197907927725ef36d70f25f850d1659c7c7",
					Lock:            false,
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronDelegateResourceType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
	if c.Resource != 1 {
		t.Fatalf("resource = %d, want 1 (ENERGY)", c.Resource)
	}
	if c.Balance != 5_000_000 {
		t.Fatalf("balance = %d, want 5000000", c.Balance)
	}
	if c.ReceiverAddress == "" {
		t.Fatal("receiver_address is empty")
	}
	if c.Lock {
		t.Fatal("lock should be false")
	}
}

// TestSignTxTronDelegateResourceLocked tests DelegateResourceContract with lock=true.
func TestSignTxTronDelegateResourceLocked(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_DelegateResource{
				DelegateResource: &txtron.DelegateResourceContract{
					OwnerAddress:    "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					Resource:        txtron.ResourceCode_BANDWIDTH,
					Balance:         3_000_000,
					ReceiverAddress: "41521ea197907927725ef36d70f25f850d1659c7c7",
					Lock:            true,
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronDelegateResourceType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
	if !c.Lock {
		t.Fatal("lock should be true")
	}
}

// TestSignTxTronUndelegateResource tests UndelegateResourceContract (type 58).
func TestSignTxTronUndelegateResource(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_UndelegateResource{
				UndelegateResource: &txtron.UndelegateResourceContract{
					OwnerAddress:    "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					Resource:        txtron.ResourceCode_ENERGY,
					Balance:         5_000_000,
					ReceiverAddress: "41521ea197907927725ef36d70f25f850d1659c7c7",
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronUndelegateResourceType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
	if c.Balance != 5_000_000 {
		t.Fatalf("balance = %d, want 5000000", c.Balance)
	}
	if c.Resource != 1 {
		t.Fatalf("resource = %d, want 1 (ENERGY)", c.Resource)
	}
}

// TestSignTxTronVoteWitness tests VoteWitnessContract (type 4) with two votes.
func TestSignTxTronVoteWitness(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_VoteWitness{
				VoteWitness: &txtron.VoteWitnessContract{
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					Votes: []*txtron.Vote{
						{
							VoteAddress: "41521ea197907927725ef36d70f25f850d1659c7c7",
							VoteCount:   3,
						},
						{
							VoteAddress: "415863f6091b8e71766da808b1dd3159790f61de7d",
							VoteCount:   2,
						},
					},
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronVoteWitnessType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
	if len(c.Votes) != 2 {
		t.Fatalf("votes = %d, want 2", len(c.Votes))
	}
	if c.Votes[0].VoteCount != 3 {
		t.Fatalf("votes[0].count = %d, want 3", c.Votes[0].VoteCount)
	}
	if c.Votes[1].VoteCount != 2 {
		t.Fatalf("votes[1].count = %d, want 2", c.Votes[1].VoteCount)
	}
}

// TestSignTxTronWithdrawExpireUnfreeze tests WithdrawExpireUnfreezeContract (type 56).
func TestSignTxTronWithdrawExpireUnfreeze(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_WithdrawExpireUnfreeze{
				WithdrawExpireUnfreeze: &txtron.WithdrawExpireUnfreezeContract{
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	assertTronRoundTrip(t, out, tronWithdrawExpireUnfreezeType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
}
