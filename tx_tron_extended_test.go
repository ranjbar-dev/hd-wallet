package hdwallet

import (
	"bytes"
	"encoding/hex"
	"errors"
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

// TestSignTxTronTriggerSmartContract tests generic TriggerSmartContract (type 31)
// with non-empty calldata and a non-zero call_value (TRX sent with the call).
// The self-consistency check (txID == sha256(raw_data)) and the round-trip decoder
// are the correctness anchors; no external TWC vector exists for the generic path.
func TestSignTxTronTriggerSmartContract(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	// Arbitrary calldata: a simple function call with one uint256 argument.
	calldata := mustHexTx(t, "a9059cbb"+ // transfer(address,uint256) selector
		"000000000000000000000000521ea197907927725ef36d70f25f850d1659c7c7"+ // padded recipient (20-byte form)
		"00000000000000000000000000000000000000000000000000000000000003e8") // 1000

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			FeeLimit:    1_000_000,
			ContractOneof: &txtron.Transaction_TriggerSmartContract{
				TriggerSmartContract: &txtron.TriggerSmartContract{
					OwnerAddress:    "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					ContractAddress: "41521ea197907927725ef36d70f25f850d1659c7c7",
					CallValue:       100_000, // 0.1 TRX in SUN
					Data:            calldata,
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronTriggerSmartContractType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")

	// Verify decoded calldata round-trips correctly.
	if !bytes.Equal(c.Data, calldata) {
		t.Fatalf("data round-trip mismatch:\n got  %x\n want %x", c.Data, calldata)
	}
	// Verify decoded call_value round-trips correctly.
	if c.CallValue != 100_000 {
		t.Fatalf("call_value = %d, want 100000", c.CallValue)
	}
	// Verify zero-valued fields are absent (proto3 default omission).
	if c.CallTokenValue != 0 {
		t.Fatalf("call_token_value = %d, want 0", c.CallTokenValue)
	}
	if c.TokenId != 0 {
		t.Fatalf("token_id = %d, want 0", c.TokenId)
	}
}

// TestSignTxTronFreezeBalance tests legacy Stake 1.0 FreezeBalanceContract (type 11).
// Two sub-tests: self-freeze (BANDWIDTH, no receiver) and delegated freeze (ENERGY,
// with receiver). No external TWC vector — correctness is anchored by
// self-consistency (txID == sha256(raw_data)) and the decode round-trip.
func TestSignTxTronFreezeBalance(t *testing.T) {
	t.Run("self-freeze", func(t *testing.T) {
		w := tronTestWallet(t)
		defer w.Destroy()

		in := &txtron.SigningInput{
			Transaction: &txtron.Transaction{
				Timestamp:   1539295479000,
				Expiration:  1539331479000,
				BlockHeader: tronTestBlockHeader(t),
				ContractOneof: &txtron.Transaction_FreezeBalance{
					FreezeBalance: &txtron.FreezeBalanceContract{
						OwnerAddress:   "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
						FrozenBalance:  1_000_000,
						FrozenDuration: 3,
						Resource:       txtron.ResourceCode_BANDWIDTH,
						// receiver_address intentionally empty (self-freeze)
					},
				},
			},
		}

		out := assertTronOutput(t, w, in)
		c := assertTronRoundTrip(t, out, tronFreezeBalanceType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
		if c.FrozenBalance != 1_000_000 {
			t.Fatalf("frozen_balance = %d, want 1000000", c.FrozenBalance)
		}
		if c.FrozenDuration != 3 {
			t.Fatalf("frozen_duration = %d, want 3", c.FrozenDuration)
		}
		if c.Resource != 0 {
			t.Fatalf("resource = %d, want 0 (BANDWIDTH)", c.Resource)
		}
		if c.ReceiverAddress != "" {
			t.Fatalf("receiver_address = %q, want empty (self-freeze)", c.ReceiverAddress)
		}
	})

	t.Run("delegated-freeze", func(t *testing.T) {
		w := tronTestWallet(t)
		defer w.Destroy()

		in := &txtron.SigningInput{
			Transaction: &txtron.Transaction{
				Timestamp:   1539295479000,
				Expiration:  1539331479000,
				BlockHeader: tronTestBlockHeader(t),
				ContractOneof: &txtron.Transaction_FreezeBalance{
					FreezeBalance: &txtron.FreezeBalanceContract{
						OwnerAddress:    "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
						FrozenBalance:   2_000_000,
						FrozenDuration:  0,
						Resource:        txtron.ResourceCode_ENERGY,
						ReceiverAddress: "41521ea197907927725ef36d70f25f850d1659c7c7",
					},
				},
			},
		}

		out := assertTronOutput(t, w, in)
		c := assertTronRoundTrip(t, out, tronFreezeBalanceType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
		if c.FrozenBalance != 2_000_000 {
			t.Fatalf("frozen_balance = %d, want 2000000", c.FrozenBalance)
		}
		if c.FrozenDuration != 0 {
			t.Fatalf("frozen_duration = %d, want 0", c.FrozenDuration)
		}
		if c.Resource != 1 {
			t.Fatalf("resource = %d, want 1 (ENERGY)", c.Resource)
		}
		if c.ReceiverAddress == "" {
			t.Fatal("receiver_address is empty, want a delegated address")
		}
	})
}

// TestSignTxTronUnfreezeBalance tests legacy Stake 1.0 UnfreezeBalanceContract
// (type 12). Two sub-tests: self-unfreeze (BANDWIDTH, no receiver) and
// delegated-unfreeze (ENERGY, with receiver). No external TWC vector —
// correctness is anchored by self-consistency (txID == sha256(raw_data)) and
// the decode round-trip.
func TestSignTxTronUnfreezeBalance(t *testing.T) {
	t.Run("self", func(t *testing.T) {
		w := tronTestWallet(t)
		defer w.Destroy()

		in := &txtron.SigningInput{
			Transaction: &txtron.Transaction{
				Timestamp:   1539295479000,
				Expiration:  1539331479000,
				BlockHeader: tronTestBlockHeader(t),
				ContractOneof: &txtron.Transaction_UnfreezeBalance{
					UnfreezeBalance: &txtron.UnfreezeBalanceContract{
						OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
						Resource:     txtron.ResourceCode_BANDWIDTH,
						// receiver_address intentionally empty (self-unfreeze)
					},
				},
			},
		}

		out := assertTronOutput(t, w, in)
		c := assertTronRoundTrip(t, out, tronUnfreezeBalanceType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
		if c.Resource != 0 {
			t.Fatalf("resource = %d, want 0 (BANDWIDTH)", c.Resource)
		}
		if c.ReceiverAddress != "" {
			t.Fatalf("receiver_address = %q, want empty (self-unfreeze)", c.ReceiverAddress)
		}
	})

	t.Run("delegated", func(t *testing.T) {
		w := tronTestWallet(t)
		defer w.Destroy()

		in := &txtron.SigningInput{
			Transaction: &txtron.Transaction{
				Timestamp:   1539295479000,
				Expiration:  1539331479000,
				BlockHeader: tronTestBlockHeader(t),
				ContractOneof: &txtron.Transaction_UnfreezeBalance{
					UnfreezeBalance: &txtron.UnfreezeBalanceContract{
						OwnerAddress:    "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
						Resource:        txtron.ResourceCode_ENERGY,
						ReceiverAddress: "41521ea197907927725ef36d70f25f850d1659c7c7",
					},
				},
			},
		}

		out := assertTronOutput(t, w, in)
		c := assertTronRoundTrip(t, out, tronUnfreezeBalanceType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
		if c.Resource != 1 {
			t.Fatalf("resource = %d, want 1 (ENERGY)", c.Resource)
		}
		if c.ReceiverAddress == "" {
			t.Fatal("receiver_address is empty, want a delegated address")
		}
	})
}

// TestSignTxTronUnfreezeAsset tests UnfreezeAssetContract (type 14).
// No external TWC vector — correctness is anchored by self-consistency
// (txID == sha256(raw_data)) and the decode round-trip.
func TestSignTxTronUnfreezeAsset(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_UnfreezeAsset{
				UnfreezeAsset: &txtron.UnfreezeAssetContract{
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	assertTronRoundTrip(t, out, tronUnfreezeAssetType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
}

// TestSignTxTronWithdrawBalance tests WithdrawBalanceContract (type 13),
// which claims SR / voting rewards. No external TWC vector — correctness is
// anchored by self-consistency (txID == sha256(raw_data)) and the decode
// round-trip confirming the owner address survives intact.
func TestSignTxTronWithdrawBalance(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_WithdrawBalance{
				WithdrawBalance: &txtron.WithdrawBalanceContract{
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	assertTronRoundTrip(t, out, tronWithdrawBalanceType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
}

// TestSignTxTronVoteAsset tests VoteAssetContract (TRC-10 asset voting, type 3)
// with two vote addresses, support=true, and count=5. No external TWC vector —
// correctness is anchored by self-consistency (txID == sha256(raw_data)) and the
// decode round-trip.
func TestSignTxTronVoteAsset(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_VoteAsset{
				VoteAsset: &txtron.VoteAssetContract{
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					VoteAddress: []string{
						"415cd0fb0ab3ce40f3051414c604b27756e69e43db",
						"41521ea197907927725ef36d70f25f850d1659c7c7",
					},
					Support: true,
					Count:   5,
				},
			},
		},
	}

	out := assertTronOutput(t, w, in)
	c := assertTronRoundTrip(t, out, tronVoteAssetType, "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC")
	if len(c.VoteAddresses) != 2 {
		t.Fatalf("vote_addresses = %d, want 2", len(c.VoteAddresses))
	}
	if !c.Support {
		t.Fatal("support = false, want true")
	}
	if c.Count != 5 {
		t.Fatalf("count = %d, want 5", c.Count)
	}
}

// TestSignTxTronTriggerSmartContractCrossCheck verifies that signing a
// TransferTRC20Contract and signing a generic TriggerSmartContract with
// identical owner, token contract, and manually-built ABI calldata produce
// the same txID — proving the two code paths produce byte-identical raw_data.
func TestSignTxTronTriggerSmartContractCrossCheck(t *testing.T) {
	// Use the TRC-20 TWC-pinned test's private key and addresses so the
	// cross-check is anchored to the known-good wantID from that test.
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "2d8f68944bdbfbc0769542fba8fc2d2a3de67393334471624364c7006da2aa54"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	bh := &txtron.BlockHeader{
		Timestamp:      1539295479000,
		TxTrieRoot:     mustHexTx(t, "64288c2db0641316762a99dbb02ef7c90f968b60f9f2e410835980614332f86d"),
		ParentHash:     mustHexTx(t, "00000000002f7b3af4f5f8b9e23a30c530f719f165b742e7358536b280eead2d"),
		Number:         3111739,
		WitnessAddress: mustHexTx(t, "415863f6091b8e71766da808b1dd3159790f61de7d"),
		Version:        3,
	}

	const (
		ownerAddr    = "TJRyWwFs9wTFGZg3JbrVriFbNfCug5tDeC"
		contractAddr = "THTR75o8xXAgCTQqpiot2AFRAjvW1tSbVV"
		toAddr       = "TW1dU4L3eNm7Lw8WvieLKEHpXWAussRG9Z"
	)
	amount := []byte{0x03, 0xe8} // 1000

	// Sign via TransferTRC20Contract (the known-good high-level path).
	inTRC20 := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			BlockHeader: bh,
			ContractOneof: &txtron.Transaction_TransferTrc20{
				TransferTrc20: &txtron.TransferTRC20Contract{
					OwnerAddress:    ownerAddr,
					ContractAddress: contractAddr,
					ToAddress:       toAddr,
					Amount:          amount,
				},
			},
		},
	}
	outTRC20 := assertTronOutput(t, w, inTRC20)
	idTRC20 := hex.EncodeToString(outTRC20.GetId())

	// Sanity-check against the pinned TWC vector.
	const wantID = "0d644290e3cf554f6219c7747f5287589b6e7e30e1b02793b48ba362da6a5058"
	if idTRC20 != wantID {
		t.Fatalf("TRC-20 txID mismatch:\n got  %s\n want %s", idTRC20, wantID)
	}

	// Build the identical calldata manually and sign via generic TriggerSmartContract.
	recipientBytes, err := tronAddressBytes(toAddr)
	if err != nil {
		t.Fatalf("tronAddressBytes: %v", err)
	}
	calldata, err := tronTRC20TransferData(recipientBytes, amount)
	if err != nil {
		t.Fatalf("tronTRC20TransferData: %v", err)
	}

	inGeneric := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			BlockHeader: bh,
			ContractOneof: &txtron.Transaction_TriggerSmartContract{
				TriggerSmartContract: &txtron.TriggerSmartContract{
					OwnerAddress:    ownerAddr,
					ContractAddress: contractAddr,
					Data:            calldata,
					// call_value=0, call_token_value=0, token_id=0 → all omitted
				},
			},
		},
	}
	outGeneric := assertTronOutput(t, w, inGeneric)
	idGeneric := hex.EncodeToString(outGeneric.GetId())

	// The two txIDs must be identical — same raw_data, same sha256.
	if idGeneric != idTRC20 {
		t.Fatalf("generic trigger txID != TRC-20 txID:\n generic %s\n trc-20  %s", idGeneric, idTRC20)
	}
}

// TestSignTxTronRawJSON verifies that signing a pre-built node JSON transaction
// (raw_json mode) produces exactly the same txID and signature as signing the
// same transaction via the normal typed path.
func TestSignTxTronRawJSON(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	// Build and sign the transaction the normal typed way first.
	in1 := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_Transfer{
				Transfer: &txtron.TransferContract{
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					ToAddress:    "41521ea197907927725ef36d70f25f850d1659c7c7",
					Amount:       1000,
				},
			},
		},
	}
	out1 := assertTronOutput(t, w, in1)

	// Encode the signed output's raw_data as hex and txID as hex.
	rawHex := hex.EncodeToString(out1.GetRawData())
	idHex := hex.EncodeToString(out1.GetId())

	// Build the raw_json signing input that a DApp / node would provide.
	jsonStr := `{"txID":"` + idHex + `","raw_data_hex":"` + rawHex + `"}`
	in2 := &txtron.SigningInput{RawJson: jsonStr}

	out2Msg, err := w.SignTransaction(TRX, 0, in2)
	if err != nil {
		t.Fatalf("SignTransaction (raw_json): %v", err)
	}
	out2, ok := out2Msg.(*txtron.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *tron.SigningOutput", out2Msg)
	}

	// txID must be byte-identical.
	if !bytes.Equal(out2.GetId(), out1.GetId()) {
		t.Fatalf("txID mismatch:\n raw_json  %x\n typed     %x", out2.GetId(), out1.GetId())
	}
	// Signature must be byte-identical (same key, same digest, RFC 6979 determinism).
	if !bytes.Equal(out2.GetSignature(), out1.GetSignature()) {
		t.Fatalf("signature mismatch:\n raw_json  %x\n typed     %x", out2.GetSignature(), out1.GetSignature())
	}
}

// TestSignTxTronRawJSONHashMismatch verifies that a deliberately wrong txID in
// the raw_json causes SignTransaction to return an error wrapping ErrTxInput.
func TestSignTxTronRawJSONHashMismatch(t *testing.T) {
	w := tronTestWallet(t)
	defer w.Destroy()

	// Build a valid signed tx to obtain a real raw_data_hex.
	in1 := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:   1539295479000,
			Expiration:  1539331479000,
			BlockHeader: tronTestBlockHeader(t),
			ContractOneof: &txtron.Transaction_Transfer{
				Transfer: &txtron.TransferContract{
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					ToAddress:    "41521ea197907927725ef36d70f25f850d1659c7c7",
					Amount:       1000,
				},
			},
		},
	}
	out1 := assertTronOutput(t, w, in1)
	rawHex := hex.EncodeToString(out1.GetRawData())

	// Use a deliberately wrong (all-zero) txID.
	wrongID := "0000000000000000000000000000000000000000000000000000000000000000"
	jsonStr := `{"txID":"` + wrongID + `","raw_data_hex":"` + rawHex + `"}`
	in2 := &txtron.SigningInput{RawJson: jsonStr}

	_, err := w.SignTransaction(TRX, 0, in2)
	if err == nil {
		t.Fatal("expected error for txID mismatch, got nil")
	}
	if !errors.Is(err, ErrTxInput) {
		t.Fatalf("expected ErrTxInput, got: %v", err)
	}
}
