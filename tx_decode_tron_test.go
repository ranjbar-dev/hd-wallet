package hdwallet

import (
	"testing"

	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// "What am I signing?" Tron decoder, proven by:
//   - round-trip: sign the TWC Tron TransferContract vector with the EXISTING
//     signer and assert DecodeTronTx recovers the owner/to/amount and the block
//     references / timestamps;
//   - a TRC-20 TriggerSmartContract round-trip to exercise the contract-call
//     decode branch;
//   - malformed: truncated/garbage bytes return ErrTxDecode, never a panic.

// tronExpectedAddr renders the base58check "T..." form the decoder produces for a
// hex (0x41-prefixed) Tron address, so round-trip assertions compare like for
// like.
func tronExpectedAddr(t *testing.T, hexAddr string) string {
	t.Helper()
	raw := mustHexTx(t, hexAddr)
	if len(raw) != 21 {
		t.Fatalf("address %s is %d bytes, want 21", hexAddr, len(raw))
	}
	return base58CheckEncode(base58BTC, raw[:1], raw[1:])
}

func TestDecodeTronRoundTripTransfer(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "ba005cd605d8a02e3d5dfd04234cef3a3ee4f76bfbad2722d1fb5af8e12e6764"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	const (
		owner = "415cd0fb0ab3ce40f3051414c604b27756e69e43db"
		to    = "41521ea197907927725ef36d70f25f850d1659c7c7"
	)
	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:  1539295479000,
			Expiration: 1539331479000,
			FeeLimit:   1000000,
			BlockHeader: &txtron.BlockHeader{
				Timestamp:      1539295479000,
				TxTrieRoot:     mustHexTx(t, "64288c2db0641316762a99dbb02ef7c90f968b60f9f2e410835980614332f86d"),
				ParentHash:     mustHexTx(t, "00000000002f7b3af4f5f8b9e23a30c530f719f165b742e7358536b280eead2d"),
				Number:         3111739,
				WitnessAddress: mustHexTx(t, "415863f6091b8e71766da808b1dd3159790f61de7d"),
				Version:        3,
			},
			ContractOneof: &txtron.Transaction_Transfer{
				Transfer: &txtron.TransferContract{
					OwnerAddress: owner,
					ToAddress:    to,
					Amount:       2000000,
				},
			},
		},
	}

	out, err := w.SignTransaction(TRX, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	rawData := out.(*txtron.SigningOutput).GetRawData()

	f, err := DecodeTronTx(rawData)
	if err != nil {
		t.Fatalf("DecodeTronTx: %v", err)
	}
	if f.Timestamp != 1539295479000 || f.Expiration != 1539331479000 || f.FeeLimit != 1000000 {
		t.Fatalf("ts/exp/fee = %d/%d/%d", f.Timestamp, f.Expiration, f.FeeLimit)
	}
	if len(f.RefBlockBytes) != 2 || len(f.RefBlockHash) != 8 {
		t.Fatalf("ref block bytes/hash len = %d/%d, want 2/8", len(f.RefBlockBytes), len(f.RefBlockHash))
	}
	if len(f.Contracts) != 1 {
		t.Fatalf("contracts len = %d, want 1", len(f.Contracts))
	}
	c := f.Contracts[0]
	if c.Type != tronTransferType || c.TypeName != "TransferContract" {
		t.Fatalf("type = %d/%s, want %d/TransferContract", c.Type, c.TypeName, tronTransferType)
	}
	if c.OwnerAddress != tronExpectedAddr(t, owner) {
		t.Fatalf("owner = %s, want %s", c.OwnerAddress, tronExpectedAddr(t, owner))
	}
	if c.ToAddress != tronExpectedAddr(t, to) {
		t.Fatalf("to = %s, want %s", c.ToAddress, tronExpectedAddr(t, to))
	}
	if c.Amount != 2000000 {
		t.Fatalf("amount = %d, want 2000000", c.Amount)
	}
}

func TestDecodeTronRoundTripTRC20(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "ba005cd605d8a02e3d5dfd04234cef3a3ee4f76bfbad2722d1fb5af8e12e6764"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	const (
		owner    = "415cd0fb0ab3ce40f3051414c604b27756e69e43db"
		contract = "4173ed3f64e3b9b1d5b9f00a685b8c7fb4f06b6d2a"
		to       = "41521ea197907927725ef36d70f25f850d1659c7c7"
	)
	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp: 1539295479000,
			BlockHeader: &txtron.BlockHeader{
				Timestamp:      1539295479000,
				TxTrieRoot:     mustHexTx(t, "64288c2db0641316762a99dbb02ef7c90f968b60f9f2e410835980614332f86d"),
				ParentHash:     mustHexTx(t, "00000000002f7b3af4f5f8b9e23a30c530f719f165b742e7358536b280eead2d"),
				Number:         3111739,
				WitnessAddress: mustHexTx(t, "415863f6091b8e71766da808b1dd3159790f61de7d"),
				Version:        3,
			},
			ContractOneof: &txtron.Transaction_TransferTrc20{
				TransferTrc20: &txtron.TransferTRC20Contract{
					OwnerAddress:    owner,
					ContractAddress: contract,
					ToAddress:       to,
					Amount:          mustHexTx(t, "0f4240"), // 1,000,000 big-endian
				},
			},
		},
	}

	out, err := w.SignTransaction(TRX, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	f, err := DecodeTronTx(out.(*txtron.SigningOutput).GetRawData())
	if err != nil {
		t.Fatalf("DecodeTronTx: %v", err)
	}
	if len(f.Contracts) != 1 {
		t.Fatalf("contracts len = %d, want 1", len(f.Contracts))
	}
	c := f.Contracts[0]
	if c.Type != tronTriggerSmartContractType || c.TypeName != "TriggerSmartContract" {
		t.Fatalf("type = %d/%s, want %d/TriggerSmartContract", c.Type, c.TypeName, tronTriggerSmartContractType)
	}
	if c.OwnerAddress != tronExpectedAddr(t, owner) {
		t.Fatalf("owner = %s, want %s", c.OwnerAddress, tronExpectedAddr(t, owner))
	}
	if c.ContractAddress != tronExpectedAddr(t, contract) {
		t.Fatalf("contract = %s, want %s", c.ContractAddress, tronExpectedAddr(t, contract))
	}
	// Data is the transfer(address,uint256) calldata: 4-byte selector + 2 words.
	if len(c.Data) != 4+32+32 {
		t.Fatalf("data len = %d, want 68", len(c.Data))
	}
}

func TestDecodeTronMalformed(t *testing.T) {
	w, _ := FromPrivateKeyBytes(
		mustHexTx(t, "ba005cd605d8a02e3d5dfd04234cef3a3ee4f76bfbad2722d1fb5af8e12e6764"),
		Secp256k1,
	)
	defer w.Destroy()
	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:  1539295479000,
			Expiration: 1539331479000,
			BlockHeader: &txtron.BlockHeader{
				Timestamp:      1539295479000,
				TxTrieRoot:     mustHexTx(t, "64288c2db0641316762a99dbb02ef7c90f968b60f9f2e410835980614332f86d"),
				ParentHash:     mustHexTx(t, "00000000002f7b3af4f5f8b9e23a30c530f719f165b742e7358536b280eead2d"),
				Number:         3111739,
				WitnessAddress: mustHexTx(t, "415863f6091b8e71766da808b1dd3159790f61de7d"),
				Version:        3,
			},
			ContractOneof: &txtron.Transaction_Transfer{
				Transfer: &txtron.TransferContract{
					OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
					ToAddress:    "41521ea197907927725ef36d70f25f850d1659c7c7",
					Amount:       2000000,
				},
			},
		},
	}
	out, _ := w.SignTransaction(TRX, 0, in)
	full := out.(*txtron.SigningOutput).GetRawData()

	cases := map[string][]byte{
		"empty":          {},
		"truncated":      full[:len(full)/2],
		"bad tag":        {0xff, 0xff},
		"length overrun": {0x0a, 0x7f}, // field 1 bytes claims 127, none follow
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTronTx(b); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}
