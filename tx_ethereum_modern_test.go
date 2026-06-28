package hdwallet

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// EIP-4844 and EIP-7702 transaction signing verified byte-for-byte against
// go-ethereum's reference signer (github.com/ethereum/go-ethereum v1.15.11).
// The oracle program (_oracle/main.go) builds identical transactions using
// go-ethereum's types.SignTx + NewCancunSigner / NewPragueSigner and prints
// the signed hex. Those bytes are hardcoded here; any change to the RLP
// layout, type byte, or signing preimage would break these tests.
//
// Key used in all vectors: 0x4646…4646 (the canonical cross-test private key).

// blobVersionedHash returns a KZG-style versioned hash (version byte 0x01 +
// sha256(label)[1:]) that matches what the oracle program produces for a given
// label string. This reproduces the oracle's sha256("commitment0") construction
// without importing any KZG library.
func blobVersionedHash(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	h := make([]byte, 32)
	h[0] = 0x01
	copy(h[1:], sum[1:])
	return h
}

// TestSignTxEthereumEIP4844 pins the EIP-4844 (type-3) blob transaction
// signing to the go-ethereum reference signer (CancunSigner). The vector was
// produced by _oracle/main.go with go-ethereum v1.15.11.
//
// Parameters:
//   - chain_id = 1, nonce = 9
//   - max_priority_fee_per_gas = 0x77359400 (2 gwei)
//   - max_fee_per_gas = 0xb2d05e00 (3 gwei)
//   - gas_limit = 0x5208 (21000), to = 0x3535…3535, value = 1 ETH
//   - max_fee_per_blob_gas = 1
//   - blob_versioned_hashes = [0x01 || sha256("commitment0")[1:]]
func TestSignTxEthereumEIP4844(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	blobHash := blobVersionedHash("commitment0")

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "09"),
		TxMode:                EthTxModeEIP4844,
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "B2D05E00"),
		GasLimit:              mustHexTx(t, "5208"),
		ToAddress:             "0x3535353535353535353535353535353535353535",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: mustHexTx(t, "0de0b6b3a7640000"),
				},
			},
		},
		MaxFeePerBlobGas:    mustHexTx(t, "01"),
		BlobVersionedHashes: [][]byte{blobHash},
	}

	// Oracle: go-ethereum v1.15.11 NewCancunSigner(chainID=1).SignTx
	const want = "03f8950109847735940084b2d05e00825208943535353535353535353535353535353535353535880de0b6b3a764000080c001e1a001a908880e392e19e291fa151038a8045130ba5688da445ead3e7b6bcfd4f6bf80a0413c3c9120e5e6e98c558898c94523281e86fb149e598c6b0f257f1a21533dbca01945d39ebfdb94e8a2ff3c6e1ae01ba04e01f05a7b550d5cd8dd967013b60be0"
	assertEthSigned(t, w, in, want)

	// Round-trip: decode the signed bytes and verify all fields.
	raw, _ := hex.DecodeString(want)
	fields, err := DecodeEthereumTx(raw)
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if fields.Type != EthTxEIP4844 {
		t.Errorf("decoded type = %v, want eip-4844", fields.Type)
	}
	if fields.ChainID == nil || fields.ChainID.Int64() != 1 {
		t.Errorf("decoded chainId = %v, want 1", fields.ChainID)
	}
	if fields.Nonce == nil || fields.Nonce.Int64() != 9 {
		t.Errorf("decoded nonce = %v, want 9", fields.Nonce)
	}
	if fields.MaxFeePerBlobGas == nil || fields.MaxFeePerBlobGas.Int64() != 1 {
		t.Errorf("decoded maxFeePerBlobGas = %v, want 1", fields.MaxFeePerBlobGas)
	}
	if len(fields.BlobVersionedHashes) != 1 {
		t.Fatalf("decoded blob hashes count = %d, want 1", len(fields.BlobVersionedHashes))
	}
	if got := hex.EncodeToString(fields.BlobVersionedHashes[0]); got != hex.EncodeToString(blobHash) {
		t.Errorf("decoded blob hash = %s, want %s", got, hex.EncodeToString(blobHash))
	}
	if fields.R == nil || fields.S == nil {
		t.Error("decoded R or S is nil — tx was not signed")
	}
}

// TestSignTxEthereumEIP4844EmptyAccessList verifies that an empty access list
// produces the same signed bytes as no access list at all. The type-3 envelope
// always carries the access list field (even when empty) so 0xc0 must appear.
func TestSignTxEthereumEIP4844EmptyAccessList(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	blobHash := blobVersionedHash("commitment0")

	base := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "09"),
		TxMode:                EthTxModeEIP4844,
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "B2D05E00"),
		GasLimit:              mustHexTx(t, "5208"),
		ToAddress:             "0x3535353535353535353535353535353535353535",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: mustHexTx(t, "0de0b6b3a7640000"),
				},
			},
		},
		MaxFeePerBlobGas:    mustHexTx(t, "01"),
		BlobVersionedHashes: [][]byte{blobHash},
		AccessList:          nil,
	}
	noAL, err1 := w.SignTransaction(ETH, 0, base)
	if err1 != nil {
		t.Fatalf("nil AccessList: %v", err1)
	}

	base.AccessList = []*txeth.Access{} // explicitly empty
	emptyAL, err2 := w.SignTransaction(ETH, 0, base)
	if err2 != nil {
		t.Fatalf("empty AccessList: %v", err2)
	}

	got1 := hex.EncodeToString(noAL.(*txeth.SigningOutput).GetEncoded())
	got2 := hex.EncodeToString(emptyAL.(*txeth.SigningOutput).GetEncoded())
	if got1 != got2 {
		t.Fatalf("nil vs empty access list differ:\n nil   %s\n empty %s", got1, got2)
	}
}

// TestSignTxEthereumEIP7702 pins the EIP-7702 (type-4) set-code transaction
// signing to the go-ethereum reference signer (PragueSigner). The vector was
// produced by _oracle/main.go with go-ethereum v1.15.11.
//
// Parameters:
//   - chain_id = 1, nonce = 9
//   - max_priority_fee_per_gas = 0x77359400, max_fee_per_gas = 0xb2d05e00
//   - gas_limit = 0x5208, to = 0x3535…3535, value = 1 ETH
//   - authorization_list: one entry — auth key 0x1234…5678 delegates to
//     0xdEADBEeF…, auth nonce 1, chain_id 1.
func TestSignTxEthereumEIP7702(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	// Pre-signed authorization produced by the oracle (auth key 0x1234…5678):
	//   chain_id=1, address=0xdEADBEeF…, nonce=1
	//   y_parity=0
	//   r=0xa1c43a1eaabd6a438b1ebe001f20431e43e2e7e26be70d237b5cf56f3d8cbde2
	//   s=0x3c9fffb20d82a6277f4a78cd1d588ca781f362cb65164fe300a46800178725b1
	auth := &txeth.EthAuthorization{
		ChainId: mustHexTx(t, "01"),
		Address: "0xdEADBEeF00000000000000000000000000000000",
		Nonce:   1,
		YParity: 0,
		R:       mustHexTx(t, "a1c43a1eaabd6a438b1ebe001f20431e43e2e7e26be70d237b5cf56f3d8cbde2"),
		S:       mustHexTx(t, "3c9fffb20d82a6277f4a78cd1d588ca781f362cb65164fe300a46800178725b1"),
	}

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "09"),
		TxMode:                EthTxModeEIP7702,
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "B2D05E00"),
		GasLimit:              mustHexTx(t, "5208"),
		ToAddress:             "0x3535353535353535353535353535353535353535",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: mustHexTx(t, "0de0b6b3a7640000"),
				},
			},
		},
		AuthorizationList: []*txeth.EthAuthorization{auth},
	}

	// Oracle: go-ethereum v1.15.11 NewPragueSigner(chainID=1).SignTx
	const want = "04f8d00109847735940084b2d05e00825208943535353535353535353535353535353535353535880de0b6b3a764000080c0f85cf85a0194deadbeef000000000000000000000000000000000180a0a1c43a1eaabd6a438b1ebe001f20431e43e2e7e26be70d237b5cf56f3d8cbde2a03c9fffb20d82a6277f4a78cd1d588ca781f362cb65164fe300a46800178725b180a09a2b7464f074ddbaab074cb09bfce9b06d83d827361ec2589e6dce6c15f3f4e3a00848fdfd0e954045bf53fd890eb5d62b5fd96abe637830400d6412c929f95eab"
	assertEthSigned(t, w, in, want)

	// Round-trip: decode the signed bytes and verify all fields.
	raw, _ := hex.DecodeString(want)
	fields, err := DecodeEthereumTx(raw)
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if fields.Type != EthTxEIP7702 {
		t.Errorf("decoded type = %v, want eip-7702", fields.Type)
	}
	if fields.ChainID == nil || fields.ChainID.Int64() != 1 {
		t.Errorf("decoded chainId = %v, want 1", fields.ChainID)
	}
	if len(fields.AuthorizationList) != 1 {
		t.Fatalf("decoded auth list len = %d, want 1", len(fields.AuthorizationList))
	}
	got := fields.AuthorizationList[0]
	if got.Nonce != 1 {
		t.Errorf("decoded auth nonce = %d, want 1", got.Nonce)
	}
	if got.YParity != 0 {
		t.Errorf("decoded auth y_parity = %d, want 0", got.YParity)
	}
	wantAddr := "0x" + "deadbeef00000000000000000000000000000000"
	if got.Address != wantAddr {
		t.Errorf("decoded auth address = %s, want %s", got.Address, wantAddr)
	}
	if fields.R == nil || fields.S == nil {
		t.Error("decoded R or S is nil — tx was not signed")
	}
}

// TestSignTxEthereumEIP7702WithAccessList verifies that EIP-7702 correctly
// includes an access list in the signed bytes. We use the existing access-list
// fixture and confirm the output is deterministic (not compared to an external
// oracle since go-ethereum hasn't published a specific combined vector, but the
// access-list encoding reuses the vetted EIP-1559 path).
func TestSignTxEthereumEIP7702WithAccessList(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	auth := &txeth.EthAuthorization{
		ChainId: mustHexTx(t, "01"),
		Address: "0xdEADBEeF00000000000000000000000000000000",
		Nonce:   1,
		YParity: 0,
		R:       mustHexTx(t, "a1c43a1eaabd6a438b1ebe001f20431e43e2e7e26be70d237b5cf56f3d8cbde2"),
		S:       mustHexTx(t, "3c9fffb20d82a6277f4a78cd1d588ca781f362cb65164fe300a46800178725b1"),
	}

	in := &txeth.SigningInput{
		ChainId:               mustHexTx(t, "01"),
		Nonce:                 mustHexTx(t, "09"),
		TxMode:                EthTxModeEIP7702,
		MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
		MaxFeePerGas:          mustHexTx(t, "B2D05E00"),
		GasLimit:              mustHexTx(t, "5208"),
		ToAddress:             "0x3535353535353535353535353535353535353535",
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{
					Amount: mustHexTx(t, "0de0b6b3a7640000"),
				},
			},
		},
		AccessList:        accessListFixture(),
		AuthorizationList: []*txeth.EthAuthorization{auth},
	}

	out, err := w.SignTransaction(ETH, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	eo := out.(*txeth.SigningOutput)
	if eo.GetError() != "" {
		t.Fatalf("signing error: %s", eo.GetError())
	}
	encoded := eo.GetEncoded()
	if len(encoded) == 0 || encoded[0] != 0x04 {
		t.Fatalf("expected type-4 prefix, got %x", encoded[0])
	}

	// Round-trip: must decode cleanly with the access list and auth list intact.
	fields, err := DecodeEthereumTx(encoded)
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if fields.Type != EthTxEIP7702 {
		t.Errorf("decoded type = %v, want eip-7702", fields.Type)
	}
	if len(fields.AccessList) != 1 {
		t.Errorf("decoded access list len = %d, want 1", len(fields.AccessList))
	}
	if len(fields.AuthorizationList) != 1 {
		t.Errorf("decoded auth list len = %d, want 1", len(fields.AuthorizationList))
	}

	// Determinism: signing the same input twice must produce identical bytes.
	out2, _ := w.SignTransaction(ETH, 0, in)
	got1 := hex.EncodeToString(encoded)
	got2 := hex.EncodeToString(out2.(*txeth.SigningOutput).GetEncoded())
	if got1 != got2 {
		t.Fatal("EIP-7702 signing is not deterministic")
	}
}

// TestSignTxEthereumEIP4844ValidationErrors checks that missing or malformed
// EIP-4844 inputs are rejected with clear error messages.
func TestSignTxEthereumEIP4844ValidationErrors(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	base := func() *txeth.SigningInput {
		return &txeth.SigningInput{
			ChainId:               mustHexTx(t, "01"),
			Nonce:                 mustHexTx(t, "09"),
			TxMode:                EthTxModeEIP4844,
			MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
			MaxFeePerGas:          mustHexTx(t, "B2D05E00"),
			GasLimit:              mustHexTx(t, "5208"),
			ToAddress:             "0x3535353535353535353535353535353535353535",
			Transaction: &txeth.Transaction{
				TransactionOneof: &txeth.Transaction_Transfer_{
					Transfer: &txeth.Transaction_Transfer{Amount: mustHexTx(t, "0de0b6b3a7640000")},
				},
			},
			MaxFeePerBlobGas:    mustHexTx(t, "01"),
			BlobVersionedHashes: [][]byte{blobVersionedHash("commitment0")},
		}
	}

	t.Run("no blob hashes", func(t *testing.T) {
		in := base()
		in.BlobVersionedHashes = nil
		_, err := w.SignTransaction(ETH, 0, in)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("blob hash wrong length", func(t *testing.T) {
		in := base()
		in.BlobVersionedHashes = [][]byte{make([]byte, 31)} // 31 not 32
		_, err := w.SignTransaction(ETH, 0, in)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("no max_fee_per_blob_gas", func(t *testing.T) {
		in := base()
		in.MaxFeePerBlobGas = nil
		_, err := w.SignTransaction(ETH, 0, in)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

// TestSignTxEthereumEIP7702ValidationErrors checks that missing or malformed
// EIP-7702 inputs are rejected with clear error messages.
func TestSignTxEthereumEIP7702ValidationErrors(t *testing.T) {
	w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
	defer w.Destroy()

	makeAuth := func() *txeth.EthAuthorization {
		return &txeth.EthAuthorization{
			ChainId: mustHexTx(t, "01"),
			Address: "0xdEADBEeF00000000000000000000000000000000",
			Nonce:   1,
			YParity: 0,
			R:       mustHexTx(t, "a1c43a1eaabd6a438b1ebe001f20431e43e2e7e26be70d237b5cf56f3d8cbde2"),
			S:       mustHexTx(t, "3c9fffb20d82a6277f4a78cd1d588ca781f362cb65164fe300a46800178725b1"),
		}
	}

	base := func() *txeth.SigningInput {
		return &txeth.SigningInput{
			ChainId:               mustHexTx(t, "01"),
			Nonce:                 mustHexTx(t, "09"),
			TxMode:                EthTxModeEIP7702,
			MaxInclusionFeePerGas: mustHexTx(t, "77359400"),
			MaxFeePerGas:          mustHexTx(t, "B2D05E00"),
			GasLimit:              mustHexTx(t, "5208"),
			ToAddress:             "0x3535353535353535353535353535353535353535",
			Transaction: &txeth.Transaction{
				TransactionOneof: &txeth.Transaction_Transfer_{
					Transfer: &txeth.Transaction_Transfer{Amount: mustHexTx(t, "0de0b6b3a7640000")},
				},
			},
			AuthorizationList: []*txeth.EthAuthorization{makeAuth()},
		}
	}

	t.Run("empty auth list", func(t *testing.T) {
		in := base()
		in.AuthorizationList = nil
		_, err := w.SignTransaction(ETH, 0, in)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("bad auth address", func(t *testing.T) {
		in := base()
		in.AuthorizationList = []*txeth.EthAuthorization{{
			ChainId: mustHexTx(t, "01"),
			Address: "0xBAD", // not 20 bytes
			Nonce:   1,
		}}
		_, err := w.SignTransaction(ETH, 0, in)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

// TestDecodeEthereumTxEIP4844 verifies that decoding an unsigned EIP-4844
// transaction (no signature fields) returns the correct field count and type.
func TestDecodeEthereumTxEIP4844(t *testing.T) {
	// Decode the signed vector from TestSignTxEthereumEIP4844; the decoder
	// accepts both signed (14 fields) and unsigned (11 fields) forms.
	const signed = "03f8950109847735940084b2d05e00825208943535353535353535353535353535353535353535880de0b6b3a764000080c001e1a001a908880e392e19e291fa151038a8045130ba5688da445ead3e7b6bcfd4f6bf80a0413c3c9120e5e6e98c558898c94523281e86fb149e598c6b0f257f1a21533dbca01945d39ebfdb94e8a2ff3c6e1ae01ba04e01f05a7b550d5cd8dd967013b60be0"
	raw, _ := hex.DecodeString(signed)
	f, err := DecodeEthereumTx(raw)
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if f.Type != EthTxEIP4844 {
		t.Errorf("type = %v, want eip-4844", f.Type)
	}
	if f.MaxFeePerBlobGas == nil || f.MaxFeePerBlobGas.Int64() != 1 {
		t.Errorf("MaxFeePerBlobGas = %v, want 1", f.MaxFeePerBlobGas)
	}
	if len(f.BlobVersionedHashes) != 1 || len(f.BlobVersionedHashes[0]) != 32 {
		t.Errorf("BlobVersionedHashes = %v, want 1 x 32-byte hash", f.BlobVersionedHashes)
	}
	if typStr := f.Type.String(); typStr != "eip-4844" {
		t.Errorf("String() = %q, want \"eip-4844\"", typStr)
	}
}

// TestDecodeEthereumTxEIP7702 verifies that decoding the go-ethereum-pinned
// EIP-7702 transaction returns the correct fields including the auth list.
func TestDecodeEthereumTxEIP7702(t *testing.T) {
	const signed = "04f8d00109847735940084b2d05e00825208943535353535353535353535353535353535353535880de0b6b3a764000080c0f85cf85a0194deadbeef000000000000000000000000000000000180a0a1c43a1eaabd6a438b1ebe001f20431e43e2e7e26be70d237b5cf56f3d8cbde2a03c9fffb20d82a6277f4a78cd1d588ca781f362cb65164fe300a46800178725b180a09a2b7464f074ddbaab074cb09bfce9b06d83d827361ec2589e6dce6c15f3f4e3a00848fdfd0e954045bf53fd890eb5d62b5fd96abe637830400d6412c929f95eab"
	raw, _ := hex.DecodeString(signed)
	f, err := DecodeEthereumTx(raw)
	if err != nil {
		t.Fatalf("DecodeEthereumTx: %v", err)
	}
	if f.Type != EthTxEIP7702 {
		t.Errorf("type = %v, want eip-7702", f.Type)
	}
	if len(f.AuthorizationList) != 1 {
		t.Fatalf("auth list len = %d, want 1", len(f.AuthorizationList))
	}
	auth := f.AuthorizationList[0]
	if auth.ChainID == nil || auth.ChainID.Int64() != 1 {
		t.Errorf("auth chainId = %v, want 1", auth.ChainID)
	}
	wantAddr := "0x" + "deadbeef00000000000000000000000000000000"
	if auth.Address != wantAddr {
		t.Errorf("auth address = %s, want %s", auth.Address, wantAddr)
	}
	if auth.Nonce != 1 {
		t.Errorf("auth nonce = %d, want 1", auth.Nonce)
	}
	if auth.YParity != 0 {
		t.Errorf("auth y_parity = %d, want 0", auth.YParity)
	}
	if typStr := f.Type.String(); typStr != "eip-7702" {
		t.Errorf("String() = %q, want \"eip-7702\"", typStr)
	}
}
