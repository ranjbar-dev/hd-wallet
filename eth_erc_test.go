package hdwallet

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// addr20 builds a 20-byte address with every byte set to b.
func addr20(b byte) []byte {
	a := make([]byte, 20)
	for i := range a {
		a[i] = b
	}
	return a
}

// decodeHex decodes a hex string (no 0x prefix) or fatals.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decodeHex(%q): %v", s, err)
	}
	return b
}

// ---- ERC-721 ---------------------------------------------------------------

func TestERC721Selectors(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"transferFrom", erc721SelTransferFrom, "23b872dd"},
		{"safeTransferFrom(3)", erc721SelSafeTransferFrom, "42842e0e"},
		{"safeTransferFrom(4)", erc721SelSafeTransferFromData, "b88d4fde"},
		{"approve", erc721SelApprove, "095ea7b3"},
		{"setApprovalForAll", erc721SelSetApprovalForAll, "a22cb465"},
	}
	for _, tc := range cases {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("ERC-721 selector %s = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// Pins ERC721TransferCalldata against the ABI spec.
// from=0x11*20, to=0x22*20, tokenID=42
func TestERC721TransferCalldata(t *testing.T) {
	from := addr20(0x11)
	to := addr20(0x22)
	got := ERC721TransferCalldata(from, to, big.NewInt(42))
	want := "23b872dd" +
		"0000000000000000000000001111111111111111111111111111111111111111" +
		"0000000000000000000000002222222222222222222222222222222222222222" +
		"000000000000000000000000000000000000000000000000000000000000002a"
	if hex.EncodeToString(got) != want {
		t.Fatalf("ERC721TransferCalldata:\n got  %s\n want %s", hex.EncodeToString(got), want)
	}
}

// Pins ERC721SetApprovalForAllCalldata against the ABI spec.
func TestERC721SetApprovalForAllCalldata(t *testing.T) {
	op := addr20(0x33)
	got := ERC721SetApprovalForAllCalldata(op, true)
	want := "a22cb465" +
		"0000000000000000000000003333333333333333333333333333333333333333" +
		"0000000000000000000000000000000000000000000000000000000000000001"
	if hex.EncodeToString(got) != want {
		t.Fatalf("ERC721SetApprovalForAllCalldata:\n got  %s\n want %s", hex.EncodeToString(got), want)
	}
}

// Verifies that the 4-byte safeTransferFrom(from,to,tokenId,bytes) selector is
// distinct from the 3-arg variant and that data is appended correctly.
func TestERC721SafeTransferWithData(t *testing.T) {
	from := addr20(0x11)
	to := addr20(0x22)
	data := []byte{0xde, 0xad}
	got := ERC721SafeTransferWithDataCalldata(from, to, big.NewInt(1), data)
	if hex.EncodeToString(got[:4]) != "b88d4fde" {
		t.Fatalf("wrong selector: %x", got[:4])
	}
	// data appears somewhere in the tail
	if !bytes.Contains(got, []byte{0xde, 0xad}) {
		t.Fatal("calldata does not contain the data bytes")
	}
}

// ---- ERC-1155 --------------------------------------------------------------

func TestERC1155Selectors(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"safeTransferFrom", erc1155SelSafeTransferFrom, "f242432a"},
		{"safeBatchTransferFrom", erc1155SelSafeBatchTransferFrom, "2eb2c2d6"},
		{"setApprovalForAll", erc1155SelSetApprovalForAll, "a22cb465"},
	}
	for _, tc := range cases {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("ERC-1155 selector %s = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// Pins ERC1155SafeTransferCalldata with empty data.
// from=0x11*20, to=0x22*20, id=7, amount=100, data=[]
func TestERC1155SafeTransferCalldata(t *testing.T) {
	from := addr20(0x11)
	to := addr20(0x22)
	got := ERC1155SafeTransferCalldata(from, to, big.NewInt(7), big.NewInt(100), nil)
	want := "f242432a" +
		"0000000000000000000000001111111111111111111111111111111111111111" +
		"0000000000000000000000002222222222222222222222222222222222222222" +
		"0000000000000000000000000000000000000000000000000000000000000007" +
		"0000000000000000000000000000000000000000000000000000000000000064" +
		"00000000000000000000000000000000000000000000000000000000000000a0" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	if hex.EncodeToString(got) != want {
		t.Fatalf("ERC1155SafeTransferCalldata:\n got  %s\n want %s", hex.EncodeToString(got), want)
	}
}

// Verifies safeBatchTransferFrom selector and that both id arrays are present.
func TestERC1155SafeBatchTransferCalldata(t *testing.T) {
	from := addr20(0x11)
	to := addr20(0x22)
	ids := []*big.Int{big.NewInt(1), big.NewInt(2)}
	amounts := []*big.Int{big.NewInt(10), big.NewInt(20)}
	got := ERC1155SafeBatchTransferCalldata(from, to, ids, amounts, nil)
	if hex.EncodeToString(got[:4]) != "2eb2c2d6" {
		t.Fatalf("wrong selector: %x", got[:4])
	}
	// both id values must appear as padded 32-byte words
	id1 := decodeHex(t, "0000000000000000000000000000000000000000000000000000000000000001")
	id2 := decodeHex(t, "0000000000000000000000000000000000000000000000000000000000000002")
	if !bytes.Contains(got, id1) || !bytes.Contains(got, id2) {
		t.Fatal("calldata does not contain expected token ids")
	}
}

// ---- ERC-20 ----------------------------------------------------------------

func TestERC20Selectors(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"approve", erc20SelApprove, "095ea7b3"},
		{"permit", erc20SelPermit, "d505accf"},
	}
	for _, tc := range cases {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("ERC-20 selector %s = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// Pins ERC20ApproveCalldata against the ABI spec.
// spender=0x44*20, amount=1e18
func TestERC20ApproveCalldata(t *testing.T) {
	spender := addr20(0x44)
	amount, _ := new(big.Int).SetString("de0b6b3a7640000", 16) // 1e18
	got := ERC20ApproveCalldata(spender, amount)
	want := "095ea7b3" +
		"0000000000000000000000004444444444444444444444444444444444444444" +
		"0000000000000000000000000000000000000000000000000de0b6b3a7640000"
	if hex.EncodeToString(got) != want {
		t.Fatalf("ERC20ApproveCalldata:\n got  %s\n want %s", hex.EncodeToString(got), want)
	}
}

// Pins ERC20PermitCalldata against the ABI spec.
// owner=0x55*20, spender=0x66*20, value=1000, deadline=9999999, v=27, r=0xaa*32, s=0xbb*32
func TestERC20PermitCalldata(t *testing.T) {
	owner := addr20(0x55)
	spender := addr20(0x66)
	var r, s [32]byte
	for i := range r {
		r[i] = 0xaa
		s[i] = 0xbb
	}
	got := ERC20PermitCalldata(owner, spender, big.NewInt(1000), big.NewInt(9999999), 27, r, s)
	want := "d505accf" +
		"0000000000000000000000005555555555555555555555555555555555555555" +
		"0000000000000000000000006666666666666666666666666666666666666666" +
		"00000000000000000000000000000000000000000000000000000000000003e8" +
		"000000000000000000000000000000000000000000000000000000000098967f" +
		"000000000000000000000000000000000000000000000000000000000000001b" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if hex.EncodeToString(got) != want {
		t.Fatalf("ERC20PermitCalldata:\n got  %s\n want %s", hex.EncodeToString(got), want)
	}
}

// TestEIP2612SignAndRecover signs a permit and verifies ecrecover returns the
// wallet's own address, confirming the EIP-712 domain + struct hash are correct.
func TestEIP2612SignAndRecover(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	tokenAddr := addr20(0xab)
	spender := addr20(0xcd)
	v, r, s, err := w.SignERC20Permit(
		ETH, 0,
		big.NewInt(1), // chainId = 1
		tokenAddr, "TestToken",
		spender,
		big.NewInt(1_000_000), // value
		big.NewInt(0),         // nonce
		big.NewInt(9999999),   // deadline
	)
	if err != nil {
		t.Fatalf("SignERC20Permit: %v", err)
	}
	if v != 27 && v != 28 {
		t.Fatalf("v = %d, want 27 or 28", v)
	}

	// Reassemble the 65-byte sig and verify ecrecover matches the wallet address.
	sig := make([]byte, 65)
	copy(sig[:32], r[:])
	copy(sig[32:64], s[:])
	sig[64] = v

	// Rebuild the same digest by going through the typed-data path directly.
	td, err := eip2612TypedData(
		big.NewInt(1), tokenAddr, "TestToken",
		"0x9858EfFD232B4033E47d90003D41EC34EcaEda94", // canonical mnemonic ETH index 0
		spender,
		big.NewInt(1_000_000), big.NewInt(0), big.NewInt(9999999),
	)
	if err != nil {
		t.Fatalf("eip2612TypedData: %v", err)
	}
	if !VerifyEthereumTypedData("0x9858EfFD232B4033E47d90003D41EC34EcaEda94", td, sig) {
		t.Fatal("EIP-2612 signature did not verify against the wallet's ETH address")
	}
}

// ---- CREATE2 ---------------------------------------------------------------

// Pins CREATE2Address against the EIP-1014 reference vector.
// deployer=0x0*20, salt=0x0*32, initCode=0x00 → 0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38
func TestCREATE2Address(t *testing.T) {
	deployer := make([]byte, 20)
	var salt [32]byte
	initCode := []byte{0x00}
	got := CREATE2Address(deployer, salt, initCode)
	want := decodeHex(t, "4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38")
	if !bytes.Equal(got, want) {
		t.Fatalf("CREATE2Address = %x, want %x", got, want)
	}
}

// ---- ERC-4337 --------------------------------------------------------------

func TestUserOpHashDeterminism(t *testing.T) {
	op := &UserOperation{
		Sender:               addr20(0xaa),
		Nonce:                big.NewInt(1),
		InitCode:             nil,
		CallData:             []byte{0xca, 0xfe},
		CallGasLimit:         big.NewInt(100_000),
		VerificationGasLimit: big.NewInt(200_000),
		PreVerificationGas:   big.NewInt(50_000),
		MaxFeePerGas:         big.NewInt(1e9),
		MaxPriorityFeePerGas: big.NewInt(2e8),
		PaymasterAndData:     nil,
	}
	ep := addr20(0xee)
	h1 := UserOperationHash(op, ep, big.NewInt(1))
	h2 := UserOperationHash(op, ep, big.NewInt(1))
	if !bytes.Equal(h1, h2) {
		t.Fatal("UserOperationHash is not deterministic")
	}
	if len(h1) != 32 {
		t.Fatalf("hash length = %d, want 32", len(h1))
	}
	// Different chainId must produce a different hash.
	h3 := UserOperationHash(op, ep, big.NewInt(137))
	if bytes.Equal(h1, h3) {
		t.Fatal("different chainId produced the same hash")
	}
}

// TestUserOpSignAndRecover signs a UserOperation and verifies ecrecover returns
// the wallet's ETH address at index 0, proving the EIP-191 wrapping is correct.
func TestUserOpSignAndRecover(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	op := &UserOperation{
		Sender:               addr20(0xaa),
		Nonce:                big.NewInt(0),
		CallData:             []byte{0x12, 0x34},
		CallGasLimit:         big.NewInt(100_000),
		VerificationGasLimit: big.NewInt(200_000),
		PreVerificationGas:   big.NewInt(50_000),
		MaxFeePerGas:         big.NewInt(1e9),
		MaxPriorityFeePerGas: big.NewInt(1e8),
	}
	ep := addr20(0xee)
	chainID := big.NewInt(1)

	sig, err := w.SignUserOperation(ETH, 0, op, ep, chainID)
	if err != nil {
		t.Fatalf("SignUserOperation: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("sig len = %d, want 65", len(sig))
	}
	if v := sig[64]; v != 27 && v != 28 {
		t.Fatalf("v = %d, want 27/28", v)
	}

	// Verify: the userOpHash is signed via personal_sign, so use RecoverEthereumAddress.
	hash := UserOperationHash(op, ep, chainID)
	recovered, err := RecoverEthereumAddress(hash, sig)
	if err != nil {
		t.Fatalf("RecoverEthereumAddress: %v", err)
	}
	const wantAddr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
	if !strings.EqualFold(recovered, wantAddr) {
		t.Fatalf("recovered %s, want %s", recovered, wantAddr)
	}
}
