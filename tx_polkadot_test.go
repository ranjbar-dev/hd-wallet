package hdwallet

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	txdot "github.com/ranjbar-dev/hd-wallet/txproto/polkadot"
)

// Polkadot (DOT) transaction signing — vector-pinned tests.
//
// Source: Trust Wallet Core TWAnySignerTests.cpp (Polkadot), test
// "TEST(TWAnySignerPolkadot, SignTransfer_9fd062)":
// https://github.com/trustwallet/wallet-core/blob/master/tests/chains/Polkadot/TWAnySignerTests.cpp
// On-chain: https://polkadot.subscan.io/extrinsic/0x9fd06208a6023e489147d8d93f0182b0cb7e45a40165247319b87278e08362d8
//
// ed25519 is deterministic, so both the signing preimage and the fully signed
// extrinsic (including the signature bytes) pin byte-for-byte.

// dotTestPrivKey returns a fresh copy of TWC's privateKeyThrow2 (ed25519 seed);
// FromPrivateKeyBytes wipes its input, so each test needs its own copy.
func dotTestPrivKey() []byte {
	k, _ := hex.DecodeString("70a794d4f1019c3ce002f33062f45029c4f930a56b3d20ec477f7668c6bbc37f")
	return k
}

// dotTestSender is the SS58 address TWC derives for dotTestPrivKey (prefix 0).
const dotTestSender = "14Ztd3KJDaB9xyJtRkREtSZDdhLSbm7UUKt8Z7AwSv7q85G2"

// dotTestRecipient is the vector's transfer destination.
const dotTestRecipient = "13ZLCqJNPsRZYEbwjtZZFpWt9GyFzg5WahXCVWKpWdUJqrQ5"

var (
	dotTestGenesisHash, _ = hex.DecodeString("91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3")
	dotTestBlockHash, _   = hex.DecodeString("5d2143bb808626d63ad7e1cda70fa8697059d670a992e82cd440fbb95ea40351")
)

// dotVectorInput reproduces the SignTransfer_9fd062 SigningInput. The vector
// predates MultiAddress (spec 26 ⇒ raw AccountId) and calls Balances.transfer
// (call index 5/0), so the default transfer_keep_alive indices are overridden.
func dotVectorInput() *txdot.SigningInput {
	return &txdot.SigningInput{
		GenesisHash:        dotTestGenesisHash,
		BlockHash:          dotTestBlockHash,
		Nonce:              3,
		SpecVersion:        26,
		TransactionVersion: 5,
		Era:                &txdot.Era{BlockNumber: 3541050, Period: 64},
		Network:            0,
		MessageOneof: &txdot.SigningInput_BalanceTransfer{BalanceTransfer: &txdot.BalanceTransfer{
			ToAddress:   dotTestRecipient,
			Value:       big.NewInt(2000000000).Bytes(), // 0.2 DOT in planck
			CallIndices: &txdot.CallIndices{ModuleIndex: 5, MethodIndex: 0},
		}},
	}
}

// TestSignTxDOT pins the Polkadot signer byte-for-byte to the TWC vector:
// sender address, signing preimage, and the fully signed extrinsic.
func TestSignTxDOT(t *testing.T) {
	w, err := FromPrivateKeyBytes(dotTestPrivKey(), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	addr, err := w.Address(DOT)
	if err != nil {
		t.Fatalf("Address(DOT): %v", err)
	}
	if addr != dotTestSender {
		t.Fatalf("sender address = %s, want %s", addr, dotTestSender)
	}

	input := dotVectorInput()

	call, err := dotBuildCall(input)
	if err != nil {
		t.Fatalf("dotBuildCall: %v", err)
	}
	preimage, _, err := dotSigningPayload(input, call)
	if err != nil {
		t.Fatalf("dotSigningPayload: %v", err)
	}
	const wantPreimage = "05007120f76076bcb0efdf94c7219e116899d0163ea61cb428183d71324eb33b2bce0300943577a5030c001a0000000500000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c35d2143bb808626d63ad7e1cda70fa8697059d670a992e82cd440fbb95ea40351"
	if got := hex.EncodeToString(preimage); got != wantPreimage {
		t.Fatalf("signing preimage:\n got %s\nwant %s", got, wantPreimage)
	}

	out, err := w.SignTransaction(DOT, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	got, ok := out.(*txdot.SigningOutput)
	if !ok {
		t.Fatalf("expected *polkadot.SigningOutput, got %T", out)
	}
	const wantEncoded = "3502849dca538b7a925b8ea979cc546464a3c5f81d2398a3a272f6f93bdf4803f2f7830073e59cef381aedf56d7af076bafff9857ffc1e3bd7d1d7484176ff5b58b73f1211a518e1ed1fd2ea201bd31869c0798bba4ffe753998c409d098b65d25dff801a5030c0005007120f76076bcb0efdf94c7219e116899d0163ea61cb428183d71324eb33b2bce0300943577"
	if gotHex := hex.EncodeToString(got.Encoded); gotHex != wantEncoded {
		t.Fatalf("signed extrinsic:\n got %s\nwant %s", gotHex, wantEncoded)
	}
	if got.EncodedHex != "0x"+wantEncoded {
		t.Fatalf("EncodedHex = %s, want 0x%s", got.EncodedHex, wantEncoded)
	}
}

// TestSignTxDOTAssetTransfer anchors the Asset Hub Assets.transfer_keep_alive
// structure (no TWC Asset Hub vector exists on master): walks the encoded
// extrinsic field by field — immortal era, MultiAddress signer/dest, default
// (50, 9) call indices, compact asset id 1984 (USDT) — and ed25519-verifies
// the embedded signature against the reconstructed signing preimage.
func TestSignTxDOTAssetTransfer(t *testing.T) {
	w, err := FromPrivateKeyBytes(dotTestPrivKey(), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	input := &txdot.SigningInput{
		GenesisHash:        dotTestGenesisHash,
		Nonce:              0,
		SpecVersion:        1002000,
		TransactionVersion: 15,
		MultiAddress:       true, // Asset Hub uses MultiAddress
		MessageOneof: &txdot.SigningInput_AssetTransfer{AssetTransfer: &txdot.AssetTransfer{
			ToAddress: dotTestRecipient,
			Value:     big.NewInt(5000000).Bytes(), // 5 USDT (6 decimals)
			AssetId:   1984,                        // USDT on Polkadot Asset Hub
		}},
	}

	out, err := w.SignTransaction(DOT, 0, input)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	enc := out.(*txdot.SigningOutput).Encoded

	pub, err := w.PublicKey(DOT)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	dest, err := ss58Validator(0, DOT)(dotTestRecipient)
	if err != nil {
		t.Fatalf("decode recipient: %v", err)
	}

	// Expected call: (50, 9) ‖ compact(1984) ‖ MultiAddress(dest) ‖ compact(5000000).
	wantCall := []byte{50, 9, 0x01, 0x1f, 0x00}
	wantCall = append(wantCall, dest...)
	wantCall = append(wantCall, scaleCompact(big.NewInt(5000000))...)

	// Body layout: 0x84 ‖ 0x00‖pub(32) ‖ 0x00 ‖ sig(64) ‖ era(0x00) ‖
	// compact(nonce)=0x00 ‖ compact(tip)=0x00 ‖ call. Length prefix: 2 bytes.
	body := enc[2:]
	wantLen := 1 + 33 + 1 + 64 + 3 + len(wantCall)
	if len(body) != wantLen {
		t.Fatalf("body length = %d, want %d", len(body), wantLen)
	}
	if body[0] != 0x84 {
		t.Fatalf("extrinsic version byte = 0x%02x, want 0x84", body[0])
	}
	if body[1] != 0x00 || !bytes.Equal(body[2:34], pub) {
		t.Fatalf("signer = %x, want MultiAddress(0x00 || %x)", body[1:34], pub)
	}
	if body[34] != 0x00 {
		t.Fatalf("MultiSignature discriminant = 0x%02x, want 0x00 (Ed25519)", body[34])
	}
	sig := body[35:99]
	if !bytes.Equal(body[99:102], []byte{0x00, 0x00, 0x00}) {
		t.Fatalf("era/nonce/tip = %x, want 000000 (immortal, nonce 0, tip 0)", body[99:102])
	}
	if !bytes.Equal(body[102:], wantCall) {
		t.Fatalf("call = %x, want %x", body[102:], wantCall)
	}

	// The signature must verify over the reconstructed preimage (which uses
	// the genesis hash as the mortality checkpoint for an immortal era).
	call, err := dotBuildCall(input)
	if err != nil {
		t.Fatalf("dotBuildCall: %v", err)
	}
	preimage, _, err := dotSigningPayload(input, call)
	if err != nil {
		t.Fatalf("dotSigningPayload: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), preimage, sig) {
		t.Fatal("ed25519 signature does not verify over the signing preimage")
	}
}

// TestDotEncodeEra pins the mortal-era quantization to the era bytes inside
// both TWC Polkadot vectors, plus the immortal case.
func TestDotEncodeEra(t *testing.T) {
	cases := []struct {
		name string
		era  *txdot.Era
		want []byte
	}{
		{"immortal", nil, []byte{0x00}},
		{"SignTransfer_9fd062", &txdot.Era{BlockNumber: 3541050, Period: 64}, []byte{0xa5, 0x03}},
		{"CompileWithSignatures", &txdot.Era{BlockNumber: 5898150, Period: 10000}, []byte{0x9d, 0xfe}},
	}
	for _, c := range cases {
		if got := dotEncodeEra(c.era); !bytes.Equal(got, c.want) {
			t.Errorf("%s: era = %x, want %x", c.name, got, c.want)
		}
	}
}

// TestScaleCompact checks the SCALE compact encoder across all four modes,
// including the two big-integer values embedded in the TWC vectors.
func TestScaleCompact(t *testing.T) {
	cases := []struct {
		v    *big.Int
		want string
	}{
		{big.NewInt(0), "00"},
		{big.NewInt(1), "04"},
		{big.NewInt(63), "fc"},
		{big.NewInt(64), "0101"},
		{big.NewInt(16383), "fdff"},
		{big.NewInt(16384), "02000100"},
		{big.NewInt(1<<30 - 1), "feffffff"},
		{big.NewInt(2000000000), "0300943577"},     // SignTransfer_9fd062 value
		{big.NewInt(0x210fdc0c00), "07000cdc0f21"}, // CompileWithSignatures value
	}
	for _, c := range cases {
		if got := hex.EncodeToString(scaleCompact(c.v)); got != c.want {
			t.Errorf("scaleCompact(%s) = %s, want %s", c.v, got, c.want)
		}
	}
}

// TestSignTxDOTInputErrors covers the fund-critical input guards.
func TestSignTxDOTInputErrors(t *testing.T) {
	w, err := FromPrivateKeyBytes(dotTestPrivKey(), Ed25519)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	// Missing message oneof.
	in := dotVectorInput()
	in.MessageOneof = nil
	if _, err := w.SignTransaction(DOT, 0, in); !errors.Is(err, ErrTxInput) {
		t.Errorf("missing message: err = %v, want ErrTxInput", err)
	}

	// Bad genesis hash length.
	in = dotVectorInput()
	in.GenesisHash = in.GenesisHash[:31]
	if _, err := w.SignTransaction(DOT, 0, in); !errors.Is(err, ErrTxInput) {
		t.Errorf("short genesis: err = %v, want ErrTxInput", err)
	}

	// Recipient with the wrong SS58 network prefix must be rejected.
	in = dotVectorInput()
	in.Network = 2 // Kusama prefix; the address is prefix 0
	if _, err := w.SignTransaction(DOT, 0, in); !errors.Is(err, ErrTxInput) {
		t.Errorf("prefix mismatch: err = %v, want ErrTxInput", err)
	}

	// Value beyond u128.
	in = dotVectorInput()
	in.GetBalanceTransfer().Value = bytes.Repeat([]byte{0xff}, 17)
	if _, err := w.SignTransaction(DOT, 0, in); !errors.Is(err, ErrTxInput) {
		t.Errorf("oversize value: err = %v, want ErrTxInput", err)
	}

	// Out-of-range call-index override must error, not truncate.
	in = dotVectorInput()
	in.GetBalanceTransfer().CallIndices = &txdot.CallIndices{ModuleIndex: 256, MethodIndex: 0}
	if _, err := w.SignTransaction(DOT, 0, in); !errors.Is(err, ErrTxInput) {
		t.Errorf("oversize call index: err = %v, want ErrTxInput", err)
	}

	// Wrong proto type for the family.
	if err := ValidateSigningInput(DOT, dotVectorInput()); err != nil {
		t.Errorf("ValidateSigningInput(valid) = %v, want nil", err)
	}
	bad := dotVectorInput()
	bad.SpecVersion = 0
	if err := ValidateSigningInput(DOT, bad); !errors.Is(err, ErrTxInput) {
		t.Errorf("ValidateSigningInput(spec_version=0) = %v, want ErrTxInput", err)
	}
}
