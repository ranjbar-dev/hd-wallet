package hdwallet

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/awnumar/memguard"
	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// WS3: targeted coverage for under-tested helpers and 0%-covered public API.
// These are deterministic unit/round-trip tests; the authoritative vector tests
// live elsewhere. A few also assert error branches that fund-critical code must
// reject.

// --- XRP wire-format helpers (multi-byte length, large field/type codes) ---

func TestXRPVarLength(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{20, []byte{0x14}},  // account id length
		{192, []byte{0xc0}}, // boundary of single-byte form
		{193, []byte{0xc1, 0x00}},
		{12480, []byte{0xf0, 0xff}}, // boundary of two-byte form
		{12481, []byte{0xf1, 0x00, 0x00}},
	}
	for _, tc := range cases {
		if got := xrpVarLength(tc.n); !bytes.Equal(got, tc.want) {
			t.Errorf("xrpVarLength(%d) = %x, want %x", tc.n, got, tc.want)
		}
	}
}

func TestXRPFieldHeader(t *testing.T) {
	cases := []struct {
		typeCode, fieldCode int
		want                []byte
	}{
		{8, 5, []byte{0x85}},               // both small: packed
		{8, 17, []byte{0x80, 0x11}},        // small type, large field
		{17, 5, []byte{0x05, 0x11}},        // large type, small field
		{17, 18, []byte{0x00, 0x11, 0x12}}, // both large
	}
	for _, tc := range cases {
		if got := xrpFieldHeader(tc.typeCode, tc.fieldCode); !bytes.Equal(got, tc.want) {
			t.Errorf("xrpFieldHeader(%d,%d) = %x, want %x", tc.typeCode, tc.fieldCode, got, tc.want)
		}
	}
}

// --- small numeric / error helpers ---

func TestU32Trunc(t *testing.T) {
	if got := u32Trunc(0x1_0000_0007); got != 7 {
		t.Errorf("u32Trunc kept high bits: %x", got)
	}
	if got := u32Trunc(0xffffffff); got != 0xffffffff {
		t.Errorf("u32Trunc(0xffffffff) = %x", got)
	}
}

func TestErrInvalidKeyLen(t *testing.T) {
	err := errInvalidKeyLen("ed25519", 31, 32)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("31")) ||
		!bytes.Contains([]byte(err.Error()), []byte("32")) {
		t.Errorf("errInvalidKeyLen message missing detail: %v", err)
	}
}

func TestStripLeadingZeros(t *testing.T) {
	if got := stripLeadingZeros([]byte{0, 0, 1, 2}); !bytes.Equal(got, []byte{1, 2}) {
		t.Errorf("stripLeadingZeros = %x", got)
	}
	if got := stripLeadingZeros([]byte{0, 0, 0}); len(got) != 0 {
		t.Errorf("all-zero strip = %x, want empty", got)
	}
	if got := stripLeadingZeros(nil); len(got) != 0 {
		t.Errorf("nil strip = %x", got)
	}
}

// --- ABI type helpers and error branches ---

func TestCanonicalTypeShorthands(t *testing.T) {
	for in, want := range map[string]string{
		"uint": "uint256", "int": "int256", "byte": "bytes1",
		"  uint256  ": "uint256", "address": "address",
	} {
		if got := canonicalType(in); got != want {
			t.Errorf("canonicalType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestABIEncodeScalarErrors(t *testing.T) {
	bad := []ABIValue{
		{Type: "address", Value: []byte{1, 2}},   // wrong length
		{Type: "bool", Value: "nope"},            // wrong Go type
		{Type: "uint256", Value: "nope"},         // not *big.Int
		{Type: "bytes2", Value: make([]byte, 3)}, // wrong fixed size
		{Type: "bytes2", Value: 42},              // not []byte
		{Type: "weirdtype", Value: nil},          // unknown type
	}
	for _, v := range bad {
		if _, err := ABIEncodeParams([]ABIValue{v}); err == nil {
			t.Errorf("ABIEncodeParams(%+v) expected error", v)
		}
	}
}

func TestABITupleFieldCountMismatch(t *testing.T) {
	v := []ABIValue{{
		Type:  "(uint256,uint256)",
		Value: []ABIValue{{Type: "uint256", Value: big.NewInt(1)}}, // 1 field, want 2
	}}
	if _, err := ABIEncodeParams(v); err == nil {
		t.Error("tuple field-count mismatch should error")
	}
}

func TestABIFixedArraySizeMismatch(t *testing.T) {
	v := []ABIValue{{
		Type: "uint256[2]",
		Value: []ABIValue{
			{Type: "uint256", Value: big.NewInt(1)},
			{Type: "uint256", Value: big.NewInt(2)},
			{Type: "uint256", Value: big.NewInt(3)}, // 3, want 2
		},
	}}
	if _, err := ABIEncodeParams(v); err == nil {
		t.Error("fixed-array size mismatch should error")
	}
}

// Fixed-size array of a static tuple exercises staticWidth (element width) and
// decodeArray's static slicing on the decode side.
func TestABIFixedArrayOfTupleRoundTrip(t *testing.T) {
	addr := make([]byte, 20)
	addr[19] = 0xaa
	vals := []ABIValue{{
		Type: "(uint256,address)[2]",
		Value: []ABIValue{
			{Value: []ABIValue{{Type: "uint256", Value: big.NewInt(11)}, {Type: "address", Value: addr}}},
			{Value: []ABIValue{{Type: "uint256", Value: big.NewInt(22)}, {Type: "address", Value: addr}}},
		},
	}}
	enc, err := ABIEncodeParams(vals)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := ABIDecodeParams([]string{"(uint256,address)[2]"}, enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr := out[0].Value.([]ABIValue)
	if len(arr) != 2 {
		t.Fatalf("got %d elements", len(arr))
	}
	first := arr[0].Value.([]ABIValue)
	if first[0].Value.(*big.Int).Int64() != 11 {
		t.Errorf("tuple[0] uint mismatch: %v", first[0].Value)
	}
}

// --- RLP long-list decode (payload >= 56 bytes) ---

func TestRLPLongListRoundTrip(t *testing.T) {
	// 4 * 32-byte strings -> 132-byte payload -> long-list form (0xf8..).
	var items []RLPItem
	for i := 0; i < 4; i++ {
		items = append(items, RLPString(bytes.Repeat([]byte{byte(i + 1)}, 32)))
	}
	enc := EncodeRLP(RLPList(items...))
	if enc[0] < 0xf8 {
		t.Fatalf("expected long-list prefix, got 0x%02x", enc[0])
	}
	dec, err := DecodeRLP(enc)
	if err != nil {
		t.Fatalf("DecodeRLP: %v", err)
	}
	if !dec.IsList || len(dec.List) != 4 || !bytes.Equal(dec.List[3].Str, bytes.Repeat([]byte{4}, 32)) {
		t.Fatalf("long-list round-trip mismatch")
	}
}

// --- EIP-712: atom-type coverage (bytes, address, negative int, bytesN, array) ---

const eip712AtomsExample = `{
  "types": {
    "EIP712Domain": [{"name":"name","type":"string"}],
    "Bag": [
      {"name":"id","type":"uint256"},
      {"name":"delta","type":"int256"},
      {"name":"who","type":"address"},
      {"name":"blob","type":"bytes"},
      {"name":"tag","type":"bytes4"},
      {"name":"flag","type":"bool"},
      {"name":"nums","type":"uint256[]"}
    ]
  },
  "primaryType": "Bag",
  "domain": {"name": "X"},
  "message": {
    "id": "0x1234",
    "delta": "-5",
    "who": "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "blob": "0xdeadbeef",
    "tag": "0xcafebabe",
    "flag": true,
    "nums": ["1", "2", "3"]
  }
}`

func TestEIP712AtomTypes(t *testing.T) {
	h, err := EIP712Hash([]byte(eip712AtomsExample))
	if err != nil {
		t.Fatalf("EIP712Hash: %v", err)
	}
	if len(h) != 32 {
		t.Fatalf("hash len %d", len(h))
	}
}

func TestEIP712HelperUnits(t *testing.T) {
	if e, ok := arrayElem("uint256[2][3]"); !ok || e != "uint256[2]" {
		t.Errorf("arrayElem outer = %q,%v", e, ok)
	}
	if _, ok := arrayElem("uint256"); ok {
		t.Error("arrayElem on scalar should be false")
	}
	if baseType("Person[2][]") != "Person" {
		t.Error("baseType strip")
	}
	if baseType("uint256") != "uint256" {
		t.Error("baseType passthrough")
	}
	// decodeIntValue: hex, empty, and malformed.
	if n, err := decodeIntValue(json.RawMessage(`""`)); err != nil || n.Sign() != 0 {
		t.Errorf("empty int = %v,%v", n, err)
	}
	if _, err := decodeIntValue(json.RawMessage(`"0xZZ"`)); err == nil {
		t.Error("bad hex int should error")
	}
	if _, err := decodeIntValue(json.RawMessage(`"not-a-number"`)); err == nil {
		t.Error("bad decimal int should error")
	}
	// decodeAddressValue length check.
	if _, err := decodeAddressValue(json.RawMessage(`"0x1234"`)); err == nil {
		t.Error("short address should error")
	}
	// encodeAtom unknown type.
	if _, err := encodeAtom("frobnicate", json.RawMessage(`"x"`)); err == nil {
		t.Error("unknown atom type should error")
	}
}

// --- Cosmos message dispatch: withdraw-reward body + empty-message rejection ---

func TestCosmosMessageAnyWithdrawAndEmpty(t *testing.T) {
	withdraw := &txcosmos.Message{MessageOneof: &txcosmos.Message_WithdrawReward{
		WithdrawReward: &txcosmos.MsgWithdrawReward{
			DelegatorAddress: "cosmos1delegator",
			ValidatorAddress: "cosmosvaloper1validator",
		},
	}}
	anyBytes, err := cosmosMessageAny(withdraw)
	if err != nil {
		t.Fatalf("withdraw message: %v", err)
	}
	if !bytes.Contains(anyBytes, []byte("MsgWithdrawDelegatorReward")) ||
		!bytes.Contains(anyBytes, []byte("cosmos1delegator")) {
		t.Errorf("withdraw Any missing expected content: %x", anyBytes)
	}

	if _, err := cosmosMessageAny(&txcosmos.Message{}); err == nil {
		t.Error("empty cosmos message should be rejected")
	}
}

// --- 0%-covered public API: path/account derivation, watch-only, buffer ctor ---

func TestPathAndAccountDerivationAgree(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	// For ETH the default path is m/44'/60'/0'/0/0, i.e. account/change/index 0.
	wantPub, err := w.PublicKey(ETH)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := w.PublicKeyAt(ETH, 0, 0, 0)
	if err != nil {
		t.Fatalf("PublicKeyAt: %v", err)
	}
	if !bytes.Equal(gotPub, wantPub) {
		t.Error("PublicKeyAt(0,0,0) != PublicKey")
	}

	// SignAt must produce a verifiable signature over a digest.
	digest := bytes.Repeat([]byte{0x11}, 32)
	sig, err := w.SignAt(ETH, 0, 0, 0, digest)
	if err != nil {
		t.Fatalf("SignAt: %v", err)
	}
	if !Verify(Secp256k1, wantPub, digest, sig) {
		t.Error("SignAt signature did not verify")
	}

	// PrivateKeyPath returns a wiped-on-Destroy buffer of the 32-byte leaf key.
	buf, err := w.PrivateKeyPath(ETH, "m/44'/60'/0'/0/0")
	if err != nil {
		t.Fatalf("PrivateKeyPath: %v", err)
	}
	if buf.Size() != 32 {
		t.Errorf("private key buffer size = %d, want 32", buf.Size())
	}
	buf.Destroy()
}

func TestWatchWalletPublicKeyMatches(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	xpub, err := w.AccountXPub(ETH, 0)
	if err != nil {
		t.Fatalf("AccountXPub: %v", err)
	}
	ww, err := WatchOnlyFromXPub(xpub, ETH)
	if err != nil {
		t.Fatalf("WatchOnlyFromXPub: %v", err)
	}
	gotPub, err := ww.PublicKey(0, 0)
	if err != nil {
		t.Fatalf("WatchWallet.PublicKey: %v", err)
	}
	wantPub, err := w.PublicKey(ETH)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPub, wantPub) {
		t.Error("watch-only PublicKey(0,0) != seed PublicKey(ETH)")
	}
	gotAddr, err := ww.Address(0, 0)
	if err != nil {
		t.Fatalf("WatchWallet.Address: %v", err)
	}
	wantAddr, _ := w.Address(ETH)
	if gotAddr != wantAddr {
		t.Errorf("watch-only Address = %s, want %s", gotAddr, wantAddr)
	}
}

// Dynamic array of a dynamic element type (bytes[]) drives decodeArray's
// per-element offset branch, distinct from the static-width path.
func TestABIDynamicElementArrayRoundTrip(t *testing.T) {
	vals := []ABIValue{{
		Type: "bytes[]",
		Value: []ABIValue{
			{Type: "bytes", Value: []byte("alpha")},
			{Type: "bytes", Value: []byte("a longer dynamic payload spanning words")},
		},
	}}
	enc, err := ABIEncodeParams(vals)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := ABIDecodeParams([]string{"bytes[]"}, enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr := out[0].Value.([]ABIValue)
	if len(arr) != 2 || string(arr[0].Value.([]byte)) != "alpha" ||
		string(arr[1].Value.([]byte)) != "a longer dynamic payload spanning words" {
		t.Fatalf("bytes[] round-trip mismatch: %+v", arr)
	}
}

func TestFromMnemonicBufferWithPassphrase(t *testing.T) {
	mnBuf := memguard.NewBufferFromBytes([]byte(canonicalMnemonic))
	// Empty passphrase (nil) must match the plain mnemonic wallet's ETH address.
	w, err := FromMnemonicBufferWithPassphrase(mnBuf, nil)
	if err != nil {
		t.Fatalf("FromMnemonicBufferWithPassphrase: %v", err)
	}
	defer w.Destroy()
	got, err := w.Address(ETH)
	if err != nil {
		t.Fatal(err)
	}

	ref, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Destroy()
	want, _ := ref.Address(ETH)
	if got != want {
		t.Errorf("buffer+empty-passphrase ETH = %s, want %s", got, want)
	}
}

func TestFromMnemonicBufferWithPassphraseNonEmpty(t *testing.T) {
	mnBuf := memguard.NewBufferFromBytes([]byte(canonicalMnemonic))
	passBuf := memguard.NewBufferFromBytes([]byte("TREZOR"))
	w, err := FromMnemonicBufferWithPassphrase(mnBuf, passBuf)
	if err != nil {
		t.Fatalf("FromMnemonicBufferWithPassphrase: %v", err)
	}
	defer w.Destroy()
	got, _ := w.Address(ETH)

	// Must match the plain passphrase entry point with the same passphrase...
	ref, err := FromMnemonicWithPassphrase([]byte(canonicalMnemonic), []byte("TREZOR"))
	if err != nil {
		t.Fatal(err)
	}
	defer ref.Destroy()
	want, _ := ref.Address(ETH)
	if got != want {
		t.Errorf("passphrase buffer ETH = %s, want %s", got, want)
	}
	// ...and differ from the empty-passphrase address (a real passphrase forks it).
	plain, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Destroy()
	if empty, _ := plain.Address(ETH); got == empty {
		t.Error("passphrase wallet should differ from empty-passphrase wallet")
	}
}

func TestFromMnemonicBufferWithPassphraseDestroyed(t *testing.T) {
	mnBuf := memguard.NewBufferFromBytes([]byte(canonicalMnemonic))
	passBuf := memguard.NewBufferFromBytes([]byte("x"))
	passBuf.Destroy() // destroyed before use -> must be rejected
	if _, err := FromMnemonicBufferWithPassphrase(mnBuf, passBuf); err == nil {
		t.Error("destroyed passphrase buffer should error")
	}
	mnBuf.Destroy() // not consumed on the error path; free it here
}
