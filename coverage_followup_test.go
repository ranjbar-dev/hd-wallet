package hdwallet

import (
	"bytes"
	"errors"
	"testing"

	"github.com/awnumar/memguard"
	btcec "github.com/btcsuite/btcd/btcec/v2"

	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
)

// --- WS-A: bitcoinVarInt — every CompactSize branch (was 14.3% covered) ---

func TestBitcoinVarIntForms(t *testing.T) {
	cases := []struct {
		n    uint64
		want []byte
	}{
		{0x00, []byte{0x00}},
		{0xfc, []byte{0xfc}},                                                        // last single-byte
		{0xfd, []byte{0xfd, 0xfd, 0x00}},                                            // first 3-byte
		{0xffff, []byte{0xfd, 0xff, 0xff}},                                          // last 3-byte
		{0x10000, []byte{0xfe, 0x00, 0x00, 0x01, 0x00}},                             // first 5-byte
		{0xffffffff, []byte{0xfe, 0xff, 0xff, 0xff, 0xff}},                          // last 5-byte
		{0x100000000, []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}}, // first 9-byte
	}
	for _, c := range cases {
		if got := bitcoinVarInt(c.n); !bytes.Equal(got, c.want) {
			t.Errorf("bitcoinVarInt(%#x) = % x, want % x", c.n, got, c.want)
		}
	}
}

// TestBitcoinMessageDigestMultiByteLength exercises the 3-byte length prefix in
// the real signing path: a >=253-byte message forces bitcoinVarInt's 0xfd branch
// inside bitcoinMessageDigest.
func TestBitcoinMessageDigestMultiByteLength(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	msg := bytes.Repeat([]byte("a"), 300) // 300 > 252 -> 3-byte CompactSize
	sig, err := w.SignBitcoinMessage(BTC, 0, msg)
	if err != nil {
		t.Fatalf("SignBitcoinMessage: %v", err)
	}
	// 65 raw bytes -> 88 base64 chars (with padding).
	if len(sig) != 88 {
		t.Errorf("base64 sig length = %d, want 88", len(sig))
	}
}

// --- WS-A: ABI decode error branches (decode* were 70-78% covered) ---

func TestABIDecodeErrorBranches(t *testing.T) {
	word := make([]byte, 32)

	t.Run("ABIDecode short input", func(t *testing.T) {
		if _, _, err := ABIDecode([]string{"uint256"}, []byte{0x01, 0x02}); !errors.Is(err, ErrABIDecode) {
			t.Errorf("err = %v, want ErrABIDecode", err)
		}
	})

	t.Run("static scalar truncated", func(t *testing.T) {
		if _, err := ABIDecodeParams([]string{"uint256"}, []byte{0x00, 0x01}); !errors.Is(err, ErrABIDecode) {
			t.Errorf("err = %v, want ErrABIDecode", err)
		}
	})

	t.Run("dynamic offset past end", func(t *testing.T) {
		// One dynamic head word whose offset (0xff) points beyond the data.
		head := make([]byte, 32)
		head[31] = 0xff
		if _, err := ABIDecodeParams([]string{"bytes"}, head); !errors.Is(err, ErrABIDecode) {
			t.Errorf("err = %v, want ErrABIDecode", err)
		}
	})

	t.Run("dynamic length overruns buffer", func(t *testing.T) {
		// offset=32, then a length word claiming 0xff bytes that aren't present.
		data := make([]byte, 64)
		data[31] = 0x20 // offset -> 32
		data[63] = 0xff // declared length 255, but no payload follows
		if _, err := ABIDecodeParams([]string{"bytes"}, data); !errors.Is(err, ErrABIDecode) {
			t.Errorf("err = %v, want ErrABIDecode", err)
		}
	})

	t.Run("dynamic array count truncated", func(t *testing.T) {
		// offset points at a region too short to hold the array length word.
		data := make([]byte, 33)
		data[31] = 0x20 // offset 32 -> region is 1 byte, can't hold a count word
		if _, err := ABIDecodeParams([]string{"uint256[]"}, data); !errors.Is(err, ErrABIDecode) {
			t.Errorf("err = %v, want ErrABIDecode", err)
		}
	})

	t.Run("unsupported scalar type", func(t *testing.T) {
		if _, err := decodeScalar("widget", word, 0); !errors.Is(err, ErrABIType) {
			t.Errorf("err = %v, want ErrABIType", err)
		}
	})
}

// --- WS-A: EIP-712 hash error branches (EIP712Hash was 70.8% covered) ---

func TestEIP712HashErrorBranches(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"invalid json", `{not json`},
		{"missing primaryType", `{"types":{"EIP712Domain":[]},"domain":{},"message":{}}`},
		{"missing EIP712Domain", `{"primaryType":"Mail","types":{"Mail":[]},"domain":{},"message":{}}`},
		{"bad domain json", `{"primaryType":"Mail","types":{"EIP712Domain":[],"Mail":[]},"domain":3,"message":{}}`},
		{"bad message json", `{"primaryType":"Mail","types":{"EIP712Domain":[],"Mail":[]},"domain":{},"message":7}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := EIP712Hash([]byte(c.json)); !errors.Is(err, ErrEIP712) {
				t.Errorf("EIP712Hash err = %v, want ErrEIP712", err)
			}
		})
	}
}

// --- WS-A: key-management error branches (WIF/PrivateKeyPath/Mnemonic) ---

func TestKeyMgmtErrorBranches(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("WIF wrong curve", func(t *testing.T) {
		// SOL is ed25519 -> WIF (Bitcoin secp256k1) must reject.
		if _, err := w.WIF(SOL, 0); !errors.Is(err, ErrInvalidWIF) {
			t.Errorf("WIF(SOL) err = %v, want ErrInvalidWIF", err)
		}
	})

	t.Run("WatchOnlyFromXPub wrong curve", func(t *testing.T) {
		if _, err := WatchOnlyFromXPub("xpub-irrelevant", SOL); !errors.Is(err, ErrExtKeyUnsupportedCurve) {
			t.Errorf("WatchOnlyFromXPub(SOL) err = %v, want ErrExtKeyUnsupportedCurve", err)
		}
	})

	t.Run("PrivateKeyPath bad path", func(t *testing.T) {
		if _, err := w.PrivateKeyPath(BTC, "not/a/path"); err == nil {
			t.Error("PrivateKeyPath with bad path should error")
		}
	})

	// Destroyed-wallet paths.
	w.Destroy()
	if _, err := w.WIF(BTC, 0); !errors.Is(err, ErrDestroyed) {
		t.Errorf("WIF after Destroy err = %v, want ErrDestroyed", err)
	}
	if _, err := w.PrivateKeyPath(BTC, "m/44'/0'/0'/0/0"); !errors.Is(err, ErrDestroyed) {
		t.Errorf("PrivateKeyPath after Destroy err = %v, want ErrDestroyed", err)
	}
	if _, err := w.Mnemonic(); !errors.Is(err, ErrDestroyed) {
		t.Errorf("Mnemonic after Destroy err = %v, want ErrDestroyed", err)
	}
}

// --- WS-A: EVM message-signing verify (round-trip + negative) ---

func TestEthMessageVerifyRoundTrip(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	msg := []byte("hello evm")
	sig, err := w.SignMessage(ETH, 0, msg)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := RecoverEthereumAddress(msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	// Match against address (20-byte case).
	if !VerifyEthereumMessage(addr, msg, sig) {
		t.Error("verify by address should pass")
	}
	// Match against compressed (33) and uncompressed (65) public keys.
	pubC, err := w.PublicKeyIndex(ETH, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEthereumMessage("0x"+hexStr(pubC), msg, sig) {
		t.Error("verify by compressed pubkey should pass")
	}
	pk, err := btcec.ParsePubKey(pubC)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEthereumMessage("0x"+hexStr(pk.SerializeUncompressed()), msg, sig) {
		t.Error("verify by uncompressed pubkey should pass")
	}

	// Negatives.
	if VerifyEthereumMessage(addr, []byte("tampered"), sig) {
		t.Error("verify with wrong message should fail")
	}
	if VerifyEthereumMessage(addr, msg, sig[:64]) {
		t.Error("verify with short signature should fail")
	}
	bad := append([]byte(nil), sig...)
	bad[64] = 99 // invalid recovery byte
	if VerifyEthereumMessage(addr, msg, bad) {
		t.Error("verify with bad recovery byte should fail")
	}

	// Typed-data path: round-trip + malformed JSON returns false.
	td := []byte(`{"primaryType":"EIP712Domain","types":{"EIP712Domain":[{"name":"name","type":"string"}]},"domain":{"name":"x"},"message":{}}`)
	tsig, err := w.SignTypedData(ETH, 0, td)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEthereumTypedData(addr, td, tsig) {
		t.Error("typed-data verify should pass")
	}
	if VerifyEthereumTypedData(addr, []byte(`{bad`), tsig) {
		t.Error("typed-data verify with bad JSON should fail")
	}
	// SignTypedData propagates the EIP712Hash parse error.
	if _, err := w.SignTypedData(ETH, 0, []byte(`{bad`)); !errors.Is(err, ErrEIP712) {
		t.Errorf("SignTypedData(bad json) err = %v, want ErrEIP712", err)
	}
}

// hexStr is a tiny lower-case hex helper for the tests above.
func hexStr(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// --- WS-A: Solana message verify negatives (VerifySolanaMessage was 71.4%) ---

func TestSolanaMessageVerifyNegatives(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	msg := []byte("hello solana")
	sig, err := w.SignSolanaMessage(SOL, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := w.AddressIndex(SOL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySolanaMessage(addr, msg, sig) {
		t.Error("round-trip verify should pass")
	}
	if VerifySolanaMessage("not-a-valid-address", msg, sig) {
		t.Error("invalid address should fail")
	}
	if VerifySolanaMessage(addr, []byte("tampered"), sig) {
		t.Error("wrong message should fail")
	}
	if VerifySolanaMessage(addr, msg, "!!!not-base58!!!") {
		t.Error("invalid base58 signature should fail")
	}
}

// --- WS-B: destroyed secret-buffer constructors now wrap ErrDestroyed ---

func TestDestroyedBufferConstructorsWrapErrDestroyed(t *testing.T) {
	mnBuf := memguard.NewBufferFromBytes([]byte(canonicalMnemonic))
	mnBuf.Destroy()
	if _, err := FromMnemonicBuffer(mnBuf); !errors.Is(err, ErrDestroyed) {
		t.Errorf("FromMnemonicBuffer(destroyed) err = %v, want ErrDestroyed", err)
	}

	mnBuf2 := memguard.NewBufferFromBytes([]byte(canonicalMnemonic))
	mnBuf2.Destroy()
	if _, err := FromMnemonicBufferWithPassphrase(mnBuf2, nil); !errors.Is(err, ErrDestroyed) {
		t.Errorf("FromMnemonicBufferWithPassphrase(destroyed) err = %v, want ErrDestroyed", err)
	}

	keyBuf := memguard.NewBuffer(32)
	keyBuf.Destroy()
	if _, err := FromPrivateKeyBuffer(keyBuf, Secp256k1); !errors.Is(err, ErrDestroyed) {
		t.Errorf("FromPrivateKeyBuffer(destroyed) err = %v, want ErrDestroyed", err)
	}
}

// --- WS-B: exported EVM tx-mode constants select the right format ---

func TestEthTxModeConstants(t *testing.T) {
	if EthTxModeLegacy != 0 || EthTxModeEIP2930 != 1 || EthTxModeEIP1559 != 2 {
		t.Fatalf("unexpected tx-mode constant values: %d %d %d", EthTxModeLegacy, EthTxModeEIP2930, EthTxModeEIP1559)
	}
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	in := &txeth.SigningInput{
		ChainId:   []byte{0x01},
		Nonce:     []byte{0x09},
		GasPrice:  []byte{0x04, 0xa8, 0x17, 0xc8, 0x00},
		GasLimit:  []byte{0x52, 0x08},
		ToAddress: "0x3535353535353535353535353535353535353535",
		TxMode:    EthTxModeLegacy,
		Transaction: &txeth.Transaction{
			TransactionOneof: &txeth.Transaction_Transfer_{
				Transfer: &txeth.Transaction_Transfer{Amount: []byte{0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00}},
			},
		},
	}
	if _, err := w.SignTransaction(ETH, 0, in); err != nil {
		t.Fatalf("SignTransaction legacy via EthTxModeLegacy: %v", err)
	}
}
