package hdwallet

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/awnumar/memguard"
	bip39 "github.com/tyler-smith/go-bip39"
)

// canonicalMnemonic is the standard BIP-39 all-"abandon" test mnemonic.
const canonicalMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// End-to-end anchors that exercise full BIP-32 secp256k1 path derivation plus
// the encoder. BTC is the BIP-84 specification's first receive address; ETH is
// the widely published value for this mnemonic. Together with the SLIP-0010 and
// encoder vector tests, these prove the complete derive->encode pipeline.
func TestEndToEndKnownAddresses(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	cases := map[Symbol]string{
		BTC: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
		ETH: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
	}
	for symbol, want := range cases {
		got, err := w.Address(symbol)
		if err != nil {
			t.Fatalf("%s: %v", symbol, err)
		}
		if got != want {
			t.Errorf("%s = %s, want %s", symbol, got, want)
		}
	}
}

// TestEndToEndTrustWalletMnemonicVectors verifies the full mnemonic->seed->
// derive->encode pipeline against Trust Wallet Core's own HDWalletTests (which
// use a real mnemonic, empty passphrase). The Cosmos case exercises secp256k1
// bech32. Together with the BTC/ETH anchors and the SLIP-0010 ed25519 spec
// test, the secp256k1 and ed25519 curve families each have an end-to-end
// Trust Wallet vector.
func TestEndToEndTrustWalletMnemonicVectors(t *testing.T) {
	t.Run("Cosmos-secp256k1", func(t *testing.T) {
		// Stargaze (Cosmos SDK, hrp "stars"), m/44'/118'/0'/0/0, empty passphrase.
		w, err := FromMnemonic("rude segment two fury you output manual volcano sugar draft elite fame")
		if err != nil {
			t.Fatal(err)
		}
		defer w.Destroy()
		coin := Coin{Curve: Secp256k1, Path: "m/44'/118'/0'/0/0", Encode: cosmosEncoder("stars")}
		var got string
		if err := w.secret.withSeed(func(seed []byte) error {
			pub, err := derivePublicKey(seed, coin)
			if err != nil {
				return err
			}
			got, err = coin.Encode(pub)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		const want = "stars1mry47pkga5tdswtluy0m8teslpalkdq02a8nhy"
		if got != want {
			t.Errorf("Stargaze = %s, want %s", got, want)
		}
	})
}

func TestAllAddressesCoversRegistry(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	all, err := w.AllAddresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(SupportedCoins()) {
		t.Fatalf("AllAddresses returned %d coins, want %d", len(all), len(SupportedCoins()))
	}
	for _, symbol := range SupportedCoins() {
		if all[symbol] == "" {
			t.Errorf("no address for %s", symbol)
		}
	}
}

func TestGenerateAndImportRoundTrip(t *testing.T) {
	w, err := NewHDWallet()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	var phrase string
	if err := w.WithMnemonic(func(m []byte) error {
		phrase = string(m)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bip39.IsMnemonicValid(phrase) {
		t.Fatalf("generated mnemonic is invalid: %q", phrase)
	}

	// Re-importing the same mnemonic must reproduce the same address.
	w2, err := FromMnemonic(phrase)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Destroy()

	a1, _ := w.Address("ETH")
	a2, _ := w2.Address("ETH")
	if a1 != a2 {
		t.Errorf("round-trip ETH mismatch: %s vs %s", a1, a2)
	}
}

// --- Security: secret isolation ---

func TestFromMnemonicBytesWipesInput(t *testing.T) {
	in := []byte(canonicalMnemonic)
	w, err := FromMnemonicBytes(in)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	for i, b := range in {
		if b != 0 {
			t.Fatalf("input mnemonic not wiped at index %d (=%d)", i, b)
		}
	}
}

func TestFromMnemonicBuffer(t *testing.T) {
	const wantETH = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

	t.Run("exact", func(t *testing.T) {
		buf := memguard.NewBufferFromBytes([]byte(canonicalMnemonic))
		w, err := FromMnemonicBuffer(buf)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Destroy()
		if buf.IsAlive() {
			t.Error("buffer should be destroyed (ownership transferred)")
		}
		if got, _ := w.Address("ETH"); got != wantETH {
			t.Errorf("ETH = %s, want %s", got, wantETH)
		}
	})

	t.Run("trimmed", func(t *testing.T) {
		buf := memguard.NewBufferFromBytes([]byte("  " + canonicalMnemonic + "\n"))
		w, err := FromMnemonicBuffer(buf)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Destroy()
		if buf.IsAlive() {
			t.Error("buffer should be destroyed")
		}
		if got, _ := w.Address("ETH"); got != wantETH {
			t.Errorf("ETH = %s, want %s", got, wantETH)
		}
		// The stored mnemonic must be the trimmed phrase.
		if err := w.WithMnemonic(func(m []byte) error {
			if !bytes.Equal(m, []byte(canonicalMnemonic)) {
				t.Errorf("stored mnemonic = %q, want trimmed %q", m, canonicalMnemonic)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("invalid destroys buffer", func(t *testing.T) {
		buf := memguard.NewBufferFromBytes([]byte("totally not a mnemonic"))
		if _, err := FromMnemonicBuffer(buf); err == nil {
			t.Fatal("expected error for invalid mnemonic")
		}
		if buf.IsAlive() {
			t.Error("buffer should be destroyed even on error")
		}
	})

	t.Run("nil buffer", func(t *testing.T) {
		if _, err := FromMnemonicBuffer(nil); err == nil {
			t.Fatal("expected error for nil buffer")
		}
	})
}

func TestWithMnemonicReturnsCorrectPhrase(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	if err := w.WithMnemonic(func(m []byte) error {
		if !bytes.Equal(m, []byte(canonicalMnemonic)) {
			t.Errorf("mnemonic = %q, want %q", m, canonicalMnemonic)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDestroyDisablesWallet(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	w.Destroy()
	w.Destroy() // idempotent

	if _, err := w.Address("BTC"); err != ErrDestroyed {
		t.Errorf("Address after Destroy = %v, want ErrDestroyed", err)
	}
	if _, err := w.AllAddresses(); err != ErrDestroyed {
		t.Errorf("AllAddresses after Destroy = %v, want ErrDestroyed", err)
	}
	if err := w.WithMnemonic(func([]byte) error { return nil }); err != ErrDestroyed {
		t.Errorf("WithMnemonic after Destroy = %v, want ErrDestroyed", err)
	}
}

// TestHDWalletExposesNoPlaintextField is a structural guard: the wallet must not
// expose its secret material through any exported field.
func TestHDWalletExposesNoPlaintextField(t *testing.T) {
	typ := reflect.TypeFor[HDWallet]()
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			t.Errorf("HDWallet exposes exported field %q; secrets must stay unexported", typ.Field(i).Name)
		}
	}
}

func TestInvalidMnemonicRejected(t *testing.T) {
	if _, err := FromMnemonic("not a valid mnemonic phrase at all"); err == nil {
		t.Fatal("expected error for invalid mnemonic, got nil")
	}
}

func TestUnsupportedCoin(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()
	if _, err := w.Address("NOPE"); err == nil {
		t.Fatal("expected error for unsupported coin, got nil")
	}
}
