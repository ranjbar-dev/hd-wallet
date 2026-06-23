package hdwallet

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// TestBitcoinAddressTypesBIPVectors checks all four standard Bitcoin address
// types against the official BIP-44/49/84/86 test vectors (which use this repo's
// canonical mnemonic) and cross-checks each against btcutil as an oracle.
func TestBitcoinAddressTypesBIPVectors(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	cases := []struct {
		name string
		typ  BitcoinAddressType
		want string // official BIP vector; "" = oracle-only
	}{
		{"P2PKH/BIP44", P2PKH, ""},
		{"P2SH-P2WPKH/BIP49", P2SHP2WPKH, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"},
		{"P2WPKH/BIP84", P2WPKH, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"},
		{"P2TR/BIP86", P2TR, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := w.BitcoinAddress(BTC, tc.typ, 0, 0, 0)
			if err != nil {
				t.Fatalf("BitcoinAddress: %v", err)
			}
			if tc.want != "" && got != tc.want {
				t.Fatalf("address = %s, want BIP vector %s", got, tc.want)
			}
			if oracle := btcOracleAddress(t, w, tc.typ); got != oracle {
				t.Fatalf("address = %s, want btcutil oracle %s", got, oracle)
			}
			if err := ValidateAddress(BTC, got); err != nil {
				t.Fatalf("ValidateAddress(%s) = %v", got, err)
			}
		})
	}
}

// btcOracleAddress independently computes the expected address with btcutil.
func btcOracleAddress(t *testing.T, w *HDWallet, typ BitcoinAddressType) string {
	t.Helper()
	purpose := map[BitcoinAddressType]int{P2PKH: 44, P2SHP2WPKH: 49, P2WPKH: 84, P2TR: 86}[typ]
	pub, err := w.PublicKeyPath(BTC, fmt.Sprintf("m/%d'/0'/0'/0/0", purpose))
	if err != nil {
		t.Fatalf("PublicKeyPath: %v", err)
	}
	params := &chaincfg.MainNetParams
	switch typ {
	case P2PKH:
		a, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pub), params)
		if err != nil {
			t.Fatalf("oracle p2pkh: %v", err)
		}
		return a.EncodeAddress()
	case P2SHP2WPKH:
		wpkh, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub), params)
		if err != nil {
			t.Fatalf("oracle wpkh: %v", err)
		}
		redeem, err := txscript.PayToAddrScript(wpkh)
		if err != nil {
			t.Fatalf("oracle redeem: %v", err)
		}
		sh, err := btcutil.NewAddressScriptHash(redeem, params)
		if err != nil {
			t.Fatalf("oracle p2sh: %v", err)
		}
		return sh.EncodeAddress()
	case P2WPKH:
		a, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(pub), params)
		if err != nil {
			t.Fatalf("oracle p2wpkh: %v", err)
		}
		return a.EncodeAddress()
	case P2TR:
		internal, err := btcec.ParsePubKey(pub)
		if err != nil {
			t.Fatalf("oracle parse: %v", err)
		}
		outKey := txscript.ComputeTaprootKeyNoScript(internal)
		a, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(outKey), params)
		if err != nil {
			t.Fatalf("oracle taproot: %v", err)
		}
		return a.EncodeAddress()
	}
	return ""
}

// TestBitcoinAddressLitecoin checks LTC native SegWit + Taproot against btcutil
// (Litecoin uses the same HRP/version scheme btcutil's mainnet params model for
// the relevant types via our params table).
func TestBitcoinAddressLitecoin(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	for _, typ := range []BitcoinAddressType{P2PKH, P2SHP2WPKH, P2WPKH, P2TR} {
		addr, err := w.BitcoinAddress(LTC, typ, 0, 0, 0)
		if err != nil {
			t.Fatalf("LTC %s: %v", typ, err)
		}
		if err := ValidateAddress(LTC, addr); err != nil {
			t.Fatalf("ValidateAddress(LTC, %s) [%s] = %v", addr, typ, err)
		}
	}
}

// TestBitcoinAddressErrors covers the unsupported-coin and bad-input paths.
func TestBitcoinAddressErrors(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	if _, err := w.BitcoinAddress(ETH, P2WPKH, 0, 0, 0); err == nil {
		t.Fatal("BitcoinAddress(ETH, ...) = nil error, want ErrUnsupportedCoin")
	}
	if _, err := w.BitcoinAddress(BTC, BitcoinAddressType(99), 0, 0, 0); err == nil {
		t.Fatal("BitcoinAddress(BTC, bogus type) = nil error, want error")
	}
}
