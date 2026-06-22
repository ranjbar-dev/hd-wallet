package hdwallet

import (
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// The account xpub and watch-only derivation must reproduce exactly the same
// addresses the full seed wallet derives (which are TWC-vector-verified), proving
// AccountXPub selects the right account and WatchWallet walks change/index
// correctly — without ever touching the seed.
func TestWatchOnlyMatchesSeedWallet(t *testing.T) {
	w, err := FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	for _, symbol := range []Symbol{ETH, BTC} {
		t.Run(string(symbol), func(t *testing.T) {
			xpub, err := w.AccountXPub(symbol, 0)
			if err != nil {
				t.Fatalf("AccountXPub: %v", err)
			}
			ww, err := WatchOnlyFromXPub(xpub, symbol)
			if err != nil {
				t.Fatalf("WatchOnlyFromXPub: %v", err)
			}

			// change=0 (receive) index 0 == the wallet's default address.
			want0, _ := w.Address(symbol)
			got0, err := ww.Address(0, 0)
			if err != nil {
				t.Fatalf("watch Address(0,0): %v", err)
			}
			if got0 != want0 {
				t.Fatalf("%s watch (0,0)=%s != seed Address=%s", symbol, got0, want0)
			}

			// index 1 == AddressIndex(1).
			want1, _ := w.AddressIndex(symbol, 1)
			got1, err := ww.Address(0, 1)
			if err != nil {
				t.Fatalf("watch Address(0,1): %v", err)
			}
			if got1 != want1 {
				t.Fatalf("%s watch (0,1)=%s != AddressIndex(1)=%s", symbol, got1, want1)
			}

			// arbitrary index 5 via the path API.
			wantTemplate, _ := CoinInfo(symbol)
			full := accountReceivePath(wantTemplate.Path, 5)
			want5, err := w.AddressPath(symbol, full)
			if err != nil {
				t.Fatalf("AddressPath: %v", err)
			}
			got5, err := ww.Address(0, 5)
			if err != nil {
				t.Fatalf("watch Address(0,5): %v", err)
			}
			if got5 != want5 {
				t.Fatalf("%s watch (0,5)=%s != AddressPath=%s", symbol, got5, want5)
			}
		})
	}
}

// accountReceivePath rewrites a 5-element template's change to 0 and index to the
// given value (test helper for the (0,index) comparison).
func accountReceivePath(template string, index uint32) string {
	// template e.g. m/44'/60'/0'/0/0 -> m/44'/60'/0'/0/<index>
	p, err := withIndex(template, index)
	if err != nil {
		panic(err)
	}
	return p
}

// TestAccountXPrvNeutersToXPub confirms the exported xprv corresponds to the
// account xpub (parse xprv, neuter, compare).
func TestAccountXPrvNeutersToXPub(t *testing.T) {
	w, err := FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	xpub, err := w.AccountXPub(ETH, 0)
	if err != nil {
		t.Fatalf("AccountXPub: %v", err)
	}
	err = w.WithAccountXPrv(ETH, 0, func(xprv []byte) error {
		k, e := hdkeychain.NewKeyFromString(string(xprv))
		if e != nil {
			return e
		}
		if !k.IsPrivate() {
			t.Fatalf("exported key is not private")
		}
		neutered, e := k.Neuter()
		if e != nil {
			return e
		}
		if neutered.String() != xpub {
			t.Fatalf("xprv neutered to %s, want xpub %s", neutered.String(), xpub)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithAccountXPrv: %v", err)
	}
}

func TestExtKeyErrors(t *testing.T) {
	w, err := FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	// ed25519 coin -> unsupported.
	if _, err := w.AccountXPub(SOL, 0); !errors.Is(err, ErrExtKeyUnsupportedCurve) {
		t.Fatalf("AccountXPub(SOL) error = %v, want ErrExtKeyUnsupportedCurve", err)
	}
	if _, err := WatchOnlyFromXPub("xpub-irrelevant", SOL); !errors.Is(err, ErrExtKeyUnsupportedCurve) {
		t.Fatalf("WatchOnlyFromXPub(SOL) error = %v, want ErrExtKeyUnsupportedCurve", err)
	}
	// bad xpub string.
	if _, err := WatchOnlyFromXPub("not-an-xpub", ETH); err == nil {
		t.Fatalf("WatchOnlyFromXPub(bad): expected error")
	}

	// hardened child rejected by watch-only.
	xpub, _ := w.AccountXPub(ETH, 0)
	ww, _ := WatchOnlyFromXPub(xpub, ETH)
	if _, err := ww.Address(0, hardenedOffset); !errors.Is(err, ErrExtKeyUnsupportedCurve) {
		t.Fatalf("watch hardened index error = %v, want ErrExtKeyUnsupportedCurve", err)
	}

	// key-only wallet has no extended keys.
	kw, _ := FromPrivateKeyBytes(mustHex(t, wifTestKeyHex), Secp256k1)
	defer kw.Destroy()
	if _, err := kw.AccountXPub(BTC, 0); !errors.Is(err, ErrKeyOnlyWallet) {
		t.Fatalf("key-only AccountXPub error = %v, want ErrKeyOnlyWallet", err)
	}
}
