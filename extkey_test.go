package hdwallet

import (
	"errors"
	"strings"
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

	for _, chain := range []Chain{ETH, BTC} {
		t.Run(string(chain), func(t *testing.T) {
			xpub, err := w.AccountXPub(chain, 0)
			if err != nil {
				t.Fatalf("AccountXPub: %v", err)
			}
			ww, err := WatchOnlyFromXPub(xpub, chain)
			if err != nil {
				t.Fatalf("WatchOnlyFromXPub: %v", err)
			}

			// change=0 (receive) index 0 == the wallet's default address.
			want0, _ := w.Address(chain)
			got0, err := ww.Address(0, 0)
			if err != nil {
				t.Fatalf("watch Address(0,0): %v", err)
			}
			if got0 != want0 {
				t.Fatalf("%s watch (0,0)=%s != seed Address=%s", chain, got0, want0)
			}

			// index 1 == AddressIndex(1).
			want1, _ := w.AddressIndex(chain, 1)
			got1, err := ww.Address(0, 1)
			if err != nil {
				t.Fatalf("watch Address(0,1): %v", err)
			}
			if got1 != want1 {
				t.Fatalf("%s watch (0,1)=%s != AddressIndex(1)=%s", chain, got1, want1)
			}

			// arbitrary index 5 via the path API.
			wantTemplate, _ := CoinInfo(chain)
			full := accountReceivePath(wantTemplate.Path, 5)
			want5, err := w.AddressPath(chain, full)
			if err != nil {
				t.Fatalf("AddressPath: %v", err)
			}
			got5, err := ww.Address(0, 5)
			if err != nil {
				t.Fatalf("watch Address(0,5): %v", err)
			}
			if got5 != want5 {
				t.Fatalf("%s watch (0,5)=%s != AddressPath=%s", chain, got5, want5)
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

func TestDetectXPubVersion(t *testing.T) {
	w, err := FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	xpub, err := w.AccountXPub(BTC, 0)
	if err != nil {
		t.Fatalf("AccountXPub: %v", err)
	}

	if got := DetectXPubVersion(xpub); got != XPubVersionLegacy {
		t.Errorf("xpub: got %d, want XPubVersionLegacy", got)
	}

	// Synthesize a ypub from the xpub (same key data, different version bytes).
	body, err := base58CheckDecode(base58BTC, xpub)
	if err != nil {
		t.Fatalf("base58CheckDecode: %v", err)
	}
	copy(body[:4], ypubVer)
	ypub := base58CheckEncode(base58BTC, nil, body)
	if got := DetectXPubVersion(ypub); got != XPubVersionP2SHP2WPKH {
		t.Errorf("ypub: got %d, want XPubVersionP2SHP2WPKH", got)
	}

	// Synthesize a zpub.
	copy(body[:4], zpubVer)
	zpub := base58CheckEncode(base58BTC, nil, body)
	if got := DetectXPubVersion(zpub); got != XPubVersionP2WPKH {
		t.Errorf("zpub: got %d, want XPubVersionP2WPKH", got)
	}

	if got := DetectXPubVersion("notanextkey"); got != XPubVersionUnknown {
		t.Errorf("garbage: got %d, want XPubVersionUnknown", got)
	}
}

func TestNormalizeXPub(t *testing.T) {
	w, err := FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	xpub, err := w.AccountXPub(BTC, 0)
	if err != nil {
		t.Fatalf("AccountXPub: %v", err)
	}

	// xpub normalizes to itself.
	norm, err := NormalizeXPub(xpub)
	if err != nil {
		t.Fatalf("NormalizeXPub(xpub): %v", err)
	}
	if norm != xpub {
		t.Errorf("xpub normalized to %q, want same", norm)
	}

	// Synthesize ypub and normalize back → same addresses as xpub wallet.
	body, _ := base58CheckDecode(base58BTC, xpub)
	copy(body[:4], ypubVer)
	ypub := base58CheckEncode(base58BTC, nil, body)

	normFromYpub, err := NormalizeXPub(ypub)
	if err != nil {
		t.Fatalf("NormalizeXPub(ypub): %v", err)
	}
	if normFromYpub != xpub {
		t.Errorf("NormalizeXPub(ypub) = %q, want %q", normFromYpub, xpub)
	}

	// The normalized xpub → WatchWallet derives same addresses as the seed wallet.
	ww, err := WatchOnlyFromXPub(normFromYpub, BTC)
	if err != nil {
		t.Fatalf("WatchOnlyFromXPub(normalizedYpub): %v", err)
	}
	want0, _ := w.Address(BTC)
	got0, err := ww.Address(0, 0)
	if err != nil {
		t.Fatalf("ww.Address(0,0): %v", err)
	}
	if got0 != want0 {
		t.Errorf("address mismatch: got %s, want %s", got0, want0)
	}

	// Invalid input should error.
	if _, err := NormalizeXPub("garbage"); err == nil {
		t.Error("expected error for invalid input")
	}
	// Unknown prefix (looks like valid base58check but unsupported version).
	body2, _ := base58CheckDecode(base58BTC, xpub)
	body2[0], body2[1], body2[2], body2[3] = 0xDE, 0xAD, 0xBE, 0xEF
	weirdKey := base58CheckEncode(base58BTC, nil, body2)
	if _, err := NormalizeXPub(weirdKey); err == nil || !strings.Contains(err.Error(), "unrecognized") {
		t.Errorf("expected 'unrecognized' error for unknown prefix, got %v", err)
	}
}

func TestAccountEd25519PubKey(t *testing.T) {
	w, err := FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, chain, err := w.AccountEd25519PubKey(SOL, 0)
	if err != nil {
		t.Fatalf("AccountEd25519PubKey: %v", err)
	}
	if len(pub) != 32 {
		t.Errorf("pubKey length: got %d, want 32", len(pub))
	}
	if len(chain) != 32 {
		t.Errorf("chainCode length: got %d, want 32", len(chain))
	}

	// Deterministic: second call gives same result.
	pub2, chain2, err := w.AccountEd25519PubKey(SOL, 0)
	if err != nil {
		t.Fatalf("AccountEd25519PubKey (2nd): %v", err)
	}
	if !bytesEqual(pub, pub2) || !bytesEqual(chain, chain2) {
		t.Error("AccountEd25519PubKey not deterministic")
	}

	// Account 1 produces a different key.
	pub1, _, _ := w.AccountEd25519PubKey(SOL, 1)
	if bytesEqual(pub, pub1) {
		t.Error("account 0 and 1 produced the same key")
	}

	// Secp256k1 coin should be rejected.
	if _, _, err := w.AccountEd25519PubKey(BTC, 0); err == nil {
		t.Error("expected error for secp256k1 coin")
	}

	// Key-only wallet should be rejected.
	kw, _ := FromPrivateKeyBytes(mustHex(t, wifTestKeyHex), Secp256k1)
	defer kw.Destroy()
	if _, _, err := kw.AccountEd25519PubKey(SOL, 0); !errors.Is(err, ErrKeyOnlyWallet) {
		t.Errorf("key-only: expected ErrKeyOnlyWallet, got %v", err)
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
