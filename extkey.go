package hdwallet

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// BIP-32 extended keys (xprv/xpub) and watch-only public derivation.
//
// These are secp256k1-only: BIP-32 public (non-hardened) child derivation — the
// basis of an xpub — is defined for secp256k1, whereas the SLIP-0010 ed25519 and
// nist256p1 schemes this library uses for the other curves support hardened
// derivation only. Non-secp256k1 coins return ErrExtKeyUnsupportedCurve.
//
// An account-level xpub (m/purpose'/coin'/account') lets a server derive every
// receive/change address for that account WITHOUT the seed (watch-only), while
// the matching xprv is a full secret export and follows the same wiped-callback
// discipline as the mnemonic and raw private key.

// AccountXPub returns the BIP-32 extended PUBLIC key (xpub) for symbol's account
// at the given index — i.e. the neutered key at m/purpose'/coin'/account'. It is
// public and safe to share; feed it to WatchOnlyFromXPub to derive addresses
// without the seed. symbol must be a secp256k1 coin.
func (w *HDWallet) AccountXPub(symbol Symbol, account uint32) (string, error) {
	var xpub string
	err := w.withAccountExtKey(symbol, account, func(k *hdkeychain.ExtendedKey) error {
		neutered, err := k.Neuter()
		if err != nil {
			return fmt.Errorf("hdwallet: %s: %w", symbol, err)
		}
		xpub = neutered.String()
		return nil
	})
	if err != nil {
		return "", err
	}
	return xpub, nil
}

// WithAccountXPrv runs fn with the BIP-32 extended PRIVATE key (xprv) string for
// symbol's account, then wipes the byte slice (mirrors WithPrivateKey/WithWIF).
// The xprv is a full secret — anyone holding it can derive every key under the
// account. The slice passed to fn must not escape fn. symbol must be secp256k1.
func (w *HDWallet) WithAccountXPrv(symbol Symbol, account uint32, fn func(xprv []byte) error) error {
	return w.withAccountExtKey(symbol, account, func(k *hdkeychain.ExtendedKey) error {
		// k.String() yields a Go string (sensitive, GC-bounded, cannot be wiped);
		// the byte copy handed to fn is wiped on return.
		b := []byte(k.String())
		defer wipe(b)
		return fn(b)
	})
}

// withAccountExtKey derives the account-level extended key (private) for symbol,
// hands it to fn, and zeroes it — and every intermediate — before returning. It
// is seed-only (a key-only wallet has no HD tree) and secp256k1-only.
func (w *HDWallet) withAccountExtKey(symbol Symbol, account uint32, fn func(*hdkeychain.ExtendedKey) error) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return ErrDestroyed
	}
	if w.secret.isKeyOnly() {
		return fmt.Errorf("%w: extended keys", ErrKeyOnlyWallet)
	}
	coin, ok := coins[symbol]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	if coin.Curve != Secp256k1 {
		return fmt.Errorf("%w: %s is %s", ErrExtKeyUnsupportedCurve, symbol, coin.Curve)
	}
	apath, err := accountPathIndices(coin.Path, account)
	if err != nil {
		return fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	return w.secret.withSeed(func(seed []byte) error {
		key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
		if err != nil {
			return err
		}
		for _, idx := range apath {
			child, derr := key.Derive(idx)
			if derr != nil {
				key.Zero()
				return derr
			}
			key.Zero() // wipe the parent before descending
			key = child
		}
		defer key.Zero()
		return fn(key)
	})
}

// accountPathIndices builds the child-index slice for m/purpose'/coin'/account'
// from a coin's path template, applying the hardened offset to account. It
// reuses parsePath for validation.
func accountPathIndices(template string, account uint32) ([]uint32, error) {
	parts := strings.Split(template, "/")
	if len(parts) < 4 || parts[0] != "m" {
		return nil, fmt.Errorf("%w: %s", ErrPathArity, template)
	}
	if account >= hardenedOffset {
		return nil, fmt.Errorf("account index out of range: %d (must be < %d)", account, hardenedOffset)
	}
	acctPath := "m/" + parts[1] + "/" + parts[2] + "/" + strconv.FormatUint(uint64(account), 10) + "'"
	return parsePath(acctPath)
}

// WatchWallet derives receive/change addresses for a single account from its
// extended PUBLIC key (xpub) — no seed, no private keys, no signing. It is the
// watch-only counterpart of HDWallet for secp256k1 coins.
type WatchWallet struct {
	acct *hdkeychain.ExtendedKey // account-level public key (m/purpose'/coin'/account')
	coin Coin
}

// WatchOnlyFromXPub builds a watch-only wallet for symbol from an account-level
// extended key string. Both xpub and xprv strings are accepted; an xprv is
// immediately neutered so the WatchWallet never holds private material. symbol
// must be a secp256k1 coin whose address format matches the xpub's chain.
func WatchOnlyFromXPub(xpub string, symbol Symbol) (*WatchWallet, error) {
	coin, ok := coins[symbol]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	if coin.Curve != Secp256k1 {
		return nil, fmt.Errorf("%w: %s is %s", ErrExtKeyUnsupportedCurve, symbol, coin.Curve)
	}
	key, err := hdkeychain.NewKeyFromString(strings.TrimSpace(xpub))
	if err != nil {
		return nil, fmt.Errorf("hdwallet: %s: invalid extended key: %w", symbol, err)
	}
	if key.IsPrivate() {
		neutered, nerr := key.Neuter()
		if nerr != nil {
			return nil, fmt.Errorf("hdwallet: %s: %w", symbol, nerr)
		}
		key.Zero()
		key = neutered
	}
	return &WatchWallet{acct: key, coin: coin}, nil
}

// Address returns the address at the account's change/index branch (e.g.
// change=0, index=5 -> .../0/5). Both must be non-hardened (< 2^31); public
// derivation cannot produce hardened children.
func (ww *WatchWallet) Address(change, index uint32) (string, error) {
	pub, err := ww.publicKey(change, index)
	if err != nil {
		return "", err
	}
	return ww.coin.Encode(pub)
}

// PublicKey returns the 33-byte compressed public key at the change/index branch.
func (ww *WatchWallet) PublicKey(change, index uint32) ([]byte, error) {
	return ww.publicKey(change, index)
}

func (ww *WatchWallet) publicKey(change, index uint32) ([]byte, error) {
	if change >= hardenedOffset || index >= hardenedOffset {
		return nil, fmt.Errorf("%w: watch-only change/index must be non-hardened (< %d)", ErrExtKeyUnsupportedCurve, hardenedOffset)
	}
	branch, err := ww.acct.Derive(change)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: watch-only derive change %d: %w", change, err)
	}
	leaf, err := branch.Derive(index)
	if err != nil {
		return nil, fmt.Errorf("hdwallet: watch-only derive index %d: %w", index, err)
	}
	pubKey, err := leaf.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("hdwallet: watch-only pubkey: %w", err)
	}
	return pubKey.SerializeCompressed(), nil
}
