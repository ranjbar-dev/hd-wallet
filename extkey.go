package hdwallet

import (
	"crypto/ed25519"
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

// AccountXPub returns the BIP-32 extended PUBLIC key (xpub) for chain's account
// at the given index — i.e. the neutered key at m/purpose'/coin'/account'. It is
// public and safe to share; feed it to WatchOnlyFromXPub to derive addresses
// without the seed. chain must be a secp256k1 coin.
func (w *HDWallet) AccountXPub(chain Chain, account uint32) (string, error) {
	var xpub string
	err := w.withAccountExtKey(chain, account, func(k *hdkeychain.ExtendedKey) error {
		neutered, err := k.Neuter()
		if err != nil {
			return fmt.Errorf("hdwallet: %s: %w", chain, err)
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
// chain's account, then wipes the byte slice (mirrors WithPrivateKey/WithWIF).
// The xprv is a full secret — anyone holding it can derive every key under the
// account. The slice passed to fn must not escape fn. chain must be secp256k1.
func (w *HDWallet) WithAccountXPrv(chain Chain, account uint32, fn func(xprv []byte) error) error {
	return w.withAccountExtKey(chain, account, func(k *hdkeychain.ExtendedKey) error {
		// k.String() yields a Go string (sensitive, GC-bounded, cannot be wiped);
		// the byte copy handed to fn is wiped on return.
		b := []byte(k.String())
		defer wipe(b)
		return fn(b)
	})
}

// withAccountExtKey derives the account-level extended key (private) for chain,
// hands it to fn, and zeroes it — and every intermediate — before returning. It
// is seed-only (a key-only wallet has no HD tree) and secp256k1-only.
func (w *HDWallet) withAccountExtKey(chain Chain, account uint32, fn func(*hdkeychain.ExtendedKey) error) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return ErrDestroyed
	}
	if w.secret.isKeyOnly() {
		return fmt.Errorf("%w: extended keys", ErrKeyOnlyWallet)
	}
	coin, ok := coins[chain]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedCoin, chain)
	}
	if coin.Curve != Secp256k1 {
		return fmt.Errorf("%w: %s is %s", ErrExtKeyUnsupportedCurve, chain, coin.Curve)
	}
	apath, err := accountPathIndices(coin.Path, account)
	if err != nil {
		return fmt.Errorf("hdwallet: %s: %w", chain, err)
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

// WatchOnlyFromXPub builds a watch-only wallet for chain from an account-level
// extended key string. Both xpub and xprv strings are accepted; an xprv is
// immediately neutered so the WatchWallet never holds private material. chain
// must be a secp256k1 coin whose address format matches the xpub's chain.
func WatchOnlyFromXPub(xpub string, chain Chain) (*WatchWallet, error) {
	coin, ok := coins[chain]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCoin, chain)
	}
	if coin.Curve != Secp256k1 {
		return nil, fmt.Errorf("%w: %s is %s", ErrExtKeyUnsupportedCurve, chain, coin.Curve)
	}
	key, err := hdkeychain.NewKeyFromString(strings.TrimSpace(xpub))
	if err != nil {
		return nil, fmt.Errorf("hdwallet: %s: invalid extended key: %w", chain, err)
	}
	if key.IsPrivate() {
		neutered, nerr := key.Neuter()
		if nerr != nil {
			return nil, fmt.Errorf("hdwallet: %s: %w", chain, nerr)
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

// ---------------------------------------------------------------------------
// xpub format detection and normalization
// ---------------------------------------------------------------------------

// XPubVersion describes the address type implied by an extended public key prefix.
type XPubVersion int

// XPubVersionUnknown is the zero value returned when the extended-key prefix
// is not recognised as any of the known BIP-32 version bytes.
const (
	XPubVersionUnknown    XPubVersion = iota // prefix did not match a known xpub version
	XPubVersionLegacy                        // xpub/tpub — BIP-44 P2PKH
	XPubVersionP2SHP2WPKH                    // ypub/upub — BIP-49 P2SH-P2WPKH
	XPubVersionP2WPKH                        // zpub/vpub — BIP-84 native SegWit
)

// version byte arrays for BIP-32 extended key prefixes (mainnet + testnet)
var (
	xpubVer = []byte{0x04, 0x88, 0xB2, 0x1E} // xpub
	ypubVer = []byte{0x04, 0x9D, 0x7C, 0xB2} // ypub
	zpubVer = []byte{0x04, 0xB2, 0x47, 0x46} // zpub
	tpubVer = []byte{0x04, 0x35, 0x87, 0xCF} // tpub (testnet xpub)
	upubVer = []byte{0x04, 0x4A, 0x52, 0x62} // upub (testnet ypub)
	vpubVer = []byte{0x04, 0x5F, 0x1C, 0xF6} // vpub (testnet zpub)
)

// DetectXPubVersion returns the address type implied by the extended key prefix.
// Returns XPubVersionUnknown for unrecognized or malformed inputs.
func DetectXPubVersion(extKey string) XPubVersion {
	body, err := base58CheckDecode(base58BTC, strings.TrimSpace(extKey))
	if err != nil || len(body) < 4 {
		return XPubVersionUnknown
	}
	v := body[:4]
	switch {
	case bytesEqual(v, xpubVer) || bytesEqual(v, tpubVer):
		return XPubVersionLegacy
	case bytesEqual(v, ypubVer) || bytesEqual(v, upubVer):
		return XPubVersionP2SHP2WPKH
	case bytesEqual(v, zpubVer) || bytesEqual(v, vpubVer):
		return XPubVersionP2WPKH
	default:
		return XPubVersionUnknown
	}
}

// NormalizeXPub converts a ypub/zpub (or their testnet equivalents) to standard
// xpub format so it can be passed to WatchOnlyFromXPub. xpub/tpub inputs are
// returned unchanged. Returns an error for unrecognized prefixes.
func NormalizeXPub(extKey string) (string, error) {
	trimmed := strings.TrimSpace(extKey)
	body, err := base58CheckDecode(base58BTC, trimmed)
	if err != nil {
		return "", fmt.Errorf("hdwallet: invalid extended key: %w", err)
	}
	if len(body) < 4 {
		return "", fmt.Errorf("hdwallet: extended key too short")
	}
	v := body[:4]
	switch {
	case bytesEqual(v, xpubVer) || bytesEqual(v, tpubVer):
		return trimmed, nil
	case bytesEqual(v, ypubVer), bytesEqual(v, upubVer),
		bytesEqual(v, zpubVer), bytesEqual(v, vpubVer):
		// Replace version bytes with xpub and re-encode.
		copy(body[:4], xpubVer)
		return base58CheckEncode(base58BTC, nil, body), nil
	default:
		return "", fmt.Errorf("hdwallet: unrecognized extended key prefix")
	}
}

// ---------------------------------------------------------------------------
// Ed25519 account-level public key export
// ---------------------------------------------------------------------------

// AccountEd25519PubKey returns the SLIP-0010 ed25519 public key (32 bytes) and
// chain code (32 bytes) at the account level (m/purpose'/coin'/account') for
// chain.
//
// SLIP-0010 ed25519 does not support public child key derivation — all path
// elements must be hardened and no WatchWallet equivalent exists. This method
// exports the account-level public key for external signing or identity use;
// child address derivation still requires the full seed. chain must be an
// Ed25519 coin.
func (w *HDWallet) AccountEd25519PubKey(chain Chain, account uint32) (pubKey, chainCode []byte, err error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.secret == nil {
		return nil, nil, ErrDestroyed
	}
	if w.secret.isKeyOnly() {
		return nil, nil, fmt.Errorf("%w: AccountEd25519PubKey", ErrKeyOnlyWallet)
	}
	coin, ok := coins[chain]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedCoin, chain)
	}
	if coin.Curve != Ed25519 {
		return nil, nil, fmt.Errorf("hdwallet: AccountEd25519PubKey requires an Ed25519 coin; %s uses %s", chain, coin.Curve)
	}
	apath, apErr := accountPathIndices(coin.Path, account)
	if apErr != nil {
		return nil, nil, fmt.Errorf("hdwallet: %s: %w", chain, apErr)
	}
	err = w.secret.withSeed(func(seed []byte) error {
		node, derErr := deriveEd25519(seed, apath)
		if derErr != nil {
			return derErr
		}
		priv := ed25519.NewKeyFromSeed(node.key)
		pubKey = make([]byte, ed25519.PublicKeySize)
		copy(pubKey, priv[ed25519.SeedSize:])
		wipe(priv)
		chainCode = make([]byte, 32)
		copy(chainCode, node.chain)
		wipe(node.key)
		wipe(node.chain)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return pubKey, chainCode, nil
}
