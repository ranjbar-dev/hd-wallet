package hdwallet

import (
	"errors"
	"fmt"

	"github.com/awnumar/memguard"
)

// Bitcoin Wallet Import Format (WIF) for secp256k1 private keys.
//
// A mainnet WIF is base58check(0x80 || key[32] [|| 0x01]) where the trailing
// 0x01 marks a key whose address uses the compressed public key. This library
// always derives compressed addresses, so export produces the compressed form;
// import accepts both. WIF is a Bitcoin concept (version byte 0x80); per-coin
// version bytes (e.g. Litecoin 0xB0) are out of scope.

const (
	wifMainnetVersion byte = 0x80 // Bitcoin mainnet private-key WIF version
	wifCompressedFlag byte = 0x01 // marks a compressed-pubkey key
)

// ErrInvalidWIF is returned for a malformed WIF string or a WIF export requested
// for a non-secp256k1 coin.
var ErrInvalidWIF = errors.New("hdwallet: invalid WIF private key")

// FromWIF builds a key-only secp256k1 wallet from a Bitcoin WIF private key held
// in a byte slice. The slice is wiped before returning; callers must not reuse
// it. Both compressed and uncompressed mainnet (0x80) WIF are accepted, and the
// imported key may then be used with any secp256k1 coin.
//
// Like the mnemonic path, the WIF is briefly converted to a Go string internally
// for base58 decoding (it cannot be wiped and is GC-bounded).
func FromWIF(wif []byte) (*HDWallet, error) {
	defer wipe(wif)
	key, err := decodeWIF(wif)
	if err != nil {
		return nil, err
	}
	// FromPrivateKeyBytes takes ownership of key and wipes it.
	return FromPrivateKeyBytes(key, Secp256k1)
}

// decodeWIF validates a mainnet WIF and returns its raw 32-byte private key.
func decodeWIF(wif []byte) ([]byte, error) {
	body, err := base58CheckDecode(base58BTC, string(wif))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidWIF, err)
	}
	defer wipe(body)
	if len(body) != 33 && len(body) != 34 {
		return nil, fmt.Errorf("%w: unexpected decoded length %d", ErrInvalidWIF, len(body))
	}
	if body[0] != wifMainnetVersion {
		return nil, fmt.Errorf("%w: version 0x%02x (want 0x80 mainnet)", ErrInvalidWIF, body[0])
	}
	if len(body) == 34 && body[33] != wifCompressedFlag {
		return nil, fmt.Errorf("%w: bad compression flag 0x%02x", ErrInvalidWIF, body[33])
	}
	key := make([]byte, 32)
	copy(key, body[1:33])
	return key, nil
}

// WithWIF runs fn with the leaf private key for chain at the given address index
// encoded as a Bitcoin mainnet compressed WIF, then wipes the WIF bytes (mirrors
// WithPrivateKey). chain must be a secp256k1 coin. The slice passed to fn must
// not escape fn.
func (w *HDWallet) WithWIF(chain Chain, index uint32, fn func(wif []byte) error) error {
	return w.withLeafPrivateKey(chain, index, func(priv []byte, coin Coin) error {
		if coin.Curve != Secp256k1 {
			return fmt.Errorf("%w: %s is not a secp256k1 coin", ErrInvalidWIF, chain)
		}
		wif := encodeWIFCompressed(priv)
		defer wipe(wif)
		return fn(wif)
	})
}

// WIF returns the leaf key for chain at the given address index as a Bitcoin
// mainnet compressed WIF in a page-locked memguard buffer; the caller MUST
// Destroy it. Prefer WithWIF, which wipes automatically.
func (w *HDWallet) WIF(chain Chain, index uint32) (*memguard.LockedBuffer, error) {
	var out *memguard.LockedBuffer
	err := w.WithWIF(chain, index, func(wif []byte) error {
		buf := memguard.NewBuffer(len(wif))
		buf.Copy(wif)
		out = buf
		return nil
	})
	if err != nil {
		if out != nil {
			out.Destroy()
		}
		return nil, err
	}
	return out, nil
}

// encodeWIFCompressed returns the Bitcoin mainnet compressed WIF for a 32-byte
// secp256k1 private key.
func encodeWIFCompressed(key []byte) []byte {
	payload := make([]byte, 0, 33)
	payload = append(payload, key...)
	payload = append(payload, wifCompressedFlag)
	defer wipe(payload)
	return []byte(base58CheckEncode(base58BTC, []byte{wifMainnetVersion}, payload))
}
