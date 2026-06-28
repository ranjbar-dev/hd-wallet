package hdwallet

import (
	"crypto/aes"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/scrypt"
)

// BIP-38 encrypted private key export (non-EC-multiply mode only).
//
// BIP-38 encrypts a secp256k1 private key with a passphrase and encodes the
// result as a 58-character base58check string starting with "6P". The address
// hash (SHA256d of the Bitcoin P2PKH address) is used as the scrypt salt so a
// wrong passphrase produces the wrong key and the mismatch is detectable.
//
// Spec: https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki

const (
	bip38Magic1         byte = 0x01
	bip38Magic2         byte = 0x42
	bip38FlagNoEC       byte = 0xC0 // top two bits always set for non-EC-multiply
	bip38FlagCompressed byte = 0x20 // bit 5: use compressed public key
)

// EncryptWIF encrypts the private key for symbol at index using BIP-38
// non-EC-multiply mode and returns the '6P…' base58check-encoded ciphertext.
// symbol must be a secp256k1 coin. The address hash is computed from the
// Bitcoin P2PKH representation of the key (BIP-38 is inherently Bitcoin-format).
func (w *HDWallet) EncryptWIF(symbol Symbol, index uint32, passphrase []byte) (string, error) {
	var result string
	err := w.withLeafPrivateKey(symbol, index, func(priv []byte, coin Coin) error {
		if coin.Curve != Secp256k1 {
			return fmt.Errorf("%w: BIP-38 requires secp256k1; %s uses %s", ErrInvalidWIF, symbol, coin.Curve)
		}
		enc, encErr := bip38Encrypt(priv, passphrase)
		if encErr != nil {
			return encErr
		}
		result = enc
		return nil
	})
	return result, err
}

// DecryptWIF decrypts a BIP-38 '6P…' encrypted key with passphrase.
// fn receives the WIF-encoded private key bytes; the slice is wiped before
// DecryptWIF returns. Returns ErrInvalidWIF if the passphrase is wrong.
func DecryptWIF(encrypted string, passphrase []byte, fn func(wif []byte)) error {
	return bip38Decrypt(encrypted, passphrase, fn)
}

// bip38Encrypt implements BIP-38 non-EC-multiply encryption of a 32-byte
// secp256k1 private key using the compressed public key form.
func bip38Encrypt(priv, passphrase []byte) (string, error) {
	// Compute compressed Bitcoin P2PKH address for the address hash.
	_, pub := btcec.PrivKeyFromBytes(priv)
	addr := base58CheckEncode(base58BTC, []byte{0x00}, hash160(pub.SerializeCompressed()))

	addresshash := sha256d([]byte(addr))[:4]

	derived, err := scrypt.Key(passphrase, addresshash, 16384, 8, 8, 64) //nolint:gomnd
	if err != nil {
		return "", fmt.Errorf("hdwallet: BIP-38 scrypt: %w", err)
	}
	defer wipe(derived)

	derivedhalf1 := derived[:32]
	derivedhalf2 := derived[32:]

	block, err := aes.NewCipher(derivedhalf2)
	if err != nil {
		return "", fmt.Errorf("hdwallet: BIP-38 AES: %w", err)
	}

	plain1 := xorBytes(priv[:16], derivedhalf1[:16])
	enc1 := make([]byte, 16)
	block.Encrypt(enc1, plain1)
	wipe(plain1)

	plain2 := xorBytes(priv[16:], derivedhalf1[16:32])
	enc2 := make([]byte, 16)
	block.Encrypt(enc2, plain2)
	wipe(plain2)

	payload := make([]byte, 0, 39)
	payload = append(payload, bip38Magic1, bip38Magic2)
	payload = append(payload, bip38FlagNoEC|bip38FlagCompressed)
	payload = append(payload, addresshash...)
	payload = append(payload, enc1...)
	payload = append(payload, enc2...)

	return base58CheckEncode(base58BTC, nil, payload), nil
}

// bip38Decrypt reverses bip38Encrypt. It also handles uncompressed keys
// (flagbyte without bip38FlagCompressed) to accept all BIP-38 test vectors.
func bip38Decrypt(encrypted string, passphrase []byte, fn func(wif []byte)) error {
	body, err := base58CheckDecode(base58BTC, strings.TrimSpace(encrypted))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidWIF, err)
	}
	// body = 0x01 0x42 flagbyte[1] addresshash[4] enc1[16] enc2[16] = 39 bytes
	if len(body) != 39 || body[0] != bip38Magic1 || body[1] != bip38Magic2 {
		return fmt.Errorf("%w: not a BIP-38 encrypted key", ErrInvalidWIF)
	}
	flagbyte := body[2]
	compressed := (flagbyte & bip38FlagCompressed) != 0
	addresshash := body[3:7]
	enc1 := body[7:23]
	enc2 := body[23:39]

	derived, err := scrypt.Key(passphrase, addresshash, 16384, 8, 8, 64) //nolint:gomnd
	if err != nil {
		return fmt.Errorf("hdwallet: BIP-38 scrypt: %w", err)
	}
	defer wipe(derived)

	block, err := aes.NewCipher(derived[32:])
	if err != nil {
		return fmt.Errorf("hdwallet: BIP-38 AES: %w", err)
	}

	dec1 := make([]byte, 16)
	block.Decrypt(dec1, enc1)
	dec2 := make([]byte, 16)
	block.Decrypt(dec2, enc2)

	priv := make([]byte, 32)
	copy(priv[:16], xorBytes(dec1, derived[:16]))
	copy(priv[16:], xorBytes(dec2, derived[16:32]))
	defer wipe(priv)
	wipe(dec1)
	wipe(dec2)

	// Verify address hash to confirm the passphrase is correct.
	_, pub := btcec.PrivKeyFromBytes(priv)
	var pubBytes []byte
	if compressed {
		pubBytes = pub.SerializeCompressed()
	} else {
		pubBytes = pub.SerializeUncompressed()
	}
	gotAddr := base58CheckEncode(base58BTC, []byte{0x00}, hash160(pubBytes))
	if !bytesEqual(sha256d([]byte(gotAddr))[:4], addresshash) {
		return fmt.Errorf("%w: wrong passphrase (address hash mismatch)", ErrInvalidWIF)
	}

	var wifBytes []byte
	if compressed {
		wifBytes = encodeWIFCompressed(priv)
	} else {
		payload := make([]byte, 32)
		copy(payload, priv)
		defer wipe(payload)
		wifBytes = []byte(base58CheckEncode(base58BTC, []byte{wifMainnetVersion}, payload))
	}
	defer wipe(wifBytes)
	fn(wifBytes)
	return nil
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}
