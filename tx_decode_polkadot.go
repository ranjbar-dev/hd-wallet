package hdwallet

// "What am I signing?" decoder for Polkadot (DOT) SCALE-encoded signed v4
// extrinsics.
//
// DecodePolkadotTx parses the wire format tx_polkadot.go's signPolkadotTx
// produces (see its header comment) back into typed, display-ready fields —
// WITHOUT touching a private key or any secret. It is the inverse of
// signPolkadotTx/dotBuildCall.
//
// Known ambiguity — signer/dest encoding: the sender/destination account can
// be encoded either as a raw 32-byte AccountId (pre-MultiAddress runtimes,
// e.g. the SignTransfer_9fd062 vector) or as MultiAddress::Id (a 0x00
// discriminant ‖ the 32-byte AccountId; every runtime since spec 28 and Asset
// Hub) — and a raw AccountId can itself start with the byte 0x00, so the two
// encodings cannot always be told apart from the signer bytes alone. The
// signer (dotEncodeAccount) always applies the same encoding to both signer
// and dest, so the decoder only tries the two *consistent* combinations: it
// attempts MultiAddress first, then raw AccountId, and accepts an
// interpretation only if the entire declared extrinsic body parses with zero
// trailing bytes (valid 0x84 version byte, valid MultiSignature discriminant,
// a recognised call shape that exactly consumes the remaining bytes). If both
// interpretations happen to parse cleanly, MultiAddress is preferred (every
// current Polkadot/Asset Hub runtime uses it); MultiAddress is reported in
// PolkadotTxFields so a caller can see which was detected.
//
// Only the two call shapes this library signs are recognised —
// Balances-pallet-style (dest ‖ compact(value)) and Assets-pallet-style
// (compact(asset_id) ‖ dest ‖ compact(value)), matched by the pallet index
// (dotBalancesPallet/dotAssetsPallet) regardless of the call/method index
// override. Staking/batch/XCM and other calls are out of scope (see
// CLAUDE.md) and return ErrTxDecode, since their shape can't be validated
// without a bespoke decoder for each and an unvalidated shape would break the
// zero-trailing-bytes check the signer-encoding disambiguation depends on.
//
// Every read is bounds-checked: malformed or truncated input returns
// ErrTxDecode and the decoder never panics.

import (
	"fmt"
	"math/big"
)

// PolkadotTxFields holds the decoded, display-ready fields of a signed
// Polkadot v4 extrinsic.
type PolkadotTxFields struct {
	SignerPubKey    []byte // 32-byte public key
	SignerAddress   string // SS58, rendered with the caller-supplied network prefix
	MultiAddress    bool   // encoding detected for signer/dest: MultiAddress::Id (true) vs raw AccountId (false)
	SignatureScheme string // "ed25519" | "sr25519" | "ecdsa" (from the MultiSignature discriminant)
	Signature       []byte

	Immortal bool
	Period   uint64 // quantized mortal-era period; 0 when Immortal
	Phase    uint64 // quantized mortal-era phase; 0 when Immortal

	Nonce uint64
	Tip   *big.Int

	ModuleIndex byte
	MethodIndex byte

	ToAddress string // SS58 of the transfer destination
	Value     *big.Int
	AssetID   *uint32 // non-nil only for an Assets-pallet-shaped call
}

// dotDecodeCursor is a bounds-checked forward reader over extrinsic bytes,
// matching the style of the other tx_decode_*.go cursors.
type dotDecodeCursor struct {
	b   []byte
	pos int
}

func (c *dotDecodeCursor) remaining() int { return len(c.b) - c.pos }

func (c *dotDecodeCursor) readByte() (byte, error) {
	if c.remaining() < 1 {
		return 0, fmt.Errorf("%w: dot: truncated (want 1 byte)", ErrTxDecode)
	}
	v := c.b[c.pos]
	c.pos++
	return v, nil
}

func (c *dotDecodeCursor) readBytes(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, fmt.Errorf("%w: dot: truncated (want %d bytes, have %d)", ErrTxDecode, n, c.remaining())
	}
	out := c.b[c.pos : c.pos+n]
	c.pos += n
	return out, nil
}

// readCompact decodes a SCALE compact-encoded non-negative integer — the
// inverse of scaleCompact (tx_polkadot.go).
func (c *dotDecodeCursor) readCompact() (*big.Int, error) {
	b0, err := c.readByte()
	if err != nil {
		return nil, err
	}
	switch b0 & 0b11 {
	case 0b00:
		return big.NewInt(int64(b0 >> 2)), nil
	case 0b01:
		b1, err := c.readByte()
		if err != nil {
			return nil, err
		}
		v := (uint16(b1)<<8 | uint16(b0)) >> 2
		return big.NewInt(int64(v)), nil
	case 0b10:
		rest, err := c.readBytes(3)
		if err != nil {
			return nil, err
		}
		v := (uint32(rest[2])<<24 | uint32(rest[1])<<16 | uint32(rest[0])<<8 | uint32(b0)) >> 2
		return big.NewInt(int64(v)), nil
	default: // 0b11: big-integer mode — header's top 6 bits hold (len-4)
		length := int(b0>>2) + 4
		le, err := c.readBytes(length)
		if err != nil {
			return nil, err
		}
		be := make([]byte, length)
		for i, bb := range le {
			be[length-1-i] = bb
		}
		return new(big.Int).SetBytes(be), nil
	}
}

// readEra decodes extrinsic mortality — the inverse of dotEncodeEra. A
// mortal era only recovers the quantized phase (the encoding is lossy by
// design), not the exact original block number.
func (c *dotDecodeCursor) readEra() (immortal bool, period, phase uint64, err error) {
	b0, err := c.readByte()
	if err != nil {
		return false, 0, 0, err
	}
	if b0 == 0x00 {
		return true, 0, 0, nil
	}
	b1, err := c.readByte()
	if err != nil {
		return false, 0, 0, err
	}
	encoded := uint64(b0) | uint64(b1)<<8
	low := encoded & 0x0f
	period = uint64(1) << (low + 1)
	phase = encoded >> 4
	return false, period, phase, nil
}

// readAccount decodes a signer/dest account: MultiAddress::Id (0x00 ‖ 32
// bytes) when multiAddress is set, otherwise a raw 32-byte AccountId — the
// inverse of dotEncodeAccount.
func (c *dotDecodeCursor) readAccount(multiAddress bool) ([]byte, error) {
	if multiAddress {
		disc, err := c.readByte()
		if err != nil {
			return nil, err
		}
		if disc != 0x00 {
			return nil, fmt.Errorf("%w: dot: unsupported MultiAddress discriminant 0x%02x (only Id/0x00)", ErrTxDecode, disc)
		}
	}
	return c.readBytes(32)
}

// dotSigSchemeLen maps a MultiSignature discriminant to its scheme name and
// signature length.
func dotSigSchemeLen(discriminant byte) (length int, scheme string, err error) {
	switch discriminant {
	case 0x00:
		return 64, "ed25519", nil
	case 0x01:
		return 64, "sr25519", nil
	case 0x02:
		return 65, "ecdsa", nil
	default:
		return 0, "", fmt.Errorf("%w: dot: invalid MultiSignature discriminant 0x%02x", ErrTxDecode, discriminant)
	}
}

// dotCompactToUint64 bounds-checks a decoded compact integer into a uint64,
// used for fields (nonce, asset id) that are always small in practice.
func dotCompactToUint64(field string, v *big.Int) (uint64, error) {
	if !v.IsUint64() {
		return 0, fmt.Errorf("%w: dot: %s exceeds u64", ErrTxDecode, field)
	}
	return v.Uint64(), nil
}

// DecodePolkadotTx decodes a signed Polkadot v4 extrinsic (the Encoded bytes
// signPolkadotTx produces) into its display fields. network is the SS58
// address prefix used to render SignerAddress/ToAddress (0 for the Polkadot
// relay chain and Asset Hub) — display-only, not re-derived from the bytes,
// so the caller must know which network signed the extrinsic. Malformed,
// truncated, or unrecognised-call input returns ErrTxDecode; never panics.
func DecodePolkadotTx(raw []byte, network byte) (*PolkadotTxFields, error) {
	outer := &dotDecodeCursor{b: raw}
	bodyLen, err := outer.readCompact()
	if err != nil {
		return nil, err
	}
	if !bodyLen.IsUint64() || uint64(outer.remaining()) != bodyLen.Uint64() { // #nosec G115 -- remaining() is non-negative
		return nil, fmt.Errorf("%w: dot: declared length %s does not match remaining %d bytes", ErrTxDecode, bodyLen, outer.remaining())
	}
	body := raw[outer.pos:]

	// Try the two internally-consistent signer/dest encodings; prefer
	// MultiAddress when both happen to parse (see file header comment).
	if f, err := decodePolkadotBody(body, true, network); err == nil {
		return f, nil
	}
	if f, err := decodePolkadotBody(body, false, network); err == nil {
		return f, nil
	}
	return nil, fmt.Errorf("%w: dot: extrinsic does not parse under either signer encoding", ErrTxDecode)
}

// decodePolkadotBody decodes the extrinsic body (everything after the outer
// compact length) under one fixed signer/dest encoding.
func decodePolkadotBody(body []byte, multiAddress bool, network byte) (*PolkadotTxFields, error) {
	c := &dotDecodeCursor{b: body}

	version, err := c.readByte()
	if err != nil {
		return nil, err
	}
	if version != 0x84 {
		return nil, fmt.Errorf("%w: dot: unsupported extrinsic version byte 0x%02x (want 0x84)", ErrTxDecode, version)
	}

	signerPub, err := c.readAccount(multiAddress)
	if err != nil {
		return nil, err
	}

	sigDiscriminant, err := c.readByte()
	if err != nil {
		return nil, err
	}
	sigLen, scheme, err := dotSigSchemeLen(sigDiscriminant)
	if err != nil {
		return nil, err
	}
	sig, err := c.readBytes(sigLen)
	if err != nil {
		return nil, err
	}

	immortal, period, phase, err := c.readEra()
	if err != nil {
		return nil, err
	}

	nonceCompact, err := c.readCompact()
	if err != nil {
		return nil, err
	}
	nonce, err := dotCompactToUint64("nonce", nonceCompact)
	if err != nil {
		return nil, err
	}

	tip, err := c.readCompact()
	if err != nil {
		return nil, err
	}

	moduleIdx, err := c.readByte()
	if err != nil {
		return nil, err
	}
	methodIdx, err := c.readByte()
	if err != nil {
		return nil, err
	}

	var assetID *uint32
	switch moduleIdx {
	case dotBalancesPallet:
		// Balances-pallet shape: dest ‖ compact(value) — no extra call arg.
	case dotAssetsPallet:
		idCompact, err := c.readCompact()
		if err != nil {
			return nil, err
		}
		id64, err := dotCompactToUint64("asset_id", idCompact)
		if err != nil {
			return nil, err
		}
		if id64 > 0xffffffff {
			return nil, fmt.Errorf("%w: dot: asset_id exceeds u32", ErrTxDecode)
		}
		id32 := uint32(id64) // #nosec G115 -- bounds-checked above
		assetID = &id32
	default:
		return nil, fmt.Errorf("%w: dot: unrecognised pallet index %d (only Balances=%d/Assets=%d transfer-shaped calls decode)",
			ErrTxDecode, moduleIdx, dotBalancesPallet, dotAssetsPallet)
	}

	destPub, err := c.readAccount(multiAddress)
	if err != nil {
		return nil, err
	}
	value, err := c.readCompact()
	if err != nil {
		return nil, err
	}

	if c.remaining() != 0 {
		return nil, fmt.Errorf("%w: dot: %d trailing bytes after call", ErrTxDecode, c.remaining())
	}

	signerAddr, err := ss58Encoder(network)(signerPub)
	if err != nil {
		return nil, fmt.Errorf("%w: dot: signer ss58 encode: %v", ErrTxDecode, err)
	}
	destAddr, err := ss58Encoder(network)(destPub)
	if err != nil {
		return nil, fmt.Errorf("%w: dot: dest ss58 encode: %v", ErrTxDecode, err)
	}

	return &PolkadotTxFields{
		SignerPubKey:    append([]byte(nil), signerPub...),
		SignerAddress:   signerAddr,
		MultiAddress:    multiAddress,
		SignatureScheme: scheme,
		Signature:       append([]byte(nil), sig...),
		Immortal:        immortal,
		Period:          period,
		Phase:           phase,
		Nonce:           nonce,
		Tip:             tip,
		ModuleIndex:     moduleIdx,
		MethodIndex:     methodIdx,
		ToAddress:       destAddr,
		Value:           value,
		AssetID:         assetID,
	}, nil
}
