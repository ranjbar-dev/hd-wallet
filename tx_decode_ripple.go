package hdwallet

// "What am I signing?" decoder for XRP Ledger (Ripple) Payment transactions.
//
// DecodeRippleTx parses a canonical XRP binary blob (the SigningOutput.Encoded
// the tx_ripple.go signer produces) back into its plain fields so a client can
// render a confirmation screen WITHOUT touching a private key or any secret. It is
// the inverse of xrpSerialize: each field is a type/field header followed by its
// value, fields ordered by (type_code, field_code).
//
// Field set for a native Payment:
//
//	TransactionType (UInt16    1.2)
//	Flags           (UInt32    2.2)
//	Sequence        (UInt32    2.4)
//	DestinationTag  (UInt32    2.14) — optional
//	LastLedgerSeq   (UInt32    2.27) — optional
//	Amount          (Amount    6.1)  drops, native
//	Fee             (Amount    6.8)  drops, native
//	SigningPubKey   (Blob      7.3)
//	TxnSignature    (Blob      7.4)
//	Account         (AccountID 8.1)
//	Destination     (AccountID 8.3)
//
// It reuses base58CheckEncode (codec.go) to render the 20-byte account ids back to
// their "r..." addresses (the reverse of encodeXRP). This file adds no
// signer/registry/proto changes; it is display-only. Every read is bounds-checked:
// malformed/truncated input returns ErrTxDecode and the decoder never panics.

import (
	"encoding/binary"
	"fmt"
)

// XrpTxFields holds the decoded, display-ready fields of an XRP Payment.
// DestinationTag and LastLedgerSequence are pointers so absence (the field was
// not on the wire) is distinguishable from a zero value.
type XrpTxFields struct {
	TransactionType uint16
	TransactionName string // "Payment" for type 0
	Account         string // "r..." address
	Destination     string // "r..." address
	Amount          uint64 // drops
	Fee             uint64 // drops
	Sequence        uint32
	Flags           uint32

	DestinationTag     *uint32
	LastLedgerSequence *uint32

	SigningPubKey []byte
	TxnSignature  []byte
}

// xrpCursor is a bounds-checked forward reader over the serialized transaction.
type xrpCursor struct {
	b   []byte
	pos int
}

func (c *xrpCursor) remaining() int { return len(c.b) - c.pos }

func (c *xrpCursor) readByte() (byte, error) {
	if c.remaining() < 1 {
		return 0, fmt.Errorf("%w: ripple: truncated (want 1 byte)", ErrTxDecode)
	}
	v := c.b[c.pos]
	c.pos++
	return v, nil
}

func (c *xrpCursor) readBytes(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, fmt.Errorf("%w: ripple: truncated (want %d bytes, have %d)", ErrTxDecode, n, c.remaining())
	}
	out := c.b[c.pos : c.pos+n]
	c.pos += n
	return out, nil
}

// readFieldHeader decodes the type/field header (the inverse of xrpFieldHeader).
func (c *xrpCursor) readFieldHeader() (typeCode, fieldCode int, err error) {
	b0, err := c.readByte()
	if err != nil {
		return 0, 0, err
	}
	hi := int(b0 >> 4)
	lo := int(b0 & 0x0f)
	switch {
	case hi != 0 && lo != 0:
		return hi, lo, nil
	case hi != 0: // small type, large field: next byte is the field code
		fc, err := c.readByte()
		if err != nil {
			return 0, 0, err
		}
		return hi, int(fc), nil
	case lo != 0: // large type, small field: next byte is the type code
		tc, err := c.readByte()
		if err != nil {
			return 0, 0, err
		}
		return int(tc), lo, nil
	default: // both large
		tc, err := c.readByte()
		if err != nil {
			return 0, 0, err
		}
		fc, err := c.readByte()
		if err != nil {
			return 0, 0, err
		}
		return int(tc), int(fc), nil
	}
}

// readVarLength decodes a variable-length prefix (the inverse of xrpVarLength).
func (c *xrpCursor) readVarLength() (int, error) {
	b0, err := c.readByte()
	if err != nil {
		return 0, err
	}
	switch {
	case b0 <= 192:
		return int(b0), nil
	case b0 <= 240:
		b1, err := c.readByte()
		if err != nil {
			return 0, err
		}
		return 193 + (int(b0)-193)*256 + int(b1), nil
	case b0 <= 254:
		b1, err := c.readByte()
		if err != nil {
			return 0, err
		}
		b2, err := c.readByte()
		if err != nil {
			return 0, err
		}
		return 12481 + (int(b0)-241)*65536 + int(b1)*256 + int(b2), nil
	default:
		return 0, fmt.Errorf("%w: ripple: invalid length prefix 0x%02x", ErrTxDecode, b0)
	}
}

// DecodeRippleTx decodes a serialized XRP transaction into its display fields.
// Malformed or truncated input returns ErrTxDecode; the function never panics and
// never reads past `raw`.
func DecodeRippleTx(raw []byte) (*XrpTxFields, error) {
	c := &xrpCursor{b: raw}
	f := &XrpTxFields{}

	for c.remaining() > 0 {
		typeCode, fieldCode, err := c.readFieldHeader()
		if err != nil {
			return nil, err
		}
		if err := c.readXrpField(f, typeCode, fieldCode); err != nil {
			return nil, err
		}
	}
	// Every XRP transaction carries an Account; its absence means the input was
	// empty or not a transaction.
	if f.Account == "" {
		return nil, fmt.Errorf("%w: ripple: missing Account field", ErrTxDecode)
	}
	return f, nil
}

// readXrpField reads one field's value (dispatched by type code) and assigns it to
// the matching struct field. Recognised (type, field) pairs are surfaced; any
// other field that can still be length-decoded by its type is consumed and
// ignored, so the cursor stays aligned.
func (c *xrpCursor) readXrpField(f *XrpTxFields, typeCode, fieldCode int) error {
	switch typeCode {
	case 1: // UInt16
		b, err := c.readBytes(2)
		if err != nil {
			return err
		}
		if fieldCode == 2 {
			f.TransactionType = binary.BigEndian.Uint16(b)
			f.TransactionName = xrpTransactionName(f.TransactionType)
		}
	case 2: // UInt32
		b, err := c.readBytes(4)
		if err != nil {
			return err
		}
		v := binary.BigEndian.Uint32(b)
		switch fieldCode {
		case 2:
			f.Flags = v
		case 4:
			f.Sequence = v
		case 14:
			vc := v
			f.DestinationTag = &vc
		case 27:
			vc := v
			f.LastLedgerSequence = &vc
		}
	case 6: // Amount (native = 8 bytes; issued currency = 48 bytes)
		drops, err := c.readXrpAmount()
		if err != nil {
			return err
		}
		switch fieldCode {
		case 1:
			f.Amount = drops
		case 8:
			f.Fee = drops
		}
	case 7: // Blob
		n, err := c.readVarLength()
		if err != nil {
			return err
		}
		b, err := c.readBytes(n)
		if err != nil {
			return err
		}
		switch fieldCode {
		case 3:
			f.SigningPubKey = append([]byte(nil), b...)
		case 4:
			f.TxnSignature = append([]byte(nil), b...)
		}
	case 8: // AccountID
		n, err := c.readVarLength()
		if err != nil {
			return err
		}
		b, err := c.readBytes(n)
		if err != nil {
			return err
		}
		addr, err := xrpRenderAccount(b)
		if err != nil {
			return err
		}
		switch fieldCode {
		case 1:
			f.Account = addr
		case 3:
			f.Destination = addr
		}
	default:
		return fmt.Errorf("%w: ripple: unsupported field type %d", ErrTxDecode, typeCode)
	}
	return nil
}

// readXrpAmount reads a native XRP drops amount (8 bytes) or skips a 48-byte
// issued-currency amount. The high bit of the first byte distinguishes them: 0 =>
// native XRP. For native amounts the two flag bits (native + sign) are masked off
// to recover the drops value.
func (c *xrpCursor) readXrpAmount() (uint64, error) {
	first, err := c.readByte()
	if err != nil {
		return 0, err
	}
	if first&0x80 != 0 {
		// Issued-currency amount: 48 bytes total, the first already consumed.
		if _, err := c.readBytes(47); err != nil {
			return 0, err
		}
		return 0, nil
	}
	rest, err := c.readBytes(7)
	if err != nil {
		return 0, err
	}
	// Reconstruct the full 8-byte big-endian value then strip the top two flag
	// bits (bit 63 native marker, bit 62 sign) to recover the drops.
	full := make([]byte, 8)
	full[0] = first
	copy(full[1:], rest)
	return binary.BigEndian.Uint64(full) &^ (uint64(0xc0) << 56), nil
}

// xrpRenderAccount renders a 20-byte account id as its "r..." base58check address
// (the reverse of encodeXRP).
func xrpRenderAccount(id []byte) (string, error) {
	if len(id) != 20 {
		return "", fmt.Errorf("%w: ripple: account id must be 20 bytes, got %d", ErrTxDecode, len(id))
	}
	return base58CheckEncode(base58XRP, []byte{0x00}, id), nil
}

// xrpTransactionName maps the TransactionType code to a human name (only Payment
// is produced by this library's signer).
func xrpTransactionName(t uint16) string {
	if t == 0 {
		return "Payment"
	}
	return ""
}
