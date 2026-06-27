package hdwallet

// "What am I signing?" decoder for XRP Ledger transactions.
//
// DecodeRippleTx parses a canonical XRP binary blob (the SigningOutput.Encoded
// the tx_ripple.go signer produces) back into its plain fields so a client can
// render a confirmation screen WITHOUT touching a private key or any secret. It
// is the inverse of xrpSerialize. Every read is bounds-checked: malformed or
// truncated input returns ErrTxDecode and the decoder never panics.

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// XrpTxFields holds the decoded, display-ready fields of an XRP transaction.
// Pointer fields are nil when the field was absent on the wire.
type XrpTxFields struct {
	TransactionType uint16
	TransactionName string
	Account         string // "r..." address
	Sequence        uint32
	Flags           uint32
	Fee             uint64 // drops
	SigningPubKey   []byte
	TxnSignature    []byte

	LastLedgerSequence *uint32
	DestinationTag     *uint32

	// Payment / EscrowCreate
	Destination string
	Amount      uint64 // drops (Payment, EscrowCreate)

	// TrustSet
	LimitAmountCurrency string
	LimitAmountIssuer   string
	LimitAmountValue    string

	// OfferCreate
	TakerPaysCurrency string
	TakerPaysIssuer   string
	TakerPaysValue    string
	TakerGetsCurrency string
	TakerGetsIssuer   string
	TakerGetsValue    string

	// OfferCreate / OfferCancel / EscrowFinish
	OfferSequence uint32

	// EscrowCreate / EscrowFinish
	Condition   []byte
	CancelAfter *uint32
	FinishAfter *uint32

	// EscrowFinish
	Owner       string
	Fulfillment []byte

	// AccountSet
	SetFlag      *uint32
	ClearFlag    *uint32
	Domain       []byte
	TransferRate *uint32
	TickSize     *uint32
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
	case hi != 0: // small type, large field
		fc, err := c.readByte()
		if err != nil {
			return 0, 0, err
		}
		return hi, int(fc), nil
	case lo != 0: // large type, small field
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
// Malformed or truncated input returns ErrTxDecode; never panics.
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
	if f.Account == "" {
		return nil, fmt.Errorf("%w: ripple: missing Account field", ErrTxDecode)
	}
	return f, nil
}

// xrpAmt is the result of decoding an Amount field.
type xrpAmt struct {
	native uint64
	// issued fields (all non-empty when the amount is an issued currency)
	issuedCurrency string
	issuedIssuer   string
	issuedValue    string
}

// readXrpField reads one field and populates the matching XrpTxFields member.
// Unknown fields within a known type are consumed to keep the cursor aligned.
func (c *xrpCursor) readXrpField(f *XrpTxFields, typeCode, fieldCode int) error {
	switch typeCode {
	case 1: // UInt16 (2 bytes)
		b, err := c.readBytes(2)
		if err != nil {
			return err
		}
		if fieldCode == 2 {
			f.TransactionType = binary.BigEndian.Uint16(b)
			f.TransactionName = xrpTransactionName(f.TransactionType)
		}

	case 2: // UInt32 (4 bytes)
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
		case 11: // TransferRate
			vc := v
			f.TransferRate = &vc
		case 14: // DestinationTag
			vc := v
			f.DestinationTag = &vc
		case 16: // TickSize
			vc := v
			f.TickSize = &vc
		case 25: // OfferSequence
			f.OfferSequence = v
		case 27: // LastLedgerSequence
			vc := v
			f.LastLedgerSequence = &vc
		case 33: // SetFlag
			vc := v
			f.SetFlag = &vc
		case 34: // ClearFlag
			vc := v
			f.ClearFlag = &vc
		case 36: // CancelAfter
			vc := v
			f.CancelAfter = &vc
		case 37: // FinishAfter
			vc := v
			f.FinishAfter = &vc
		}

	case 6: // Amount (native 8 bytes or issued 48 bytes)
		a, err := c.readXrpAmount()
		if err != nil {
			return err
		}
		switch fieldCode {
		case 1: // Amount (Payment, EscrowCreate)
			f.Amount = a.native
		case 3: // LimitAmount (TrustSet)
			f.LimitAmountCurrency = a.issuedCurrency
			f.LimitAmountIssuer = a.issuedIssuer
			f.LimitAmountValue = a.issuedValue
		case 4: // TakerPays (OfferCreate)
			f.TakerPaysCurrency = a.issuedCurrency
			f.TakerPaysIssuer = a.issuedIssuer
			if a.issuedCurrency == "" {
				f.TakerPaysValue = strconv.FormatUint(a.native, 10)
			} else {
				f.TakerPaysValue = a.issuedValue
			}
		case 5: // TakerGets (OfferCreate)
			f.TakerGetsCurrency = a.issuedCurrency
			f.TakerGetsIssuer = a.issuedIssuer
			if a.issuedCurrency == "" {
				f.TakerGetsValue = strconv.FormatUint(a.native, 10)
			} else {
				f.TakerGetsValue = a.issuedValue
			}
		case 8: // Fee
			f.Fee = a.native
		}

	case 7: // Blob (variable length)
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
		case 7: // Domain
			f.Domain = append([]byte(nil), b...)
		case 16: // Fulfillment
			f.Fulfillment = append([]byte(nil), b...)
		case 24: // Condition
			f.Condition = append([]byte(nil), b...)
		}

	case 8: // AccountID (variable length, always 20 bytes + 1-byte prefix)
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
		case 2: // Owner (EscrowFinish)
			f.Owner = addr
		case 3: // Destination
			f.Destination = addr
		}

	default:
		return fmt.Errorf("%w: ripple: unsupported field type %d", ErrTxDecode, typeCode)
	}
	return nil
}

// readXrpAmount decodes an Amount field: 8 bytes for native XRP, 48 bytes for
// issued currency. The high bit of the first byte distinguishes them.
func (c *xrpCursor) readXrpAmount() (xrpAmt, error) {
	first, err := c.readByte()
	if err != nil {
		return xrpAmt{}, err
	}

	if first&0x80 == 0 {
		// Native XRP: mask off the top two flag bits to recover drops.
		rest, err := c.readBytes(7)
		if err != nil {
			return xrpAmt{}, err
		}
		full := make([]byte, 8)
		full[0] = first
		copy(full[1:], rest)
		drops := binary.BigEndian.Uint64(full) &^ (uint64(0xc0) << 56)
		return xrpAmt{native: drops}, nil
	}

	// Issued currency: 48 bytes total (first already consumed).
	rest, err := c.readBytes(47)
	if err != nil {
		return xrpAmt{}, err
	}
	all := make([]byte, 48)
	all[0] = first
	copy(all[1:], rest)

	currency, issuer, value, err := xrpDecodeIssuedAmount(all)
	if err != nil {
		return xrpAmt{}, err
	}
	return xrpAmt{issuedCurrency: currency, issuedIssuer: issuer, issuedValue: value}, nil
}

// xrpDecodeIssuedAmount decodes a 48-byte issued-currency amount into its
// human-readable parts. The reverse of xrpIssuedAmount.
func xrpDecodeIssuedAmount(b []byte) (currency, issuer, value string, err error) {
	if len(b) != 48 {
		return "", "", "", fmt.Errorf("%w: ripple: issued amount must be 48 bytes", ErrTxDecode)
	}
	word := binary.BigEndian.Uint64(b[:8])

	// Currency: bytes 8–27, 20-byte code.
	var currBytes [20]byte
	copy(currBytes[:], b[8:28])
	if currBytes[0] == 0x00 {
		// Standard 3-letter ASCII: bytes 12–14.
		raw := strings.TrimRight(string(currBytes[12:15]), "\x00")
		currency = raw
	} else {
		currency = bytesToHex(currBytes[:])
	}

	// Issuer: bytes 28–47.
	issuer, err = xrpRenderAccount(b[28:48])
	if err != nil {
		return "", "", "", err
	}

	// Value from the 8-byte word.
	mantissa := word & ((1 << 54) - 1)
	if mantissa == 0 {
		value = "0"
		return
	}
	negative := (word>>62)&1 == 0
	storedExp := int((word >> 54) & 0xFF)
	actualExp := storedExp - 97

	// Format: mantissa × 10^actualExp as a decimal string.
	v := strconv.FormatUint(mantissa, 10)
	pos := len(v) + actualExp // decimal point position from the left
	if pos <= 0 {
		value = "0." + strings.Repeat("0", -pos) + v
	} else if pos >= len(v) {
		value = v + strings.Repeat("0", pos-len(v))
	} else {
		value = v[:pos] + "." + v[pos:]
	}
	// Trim trailing zeros and a trailing decimal point.
	if strings.ContainsRune(value, '.') {
		value = strings.TrimRight(value, "0")
		value = strings.TrimRight(value, ".")
	}
	if negative {
		value = "-" + value
	}
	return
}

// xrpRenderAccount renders a 20-byte account id as its "r..." base58check address.
func xrpRenderAccount(id []byte) (string, error) {
	if len(id) != 20 {
		return "", fmt.Errorf("%w: ripple: account id must be 20 bytes, got %d", ErrTxDecode, len(id))
	}
	return base58CheckEncode(base58XRP, []byte{0x00}, id), nil
}

// xrpTransactionName maps the TransactionType code to a human name.
func xrpTransactionName(t uint16) string {
	switch t {
	case 0:
		return "Payment"
	case 1:
		return "EscrowCreate"
	case 2:
		return "EscrowFinish"
	case 3:
		return "AccountSet"
	case 7:
		return "OfferCreate"
	case 8:
		return "OfferCancel"
	case 20:
		return "TrustSet"
	default:
		return ""
	}
}
