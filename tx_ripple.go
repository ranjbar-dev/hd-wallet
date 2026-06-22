package hdwallet

import (
	"encoding/binary"
	"fmt"

	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
)

// XRP Ledger (Ripple) Payment signing.
//
// XRP transactions use a canonical binary serialization: each field is emitted
// as a type/field header byte (or bytes) followed by its value, and fields are
// ordered by (type_code, field_code) ascending. The signing digest is
// sha512Half(0x53545800 || serialize(tx without TxnSignature)) — the four-byte
// "STX\0" prefix domain-separates single-signing. The TxnSignature is the
// canonical low-S DER secp256k1 signature; it is then inserted and the full tx
// re-serialized for the wire.
//
// Field set for a native Payment (in serialization order):
//
//	TransactionType (UInt16  1.2)  Payment = 0
//	Flags           (UInt32  2.2)
//	Sequence        (UInt32  2.4)
//	DestinationTag  (UInt32  2.14) — only if set
//	LastLedgerSeq   (UInt32  2.27)
//	Amount          (Amount  6.1)  drops, native (high bit set)
//	Fee             (Amount  6.8)  drops, native
//	SigningPubKey   (Blob    7.3)  33-byte compressed key
//	TxnSignature    (Blob    7.4)  DER signature (omitted from signing preimage)
//	Account         (AccountID 8.1)
//	Destination     (AccountID 8.3)
//
// Verified byte-for-byte against Trust Wallet Core's Ripple AnySigner vector
// (see tx_ripple_test.go).

// xrpSingleSignPrefix is the "STX\0" hash prefix for single-signing.
var xrpSingleSignPrefix = []byte{0x53, 0x54, 0x58, 0x00}

// xrpNativeAmountFlag is OR-ed into a drops amount: bit 63 marks "not an XRP
// issued-currency amount" (i.e. native XRP), bit 62 marks a positive value.
const xrpNativeAmountFlag uint64 = 0x4000000000000000

// signRippleTx builds, signs and serializes an XRP Payment.
func (w *HDWallet) signRippleTx(symbol Symbol, index uint32, in *txripple.SigningInput) (*txripple.SigningOutput, error) {
	payment := in.GetPayment()
	if payment == nil {
		return nil, fmt.Errorf("%w: ripple: only native Payment is supported", ErrTxInput)
	}

	account, err := ParseAddress(XRP, in.GetAccount())
	if err != nil {
		return nil, fmt.Errorf("%w: ripple: account: %v", ErrTxInput, err)
	}
	destination, err := ParseAddress(XRP, payment.GetDestination())
	if err != nil {
		return nil, fmt.Errorf("%w: ripple: destination: %v", ErrTxInput, err)
	}

	pub, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(pub) != 33 {
		return nil, fmt.Errorf("%w: ripple: expected 33-byte compressed key", ErrTxInput)
	}

	fields := xrpPaymentFields(in, payment, account, destination, pub)

	// Signing preimage: STX prefix || serialize(fields without TxnSignature).
	preimage := append(append([]byte(nil), xrpSingleSignPrefix...), xrpSerialize(fields)...)
	digest := sha512Half(preimage)

	sig, err := w.SignIndex(symbol, index, digest)
	if err != nil {
		return nil, err
	}
	der := sig.DER()
	if der == nil {
		return nil, fmt.Errorf("%w: ripple: %s is not an ECDSA coin", ErrTxInput, symbol)
	}

	// Insert TxnSignature (Blob 7.4) and re-serialize for the wire.
	fields = append(fields, xrpField{typeCode: 7, fieldCode: 4, value: xrpBlob(der)})
	xrpSortFields(fields)
	encoded := xrpSerialize(fields)

	return &txripple.SigningOutput{
		Encoded:    encoded,
		EncodedHex: bytesToHex(encoded),
	}, nil
}

// xrpField is one serialized field: its type/field codes (for ordering and the
// header) and its already-encoded value bytes.
type xrpField struct {
	typeCode  int
	fieldCode int
	value     []byte
}

// xrpPaymentFields builds the ordered field set for a Payment, excluding the
// TxnSignature (added after signing).
func xrpPaymentFields(in *txripple.SigningInput, payment *txripple.Payment, account, destination, pub []byte) []xrpField {
	fields := []xrpField{
		{typeCode: 1, fieldCode: 2, value: xrpUint16(0)},                             // TransactionType = Payment
		{typeCode: 2, fieldCode: 2, value: xrpUint32(in.GetFlags())},                 // Flags
		{typeCode: 2, fieldCode: 4, value: xrpUint32(in.GetSequence())},              // Sequence
		{typeCode: 2, fieldCode: 27, value: xrpUint32(in.GetLastLedgerSequence())},   // LastLedgerSequence
		{typeCode: 6, fieldCode: 1, value: xrpAmount(i64AsU64(payment.GetAmount()))}, // Amount
		{typeCode: 6, fieldCode: 8, value: xrpAmount(i64AsU64(in.GetFee()))},         // Fee
		{typeCode: 7, fieldCode: 3, value: xrpBlob(pub)},                             // SigningPubKey
		{typeCode: 8, fieldCode: 1, value: xrpAccountID(account)},                    // Account
		{typeCode: 8, fieldCode: 3, value: xrpAccountID(destination)},                // Destination
	}
	if tag := payment.GetDestinationTag(); tag != 0 {
		fields = append(fields, xrpField{typeCode: 2, fieldCode: 14, value: xrpUint32(u32Trunc(i64AsU64(tag)))})
	}
	xrpSortFields(fields)
	return fields
}

// xrpSortFields sorts fields by (typeCode, fieldCode) ascending — XRP's canonical
// serialization order. Uses a simple insertion sort to avoid a sort import for
// these tiny slices.
func xrpSortFields(fields []xrpField) {
	for i := 1; i < len(fields); i++ {
		for j := i; j > 0 && xrpLess(fields[j], fields[j-1]); j-- {
			fields[j], fields[j-1] = fields[j-1], fields[j]
		}
	}
}

// xrpLess reports whether a sorts before b in canonical order.
func xrpLess(a, b xrpField) bool {
	if a.typeCode != b.typeCode {
		return a.typeCode < b.typeCode
	}
	return a.fieldCode < b.fieldCode
}

// xrpSerialize concatenates each field's header and value in the given order.
func xrpSerialize(fields []xrpField) []byte {
	var out []byte
	for _, f := range fields {
		out = append(out, xrpFieldHeader(f.typeCode, f.fieldCode)...)
		out = append(out, f.value...)
	}
	return out
}

// xrpFieldHeader encodes the field id. If both type and field codes are < 16
// they pack into one byte (type<<4 | field); otherwise the large code(s) spill
// into following byte(s) per the XRP wire format.
func xrpFieldHeader(typeCode, fieldCode int) []byte {
	tc, fc := lowByte(typeCode), lowByte(fieldCode)
	switch {
	case typeCode < 16 && fieldCode < 16:
		return []byte{tc<<4 | fc}
	case typeCode < 16: // small type, large field
		return []byte{tc << 4, fc}
	case fieldCode < 16: // large type, small field
		return []byte{fc, tc}
	default: // both large
		return []byte{0x00, tc, fc}
	}
}

// xrpUint16 encodes a big-endian uint16.
func xrpUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// xrpUint32 encodes a big-endian uint32.
func xrpUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// xrpAmount encodes a native XRP drops amount: 8 bytes big-endian with the
// native/positive flags set.
func xrpAmount(drops uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, drops|xrpNativeAmountFlag)
	return b
}

// xrpBlob length-prefixes variable-length data (used for keys and signatures).
// For lengths < 193 the prefix is a single byte equal to the length.
func xrpBlob(b []byte) []byte {
	return append(xrpVarLength(len(b)), b...)
}

// xrpAccountID encodes a 20-byte account id as a length-prefixed blob (the
// length is always 20 -> single 0x14 prefix byte).
func xrpAccountID(id []byte) []byte {
	return xrpBlob(id)
}

// xrpVarLength encodes a variable-length prefix per the XRP format. Only the
// single-byte form (length 0..192) is needed for Payment fields (keys 33 bytes,
// signatures ~70 bytes); larger lengths use the documented multi-byte forms.
func xrpVarLength(n int) []byte {
	switch {
	case n <= 192:
		return []byte{lowByte(n)}
	case n <= 12480:
		n -= 193
		return []byte{lowByte(193 + (n >> 8)), lowByte(n)}
	default:
		n -= 12481
		return []byte{lowByte(241 + (n >> 16)), lowByte(n >> 8), lowByte(n)}
	}
}

// sha512Half returns the first 32 bytes of SHA-512(b), XRP's transaction hash.
func sha512Half(b []byte) []byte {
	full := sha512Sum(b)
	return full[:32]
}
