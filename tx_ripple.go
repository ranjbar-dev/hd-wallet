package hdwallet

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

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

// signRippleTx dispatches to the correct per-type signer based on the oneof.
func (w *HDWallet) signRippleTx(symbol Symbol, index uint32, in *txripple.SigningInput) (*txripple.SigningOutput, error) {
	account, err := ParseAddress(XRP, in.GetAccount())
	if err != nil {
		return nil, fmt.Errorf("%w: ripple: account: %v", ErrTxInput, err)
	}
	pub, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(pub) != 33 {
		return nil, fmt.Errorf("%w: ripple: expected 33-byte compressed key", ErrTxInput)
	}

	var fields []xrpField
	switch {
	case in.GetPayment() != nil:
		payment := in.GetPayment()
		dest, err := ParseAddress(XRP, payment.GetDestination())
		if err != nil {
			return nil, fmt.Errorf("%w: ripple: destination: %v", ErrTxInput, err)
		}
		fields = xrpPaymentFields(in, payment, account, dest, pub)
	case in.GetTrustSet() != nil:
		f, err := xrpTrustSetFields(in, in.GetTrustSet(), account, pub)
		if err != nil {
			return nil, err
		}
		fields = f
	case in.GetOfferCreate() != nil:
		f, err := xrpOfferCreateFields(in, in.GetOfferCreate(), account, pub)
		if err != nil {
			return nil, err
		}
		fields = f
	case in.GetOfferCancel() != nil:
		fields = xrpOfferCancelFields(in, in.GetOfferCancel(), account, pub)
	case in.GetEscrowCreate() != nil:
		f, err := xrpEscrowCreateFields(in, in.GetEscrowCreate(), account, pub)
		if err != nil {
			return nil, err
		}
		fields = f
	case in.GetEscrowFinish() != nil:
		f, err := xrpEscrowFinishFields(in, in.GetEscrowFinish(), account, pub)
		if err != nil {
			return nil, err
		}
		fields = f
	case in.GetAccountSet() != nil:
		fields = xrpAccountSetFields(in, in.GetAccountSet(), account, pub)
	default:
		return nil, fmt.Errorf("%w: ripple: no transaction type set", ErrTxInput)
	}

	return xrpSignAndEncode(w, symbol, index, fields)
}

// xrpSignAndEncode computes the signing preimage, signs, inserts TxnSignature,
// and returns the final encoded output.
func xrpSignAndEncode(w *HDWallet, symbol Symbol, index uint32, fields []xrpField) (*txripple.SigningOutput, error) {
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

	fields = append(fields, xrpField{typeCode: 7, fieldCode: 4, value: xrpBlob(der)})
	xrpSortFields(fields)
	encoded := xrpSerialize(fields)
	txID := strings.ToUpper(bytesToHex(sha512Half(encoded)))
	return &txripple.SigningOutput{
		Encoded:    encoded,
		EncodedHex: bytesToHex(encoded),
		TxId:       txID,
	}, nil
}

// xrpTrustSetFields builds the pre-signature field list for a TrustSet (type 20).
//
// Canonical field order:
//
//	TransactionType (1.2)  = 20
//	Flags           (2.2)
//	Sequence        (2.4)
//	LastLedgerSeq   (2.27)
//	LimitAmount     (6.3)  issued currency amount (48 bytes)
//	Fee             (6.8)
//	SigningPubKey   (7.3)
//	Account         (8.1)
func xrpTrustSetFields(in *txripple.SigningInput, ts *txripple.TrustSet, account, pub []byte) ([]xrpField, error) {
	limit, err := xrpIssuedAmount(ts.GetLimitAmountCurrency(), ts.GetLimitAmountIssuer(), ts.GetLimitAmountValue())
	if err != nil {
		return nil, fmt.Errorf("%w: ripple: trustset limit: %v", ErrTxInput, err)
	}
	fields := []xrpField{
		{typeCode: 1, fieldCode: 2, value: xrpUint16(20)},                          // TransactionType = TrustSet
		{typeCode: 2, fieldCode: 2, value: xrpUint32(in.GetFlags())},               // Flags
		{typeCode: 2, fieldCode: 4, value: xrpUint32(in.GetSequence())},            // Sequence
		{typeCode: 2, fieldCode: 27, value: xrpUint32(in.GetLastLedgerSequence())}, // LastLedgerSequence
		{typeCode: 6, fieldCode: 3, value: limit},                                  // LimitAmount (issued)
		{typeCode: 6, fieldCode: 8, value: xrpAmount(i64AsU64(in.GetFee()))},       // Fee
		{typeCode: 7, fieldCode: 3, value: xrpBlob(pub)},                           // SigningPubKey
		{typeCode: 8, fieldCode: 1, value: xrpAccountID(account)},                  // Account
	}
	xrpSortFields(fields)
	return fields, nil
}

// xrpOfferCreateFields builds the pre-signature field list for an OfferCreate (type 7).
//
// Canonical field order (sorted by type_code, field_code):
//
//	TransactionType (1.2)  = 7
//	Flags           (2.2)
//	Sequence        (2.4)
//	OfferSequence   (2.25) — only if != 0
//	LastLedgerSeq   (2.27)
//	TakerPays       (6.4)  native or issued
//	TakerGets       (6.5)  native or issued
//	Fee             (6.8)
//	SigningPubKey   (7.3)
//	Account         (8.1)
func xrpOfferCreateFields(in *txripple.SigningInput, oc *txripple.OfferCreate, account, pub []byte) ([]xrpField, error) {
	takerPays, err := xrpAmountField(oc.GetTakerPaysCurrency(), oc.GetTakerPaysIssuer(), oc.GetTakerPaysValue())
	if err != nil {
		return nil, fmt.Errorf("%w: ripple: offercreate taker_pays: %v", ErrTxInput, err)
	}
	takerGets, err := xrpAmountField(oc.GetTakerGetsCurrency(), oc.GetTakerGetsIssuer(), oc.GetTakerGetsValue())
	if err != nil {
		return nil, fmt.Errorf("%w: ripple: offercreate taker_gets: %v", ErrTxInput, err)
	}
	fields := []xrpField{
		{typeCode: 1, fieldCode: 2, value: xrpUint16(7)},                           // TransactionType = OfferCreate
		{typeCode: 2, fieldCode: 2, value: xrpUint32(in.GetFlags())},               // Flags
		{typeCode: 2, fieldCode: 4, value: xrpUint32(in.GetSequence())},            // Sequence
		{typeCode: 2, fieldCode: 27, value: xrpUint32(in.GetLastLedgerSequence())}, // LastLedgerSequence
		{typeCode: 6, fieldCode: 4, value: takerPays},                              // TakerPays
		{typeCode: 6, fieldCode: 5, value: takerGets},                              // TakerGets
		{typeCode: 6, fieldCode: 8, value: xrpAmount(i64AsU64(in.GetFee()))},       // Fee
		{typeCode: 7, fieldCode: 3, value: xrpBlob(pub)},                           // SigningPubKey
		{typeCode: 8, fieldCode: 1, value: xrpAccountID(account)},                  // Account
	}
	if seq := oc.GetOfferSequence(); seq != 0 {
		fields = append(fields, xrpField{typeCode: 2, fieldCode: 25, value: xrpUint32(seq)})
	}
	xrpSortFields(fields)
	return fields, nil
}

// xrpOfferCancelFields builds the pre-signature field list for an OfferCancel (type 8).
func xrpOfferCancelFields(in *txripple.SigningInput, oc *txripple.OfferCancel, account, pub []byte) []xrpField {
	fields := []xrpField{
		{typeCode: 1, fieldCode: 2, value: xrpUint16(8)},                           // TransactionType = OfferCancel
		{typeCode: 2, fieldCode: 2, value: xrpUint32(in.GetFlags())},               // Flags
		{typeCode: 2, fieldCode: 4, value: xrpUint32(in.GetSequence())},            // Sequence
		{typeCode: 2, fieldCode: 25, value: xrpUint32(oc.GetOfferSequence())},      // OfferSequence
		{typeCode: 2, fieldCode: 27, value: xrpUint32(in.GetLastLedgerSequence())}, // LastLedgerSequence
		{typeCode: 6, fieldCode: 8, value: xrpAmount(i64AsU64(in.GetFee()))},       // Fee
		{typeCode: 7, fieldCode: 3, value: xrpBlob(pub)},                           // SigningPubKey
		{typeCode: 8, fieldCode: 1, value: xrpAccountID(account)},                  // Account
	}
	xrpSortFields(fields)
	return fields
}

// xrpEscrowCreateFields builds the pre-signature field list for an EscrowCreate (type 1).
func xrpEscrowCreateFields(in *txripple.SigningInput, ec *txripple.EscrowCreate, account, pub []byte) ([]xrpField, error) {
	drops, err := strconv.ParseUint(ec.GetAmount(), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: ripple: escrowcreate amount: %v", ErrTxInput, err)
	}
	dest, err := ParseAddress(XRP, ec.GetDestination())
	if err != nil {
		return nil, fmt.Errorf("%w: ripple: escrowcreate destination: %v", ErrTxInput, err)
	}
	fields := []xrpField{
		{typeCode: 1, fieldCode: 2, value: xrpUint16(1)},                           // TransactionType = EscrowCreate
		{typeCode: 2, fieldCode: 2, value: xrpUint32(in.GetFlags())},               // Flags
		{typeCode: 2, fieldCode: 4, value: xrpUint32(in.GetSequence())},            // Sequence
		{typeCode: 2, fieldCode: 27, value: xrpUint32(in.GetLastLedgerSequence())}, // LastLedgerSequence
		{typeCode: 6, fieldCode: 1, value: xrpAmount(drops)},                       // Amount
		{typeCode: 6, fieldCode: 8, value: xrpAmount(i64AsU64(in.GetFee()))},       // Fee
		{typeCode: 7, fieldCode: 3, value: xrpBlob(pub)},                           // SigningPubKey
		{typeCode: 8, fieldCode: 1, value: xrpAccountID(account)},                  // Account
		{typeCode: 8, fieldCode: 3, value: xrpAccountID(dest)},                     // Destination
	}
	if tag := ec.GetDestinationTag(); tag != 0 {
		fields = append(fields, xrpField{typeCode: 2, fieldCode: 14, value: xrpUint32(tag)})
	}
	if ca := ec.GetCancelAfter(); ca != 0 {
		fields = append(fields, xrpField{typeCode: 2, fieldCode: 36, value: xrpUint32(ca)})
	}
	if fa := ec.GetFinishAfter(); fa != 0 {
		fields = append(fields, xrpField{typeCode: 2, fieldCode: 37, value: xrpUint32(fa)})
	}
	if cond := ec.GetCondition(); len(cond) > 0 {
		fields = append(fields, xrpField{typeCode: 7, fieldCode: 24, value: xrpBlob(cond)})
	}
	xrpSortFields(fields)
	return fields, nil
}

// xrpEscrowFinishFields builds the pre-signature field list for an EscrowFinish (type 2).
func xrpEscrowFinishFields(in *txripple.SigningInput, ef *txripple.EscrowFinish, account, pub []byte) ([]xrpField, error) {
	owner, err := ParseAddress(XRP, ef.GetOwner())
	if err != nil {
		return nil, fmt.Errorf("%w: ripple: escrowfinish owner: %v", ErrTxInput, err)
	}
	fields := []xrpField{
		{typeCode: 1, fieldCode: 2, value: xrpUint16(2)},                           // TransactionType = EscrowFinish
		{typeCode: 2, fieldCode: 2, value: xrpUint32(in.GetFlags())},               // Flags
		{typeCode: 2, fieldCode: 4, value: xrpUint32(in.GetSequence())},            // Sequence
		{typeCode: 2, fieldCode: 25, value: xrpUint32(ef.GetOfferSequence())},      // OfferSequence (EscrowCreate seq)
		{typeCode: 2, fieldCode: 27, value: xrpUint32(in.GetLastLedgerSequence())}, // LastLedgerSequence
		{typeCode: 6, fieldCode: 8, value: xrpAmount(i64AsU64(in.GetFee()))},       // Fee
		{typeCode: 7, fieldCode: 3, value: xrpBlob(pub)},                           // SigningPubKey
		{typeCode: 8, fieldCode: 1, value: xrpAccountID(account)},                  // Account
		{typeCode: 8, fieldCode: 2, value: xrpAccountID(owner)},                    // Owner
	}
	if cond := ef.GetCondition(); len(cond) > 0 {
		fields = append(fields, xrpField{typeCode: 7, fieldCode: 24, value: xrpBlob(cond)})
	}
	if ful := ef.GetFulfillment(); len(ful) > 0 {
		fields = append(fields, xrpField{typeCode: 7, fieldCode: 16, value: xrpBlob(ful)})
	}
	xrpSortFields(fields)
	return fields, nil
}

// xrpAccountSetFields builds the pre-signature field list for an AccountSet (type 3).
func xrpAccountSetFields(in *txripple.SigningInput, as *txripple.AccountSet, account, pub []byte) []xrpField {
	fields := []xrpField{
		{typeCode: 1, fieldCode: 2, value: xrpUint16(3)},                           // TransactionType = AccountSet
		{typeCode: 2, fieldCode: 2, value: xrpUint32(in.GetFlags())},               // Flags
		{typeCode: 2, fieldCode: 4, value: xrpUint32(in.GetSequence())},            // Sequence
		{typeCode: 2, fieldCode: 27, value: xrpUint32(in.GetLastLedgerSequence())}, // LastLedgerSequence
		{typeCode: 6, fieldCode: 8, value: xrpAmount(i64AsU64(in.GetFee()))},       // Fee
		{typeCode: 7, fieldCode: 3, value: xrpBlob(pub)},                           // SigningPubKey
		{typeCode: 8, fieldCode: 1, value: xrpAccountID(account)},                  // Account
	}
	if r := as.GetTransferRate(); r != 0 {
		fields = append(fields, xrpField{typeCode: 2, fieldCode: 11, value: xrpUint32(r)})
	}
	if ts := as.GetTickSize(); ts != 0 {
		fields = append(fields, xrpField{typeCode: 2, fieldCode: 16, value: xrpUint32(ts)})
	}
	if sf := as.GetSetFlag(); sf != 0 {
		fields = append(fields, xrpField{typeCode: 2, fieldCode: 33, value: xrpUint32(sf)})
	}
	if cf := as.GetClearFlag(); cf != 0 {
		fields = append(fields, xrpField{typeCode: 2, fieldCode: 34, value: xrpUint32(cf)})
	}
	if dom := as.GetDomain(); len(dom) > 0 {
		fields = append(fields, xrpField{typeCode: 7, fieldCode: 7, value: xrpBlob(dom)})
	}
	xrpSortFields(fields)
	return fields
}

// xrpAmountField encodes a TakerPays/TakerGets amount: native XRP (drops) when
// currency is empty or "XRP", issued currency otherwise.
func xrpAmountField(currency, issuer, valueStr string) ([]byte, error) {
	if currency == "" || strings.EqualFold(currency, "XRP") {
		drops, err := strconv.ParseUint(valueStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("native XRP drops: %v", err)
		}
		return xrpAmount(drops), nil
	}
	return xrpIssuedAmount(currency, issuer, valueStr)
}

// xrpIssuedAmount encodes a 48-byte issued-currency amount:
//   - 8 bytes: IEEE-754–style sign+exponent+mantissa word
//   - 20 bytes: currency code
//   - 20 bytes: issuer account ID
//
// The mantissa is normalized so 10^15 ≤ M < 10^16 (XRPL canonical form).
// Currency may be a 3-letter ASCII code ("USD") or a 40-char lowercase hex string.
func xrpIssuedAmount(currency, issuer, valueStr string) ([]byte, error) {
	mantissa, exp, neg, err := xrpParseDecimal(valueStr)
	if err != nil {
		return nil, fmt.Errorf("issued amount value: %v", err)
	}

	var word uint64
	if mantissa == 0 {
		word = 0x8000000000000000 // canonical zero for issued currency
	} else {
		// Normalize: 10^15 ≤ mantissa < 10^16
		for mantissa < 1_000_000_000_000_000 {
			mantissa *= 10
			exp--
		}
		for mantissa >= 10_000_000_000_000_000 {
			mantissa /= 10
			exp++
		}
		word = 1 << 63 // issued-currency marker
		if !neg {
			word |= 1 << 62 // positive
		}
		word |= uint64(exp+97) << 54 // #nosec G115 -- exp+97 ∈ [1,17] (XRP exponent range); always fits uint64
		word |= mantissa & ((1 << 54) - 1)
	}

	currCode, err := xrpCurrencyCode(currency)
	if err != nil {
		return nil, err
	}
	issuerID, err := ParseAddress(XRP, issuer)
	if err != nil {
		return nil, fmt.Errorf("issued amount issuer: %v", err)
	}

	var out [48]byte
	binary.BigEndian.PutUint64(out[:8], word)
	copy(out[8:28], currCode[:])
	copy(out[28:48], issuerID)
	return out[:], nil
}

// xrpCurrencyCode encodes a currency string into the 20-byte XRPL representation.
// 3-letter ASCII codes (e.g. "USD") use the standard encoding:
// 12 zero bytes || 3 ASCII bytes || 5 zero bytes.
// 40-char lowercase hex strings are decoded directly.
func xrpCurrencyCode(currency string) ([20]byte, error) {
	var code [20]byte
	switch len(currency) {
	case 40:
		b, err := hex.DecodeString(currency)
		if err != nil {
			return code, fmt.Errorf("currency code hex: %v", err)
		}
		copy(code[:], b)
	case 3:
		copy(code[12:15], []byte(currency))
	default:
		return code, fmt.Errorf("currency code must be 3-letter ASCII or 40-char hex, got %q", currency)
	}
	return code, nil
}

// xrpParseDecimal parses a decimal string into (mantissa, exponent, negative)
// where value = mantissa × 10^exponent. Does not normalize.
func xrpParseDecimal(s string) (mantissa uint64, exp int, negative bool, err error) {
	if s == "" {
		return 0, 0, false, fmt.Errorf("empty amount string")
	}
	if s[0] == '-' {
		negative = true
		s = s[1:]
	}
	var intPart, fracPart string
	if i := strings.IndexByte(s, '.'); i >= 0 {
		intPart, fracPart = s[:i], s[i+1:]
	} else {
		intPart = s
	}
	exp = -len(fracPart)
	combined := intPart + fracPart
	if combined == "" {
		return 0, 0, false, fmt.Errorf("invalid amount %q", s)
	}
	for _, c := range combined {
		if c < '0' || c > '9' {
			return 0, 0, false, fmt.Errorf("invalid character %q in amount", c)
		}
		mantissa = mantissa*10 + uint64(c-'0')
	}
	return
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
