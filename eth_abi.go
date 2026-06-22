package hdwallet

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Ethereum Contract ABI encoding/decoding, mirroring Trust Wallet Core's
// EthereumAbi. It encodes a function call as the 4-byte selector
// (keccak256(signature)[:4]) followed by the head/tail encoding of the arguments,
// and decodes the reverse. Supported element types:
//
//	address, bool, uint<M>/int<M> (M in 8..256, multiple of 8), bytes<N> (1..32),
//	bytes (dynamic), string (dynamic), T[] (dynamic array), T[k] (fixed array),
//	and tuples (T1,T2,...).
//
// Numbers are passed as *big.Int, address/bytesN/bytes/string as []byte (address
// must be 20 bytes), bool as bool, arrays/tuples as []ABIValue.

// ABI-related errors.
var (
	// ErrABIType is returned for an unrecognized or unsupported ABI type string.
	ErrABIType = errors.New("hdwallet: unsupported ABI type")
	// ErrABIValue is returned when a Go value does not match its ABI type.
	ErrABIValue = errors.New("hdwallet: ABI value does not match type")
	// ErrABIDecode is returned when ABI-encoded input is malformed.
	ErrABIDecode = errors.New("hdwallet: malformed ABI encoding")
)

const abiWord = 32

// ABIValue is one ABI argument: Type is the canonical type string (e.g. "uint256",
// "address", "bytes", "uint256[]", "(address,uint256)") and Value is the Go value:
//
//	address, bytesN, bytes, string -> []byte
//	uint*/int*                     -> *big.Int
//	bool                           -> bool
//	arrays, tuples                 -> []ABIValue (elements/fields)
type ABIValue struct {
	Type  string
	Value any
}

// ABIEncode encodes a function call: selector(name,types...) || head/tail(args).
// The signature is formed from name and the argument types, so name must be the
// bare function name (e.g. "transfer"), not the full signature.
func ABIEncode(name string, args []ABIValue) ([]byte, error) {
	types := make([]string, len(args))
	for i, a := range args {
		types[i] = canonicalType(a.Type)
	}
	sig := fmt.Sprintf("%s(%s)", name, strings.Join(types, ","))
	selector := keccak256([]byte(sig))[:4]

	body, err := ABIEncodeParams(args)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), selector...), body...), nil
}

// ABIFunctionSelector returns the 4-byte selector for a function signature built
// from name and the given argument types (the canonical forms are used).
func ABIFunctionSelector(name string, types []string) []byte {
	canon := make([]string, len(types))
	for i, t := range types {
		canon[i] = canonicalType(t)
	}
	sig := fmt.Sprintf("%s(%s)", name, strings.Join(canon, ","))
	return keccak256([]byte(sig))[:4]
}

// ABIEncodeParams encodes a tuple of values (no selector) using the head/tail
// layout. This is the encoding used for the arguments of a call and for nested
// tuples/arrays.
func ABIEncodeParams(values []ABIValue) ([]byte, error) {
	heads := make([][]byte, len(values))
	tails := make([][]byte, len(values))
	dynamic := make([]bool, len(values))

	headSize := 0
	for i, v := range values {
		enc, err := encodeValue(v)
		if err != nil {
			return nil, err
		}
		dyn, err := isDynamicType(v.Type)
		if err != nil {
			return nil, err
		}
		dynamic[i] = dyn
		if dyn {
			tails[i] = enc
			headSize += abiWord
		} else {
			heads[i] = enc
			headSize += len(enc)
		}
	}

	// Second pass: fill dynamic heads with offsets now that headSize is known.
	offset := headSize
	for i := range values {
		if dynamic[i] {
			heads[i] = encodeUint(big.NewInt(int64(offset)))
			offset += len(tails[i])
		}
	}

	var out []byte
	for i := range values {
		out = append(out, heads[i]...)
	}
	for i := range values {
		if dynamic[i] {
			out = append(out, tails[i]...)
		}
	}
	return out, nil
}

// encodeValue encodes a single value to its (head-or-full) byte form. For dynamic
// types this is the full tail encoding; the caller places offsets in heads.
func encodeValue(v ABIValue) ([]byte, error) {
	t := canonicalType(v.Type)

	if elem, size, ok := parseArray(t); ok {
		return encodeArray(v, elem, size)
	}
	if fields, ok := parseTuple(t); ok {
		return encodeTuple(v, fields)
	}
	return encodeScalar(t, v.Value)
}

func encodeScalar(t string, value any) ([]byte, error) {
	switch {
	case t == "address":
		b, ok := value.([]byte)
		if !ok || len(b) != 20 {
			return nil, fmt.Errorf("%w: address must be 20 bytes", ErrABIValue)
		}
		return leftPad(b, abiWord), nil
	case t == "bool":
		b, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("%w: bool", ErrABIValue)
		}
		n := big.NewInt(0)
		if b {
			n = big.NewInt(1)
		}
		return encodeUint(n), nil
	case t == "string", t == "bytes":
		b, ok := value.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: %s must be []byte", ErrABIValue, t)
		}
		return encodeDynamicBytes(b), nil
	case strings.HasPrefix(t, "uint"), strings.HasPrefix(t, "int"):
		n, ok := value.(*big.Int)
		if !ok {
			return nil, fmt.Errorf("%w: %s must be *big.Int", ErrABIValue, t)
		}
		if strings.HasPrefix(t, "uint") {
			return encodeUint(n), nil
		}
		return encodeInt(n), nil
	case strings.HasPrefix(t, "bytes"):
		b, ok := value.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: %s must be []byte", ErrABIValue, t)
		}
		size, err := fixedBytesSize(t)
		if err != nil {
			return nil, err
		}
		if len(b) != size {
			return nil, fmt.Errorf("%w: %s expects %d bytes, got %d", ErrABIValue, t, size, len(b))
		}
		out := make([]byte, abiWord)
		copy(out, b) // right-padded
		return out, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrABIType, t)
	}
}

// encodeUint left-pads an unsigned big.Int to a 32-byte word.
func encodeUint(n *big.Int) []byte {
	return leftPad(n.Bytes(), abiWord)
}

// encodeInt two's-complement encodes a signed big.Int to a 32-byte word.
func encodeInt(n *big.Int) []byte {
	if n.Sign() >= 0 {
		return leftPad(n.Bytes(), abiWord)
	}
	// two's complement: 2^256 + n
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	tc := new(big.Int).Add(mod, n)
	return leftPad(tc.Bytes(), abiWord)
}

// encodeDynamicBytes encodes length-prefixed, right-padded bytes/string.
func encodeDynamicBytes(b []byte) []byte {
	out := encodeUint(big.NewInt(int64(len(b))))
	out = append(out, b...)
	if pad := len(b) % abiWord; pad != 0 {
		out = append(out, make([]byte, abiWord-pad)...)
	}
	return out
}

func encodeArray(v ABIValue, elemType string, size int) ([]byte, error) {
	elems, ok := v.Value.([]ABIValue)
	if !ok {
		return nil, fmt.Errorf("%w: array must be []ABIValue", ErrABIValue)
	}
	if size >= 0 && len(elems) != size {
		return nil, fmt.Errorf("%w: fixed array %s expects %d elements", ErrABIValue, v.Type, size)
	}
	// Normalize element types so callers may leave them empty.
	for i := range elems {
		if elems[i].Type == "" {
			elems[i].Type = elemType
		}
	}
	body, err := ABIEncodeParams(elems)
	if err != nil {
		return nil, err
	}
	if size < 0 {
		// dynamic array: length prefix + encoded elements
		return append(encodeUint(big.NewInt(int64(len(elems)))), body...), nil
	}
	return body, nil
}

func encodeTuple(v ABIValue, fieldTypes []string) ([]byte, error) {
	fields, ok := v.Value.([]ABIValue)
	if !ok {
		return nil, fmt.Errorf("%w: tuple must be []ABIValue", ErrABIValue)
	}
	if len(fields) != len(fieldTypes) {
		return nil, fmt.Errorf("%w: tuple %s expects %d fields", ErrABIValue, v.Type, len(fieldTypes))
	}
	for i := range fields {
		if fields[i].Type == "" {
			fields[i].Type = fieldTypes[i]
		}
	}
	return ABIEncodeParams(fields)
}

// ---------- type helpers ----------

// canonicalType normalizes shorthand types: "uint" -> "uint256", "int" -> "int256",
// "byte" -> "bytes1". Whitespace inside tuples is removed.
func canonicalType(t string) string {
	t = strings.TrimSpace(t)
	switch t {
	case "uint":
		return "uint256"
	case "int":
		return "int256"
	case "byte":
		return "bytes1"
	}
	return t
}

// isDynamicType reports whether a type's encoding has a variable size (and so is
// placed in the tail with an offset in the head).
func isDynamicType(t string) (bool, error) {
	t = canonicalType(t)
	if t == "bytes" || t == "string" {
		return true, nil
	}
	if elem, size, ok := parseArray(t); ok {
		if size < 0 {
			return true, nil // dynamic array
		}
		// fixed-size array is dynamic iff its element is dynamic
		return isDynamicType(elem)
	}
	if fields, ok := parseTuple(t); ok {
		for _, f := range fields {
			dyn, err := isDynamicType(f)
			if err != nil {
				return false, err
			}
			if dyn {
				return true, nil
			}
		}
		return false, nil
	}
	return false, nil
}

// parseArray splits "T[]" -> (T, -1, true) and "T[k]" -> (T, k, true). It returns
// ok=false for non-array types. It matches the outermost (rightmost) brackets so
// nested arrays like "uint256[2][]" parse correctly.
func parseArray(t string) (elem string, size int, ok bool) {
	if !strings.HasSuffix(t, "]") {
		return "", 0, false
	}
	open := strings.LastIndexByte(t, '[')
	if open < 0 {
		return "", 0, false
	}
	inner := t[open+1 : len(t)-1]
	if inner == "" {
		return t[:open], -1, true
	}
	n := 0
	for _, c := range inner {
		if c < '0' || c > '9' {
			return "", 0, false
		}
		n = n*10 + int(c-'0')
	}
	return t[:open], n, true
}

// parseTuple splits "(A,B,C)" into its top-level component types, respecting
// nested parentheses and brackets. Returns ok=false for non-tuples.
func parseTuple(t string) ([]string, bool) {
	if !strings.HasPrefix(t, "(") || !strings.HasSuffix(t, "]") && !strings.HasSuffix(t, ")") {
		return nil, false
	}
	// A tuple type may be "(...)" or "(...)[k]"; only treat a bare "(...)" here.
	if !strings.HasPrefix(t, "(") || !strings.HasSuffix(t, ")") {
		return nil, false
	}
	inner := t[1 : len(t)-1]
	if inner == "" {
		return []string{}, true
	}
	var fields []string
	depth := 0
	start := 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case ',':
			if depth == 0 {
				fields = append(fields, inner[start:i])
				start = i + 1
			}
		}
	}
	fields = append(fields, inner[start:])
	return fields, true
}

// fixedBytesSize returns N for "bytesN".
func fixedBytesSize(t string) (int, error) {
	n := strings.TrimPrefix(t, "bytes")
	size := 0
	for _, c := range n {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("%w: %s", ErrABIType, t)
		}
		size = size*10 + int(c-'0')
	}
	if size < 1 || size > 32 {
		return 0, fmt.Errorf("%w: %s (1..32)", ErrABIType, t)
	}
	return size, nil
}

// ---------- decoding ----------

// ABIDecodeParams decodes the head/tail-encoded data for the given tuple of
// types into ABIValues. data must be the argument region (no selector).
func ABIDecodeParams(types []string, data []byte) ([]ABIValue, error) {
	out := make([]ABIValue, len(types))
	headPos := 0
	for i, raw := range types {
		t := canonicalType(raw)
		dyn, err := isDynamicType(t)
		if err != nil {
			return nil, err
		}
		if dyn {
			if headPos+abiWord > len(data) {
				return nil, ErrABIDecode
			}
			offBig := new(big.Int).SetBytes(data[headPos : headPos+abiWord])
			if !offBig.IsInt64() {
				return nil, ErrABIDecode
			}
			off := int(offBig.Int64())
			if off < 0 || off > len(data) {
				return nil, ErrABIDecode
			}
			val, err := decodeValue(t, data, off)
			if err != nil {
				return nil, err
			}
			out[i] = val
			headPos += abiWord
		} else {
			width, err := staticWidth(t)
			if err != nil {
				return nil, err
			}
			if headPos+width > len(data) {
				return nil, ErrABIDecode
			}
			val, err := decodeValue(t, data, headPos)
			if err != nil {
				return nil, err
			}
			out[i] = val
			headPos += width
		}
	}
	return out, nil
}

// ABIDecode decodes input that begins with a 4-byte selector followed by the
// arguments encoded for the given types. The returned selector is the leading
// 4 bytes (not verified against any signature).
func ABIDecode(types []string, input []byte) (selector []byte, values []ABIValue, err error) {
	if len(input) < 4 {
		return nil, nil, ErrABIDecode
	}
	sel := append([]byte(nil), input[:4]...)
	vals, err := ABIDecodeParams(types, input[4:])
	if err != nil {
		return nil, nil, err
	}
	return sel, vals, nil
}

// decodeValue decodes one value of type t whose encoding starts at data[pos].
func decodeValue(t string, data []byte, pos int) (ABIValue, error) {
	if elem, size, ok := parseArray(t); ok {
		return decodeArray(t, elem, size, data, pos)
	}
	if fields, ok := parseTuple(t); ok {
		return decodeTuple(t, fields, data, pos)
	}
	return decodeScalar(t, data, pos)
}

func decodeScalar(t string, data []byte, pos int) (ABIValue, error) {
	if pos+abiWord > len(data) {
		return ABIValue{}, ErrABIDecode
	}
	word := data[pos : pos+abiWord]
	switch {
	case t == "address":
		return ABIValue{Type: t, Value: append([]byte(nil), word[12:]...)}, nil
	case t == "bool":
		return ABIValue{Type: t, Value: new(big.Int).SetBytes(word).Sign() != 0}, nil
	case t == "bytes", t == "string":
		b, err := decodeDynamicBytes(data, pos)
		if err != nil {
			return ABIValue{}, err
		}
		return ABIValue{Type: t, Value: b}, nil
	case strings.HasPrefix(t, "uint"):
		return ABIValue{Type: t, Value: new(big.Int).SetBytes(word)}, nil
	case strings.HasPrefix(t, "int"):
		return ABIValue{Type: t, Value: decodeSigned(word)}, nil
	case strings.HasPrefix(t, "bytes"):
		size, err := fixedBytesSize(t)
		if err != nil {
			return ABIValue{}, err
		}
		return ABIValue{Type: t, Value: append([]byte(nil), word[:size]...)}, nil
	default:
		return ABIValue{}, fmt.Errorf("%w: %s", ErrABIType, t)
	}
}

// decodeSigned interprets a 32-byte word as a two's-complement signed integer.
func decodeSigned(word []byte) *big.Int {
	n := new(big.Int).SetBytes(word)
	// If the high bit is set, subtract 2^256.
	if word[0]&0x80 != 0 {
		mod := new(big.Int).Lsh(big.NewInt(1), 256)
		n.Sub(n, mod)
	}
	return n
}

func decodeDynamicBytes(data []byte, pos int) ([]byte, error) {
	if pos+abiWord > len(data) {
		return nil, ErrABIDecode
	}
	lenBig := new(big.Int).SetBytes(data[pos : pos+abiWord])
	if !lenBig.IsInt64() {
		return nil, ErrABIDecode
	}
	n := int(lenBig.Int64())
	start := pos + abiWord
	if n < 0 || start+n > len(data) {
		return nil, ErrABIDecode
	}
	return append([]byte(nil), data[start:start+n]...), nil
}

func decodeArray(t, elem string, size int, data []byte, pos int) (ABIValue, error) {
	base := pos
	count := size
	if size < 0 {
		if pos+abiWord > len(data) {
			return ABIValue{}, ErrABIDecode
		}
		cBig := new(big.Int).SetBytes(data[pos : pos+abiWord])
		if !cBig.IsInt64() {
			return ABIValue{}, ErrABIDecode
		}
		count = int(cBig.Int64())
		base = pos + abiWord
	}
	if count < 0 {
		return ABIValue{}, ErrABIDecode
	}
	elems := make([]ABIValue, count)
	region := data[base:]
	dyn, err := isDynamicType(elem)
	if err != nil {
		return ABIValue{}, err
	}
	headPos := 0
	for i := 0; i < count; i++ {
		if dyn {
			if headPos+abiWord > len(region) {
				return ABIValue{}, ErrABIDecode
			}
			offBig := new(big.Int).SetBytes(region[headPos : headPos+abiWord])
			if !offBig.IsInt64() {
				return ABIValue{}, ErrABIDecode
			}
			off := int(offBig.Int64())
			if off < 0 || off > len(region) {
				return ABIValue{}, ErrABIDecode
			}
			v, err := decodeValue(elem, region, off)
			if err != nil {
				return ABIValue{}, err
			}
			elems[i] = v
			headPos += abiWord
		} else {
			width, err := staticWidth(elem)
			if err != nil {
				return ABIValue{}, err
			}
			v, err := decodeValue(elem, region, headPos)
			if err != nil {
				return ABIValue{}, err
			}
			elems[i] = v
			headPos += width
		}
	}
	return ABIValue{Type: t, Value: elems}, nil
}

func decodeTuple(t string, fields []string, data []byte, pos int) (ABIValue, error) {
	dyn, err := isDynamicType(t)
	if err != nil {
		return ABIValue{}, err
	}
	region := data
	base := pos
	if dyn {
		region = data[pos:]
		base = 0
	}
	vals, err := decodeTupleRegion(fields, region, base)
	if err != nil {
		return ABIValue{}, err
	}
	return ABIValue{Type: t, Value: vals}, nil
}

// decodeTupleRegion decodes a tuple whose head region starts at base within region.
func decodeTupleRegion(fields []string, region []byte, base int) ([]ABIValue, error) {
	out := make([]ABIValue, len(fields))
	headPos := base
	for i, raw := range fields {
		ft := canonicalType(raw)
		dyn, err := isDynamicType(ft)
		if err != nil {
			return nil, err
		}
		if dyn {
			if headPos+abiWord > len(region) {
				return nil, ErrABIDecode
			}
			offBig := new(big.Int).SetBytes(region[headPos : headPos+abiWord])
			if !offBig.IsInt64() {
				return nil, ErrABIDecode
			}
			// Offsets in a tuple are relative to the start of the tuple region (base).
			off := base + int(offBig.Int64())
			if off < 0 || off > len(region) {
				return nil, ErrABIDecode
			}
			v, err := decodeValue(ft, region, off)
			if err != nil {
				return nil, err
			}
			out[i] = v
			headPos += abiWord
		} else {
			width, err := staticWidth(ft)
			if err != nil {
				return nil, err
			}
			v, err := decodeValue(ft, region, headPos)
			if err != nil {
				return nil, err
			}
			out[i] = v
			headPos += width
		}
	}
	return out, nil
}

// staticWidth returns the encoded byte width of a static type.
func staticWidth(t string) (int, error) {
	t = canonicalType(t)
	if elem, size, ok := parseArray(t); ok {
		if size < 0 {
			return 0, fmt.Errorf("%w: dynamic array has no static width", ErrABIType)
		}
		w, err := staticWidth(elem)
		if err != nil {
			return 0, err
		}
		return w * size, nil
	}
	if fields, ok := parseTuple(t); ok {
		total := 0
		for _, f := range fields {
			w, err := staticWidth(f)
			if err != nil {
				return 0, err
			}
			total += w
		}
		return total, nil
	}
	// All static scalars occupy one word.
	return abiWord, nil
}
