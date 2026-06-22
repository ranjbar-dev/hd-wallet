package hdwallet

import (
	"errors"
	"fmt"
)

// Recursive Length Prefix (RLP) encoding/decoding per the Ethereum Yellow Paper,
// Appendix B. RLP is the canonical serialization for everything that goes on the
// Ethereum wire and into transaction/structure hashing: it encodes nested arrays
// of byte strings and nothing else (numbers, addresses, etc. are first reduced to
// their big-endian byte strings by the caller).
//
// This is a pure-Go port of the spec; it adds no dependencies. It is exported as
// the RLPItem tree plus EncodeRLP/DecodeRLP so transaction builders ("Option B")
// can reuse it.

// RLP-related errors.
var (
	// ErrRLPCanonical is returned when a decoded item is not in canonical form
	// (e.g. a leading zero in a length prefix, or a single byte < 0x80 wrapped in
	// a string header). Ethereum requires canonical RLP.
	ErrRLPCanonical = errors.New("hdwallet: non-canonical RLP encoding")
	// ErrRLPTruncated is returned when the input ends before a declared length.
	ErrRLPTruncated = errors.New("hdwallet: truncated RLP input")
	// ErrRLPTrailing is returned by DecodeRLP when bytes remain after one item.
	ErrRLPTrailing = errors.New("hdwallet: trailing bytes after RLP item")
)

// RLPItem is a node in an RLP tree: exactly one of Str (a byte string, a leaf) or
// List (an ordered list of items) is meaningful. IsList selects which. The zero
// value is the empty string item (encodes to 0x80).
type RLPItem struct {
	IsList bool
	Str    []byte
	List   []RLPItem
}

// RLPString builds a leaf RLPItem holding the given bytes.
func RLPString(b []byte) RLPItem { return RLPItem{Str: b} }

// RLPList builds a list RLPItem from the given child items.
func RLPList(items ...RLPItem) RLPItem { return RLPItem{IsList: true, List: items} }

// EncodeRLP encodes an RLP tree to its canonical byte serialization.
func EncodeRLP(item RLPItem) []byte {
	if item.IsList {
		payload := make([]byte, 0, len(item.List))
		for i := range item.List {
			payload = append(payload, EncodeRLP(item.List[i])...)
		}
		return append(encodeLength(len(payload), 0xc0), payload...)
	}
	return encodeBytes(item.Str)
}

// encodeBytes encodes a single byte string per the Yellow Paper string rules.
func encodeBytes(b []byte) []byte {
	// A single byte in [0x00, 0x7f] is its own encoding.
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	out := encodeLength(len(b), 0x80)
	return append(out, b...)
}

// encodeLength produces the RLP length prefix. offset is 0x80 for strings or 0xc0
// for lists. Lengths < 56 are encoded into the first byte; larger lengths use the
// big-endian length of the length.
func encodeLength(length int, offset byte) []byte {
	if length < 56 {
		return []byte{offset + byte(length)}
	}
	lenBytes := bigEndianBytes(uint64(length))
	out := make([]byte, 0, 1+len(lenBytes))
	out = append(out, offset+55+byte(len(lenBytes)))
	out = append(out, lenBytes...)
	return out
}

// bigEndianBytes returns the minimal big-endian encoding of n (no leading zeros).
// For n == 0 it returns a single zero byte; callers that need the empty string
// must handle that case before calling.
func bigEndianBytes(n uint64) []byte {
	if n == 0 {
		return []byte{0}
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n)
		n >>= 8
	}
	return buf[i:]
}

// DecodeRLP decodes a single, complete RLP item. It is strict: the entire input
// must be exactly one canonical item with no trailing bytes.
func DecodeRLP(data []byte) (RLPItem, error) {
	item, rest, err := decodeItem(data)
	if err != nil {
		return RLPItem{}, err
	}
	if len(rest) != 0 {
		return RLPItem{}, ErrRLPTrailing
	}
	return item, nil
}

// decodeItem decodes one item from the front of data and returns the remainder.
func decodeItem(data []byte) (RLPItem, []byte, error) {
	if len(data) == 0 {
		return RLPItem{}, nil, ErrRLPTruncated
	}
	prefix := data[0]
	switch {
	case prefix < 0x80:
		// Single byte, value is itself.
		return RLPItem{Str: []byte{prefix}}, data[1:], nil
	case prefix < 0xb8:
		// Short string, 0..55 bytes.
		return decodeShortString(data, prefix)
	case prefix < 0xc0:
		// Long string, length-of-length encoded.
		return decodeLongString(data, prefix)
	case prefix < 0xf8:
		// Short list.
		return decodeShortList(data, prefix)
	default:
		// Long list.
		return decodeLongList(data, prefix)
	}
}

func decodeShortString(data []byte, prefix byte) (RLPItem, []byte, error) {
	n := int(prefix - 0x80)
	if len(data) < 1+n {
		return RLPItem{}, nil, ErrRLPTruncated
	}
	body := data[1 : 1+n]
	// A single byte < 0x80 must use the single-byte form, not a header.
	if n == 1 && body[0] < 0x80 {
		return RLPItem{}, nil, ErrRLPCanonical
	}
	return RLPItem{Str: append([]byte(nil), body...)}, data[1+n:], nil
}

func decodeLongString(data []byte, prefix byte) (RLPItem, []byte, error) {
	lenOfLen := int(prefix - 0xb7)
	n, err := decodeLengthHeader(data, lenOfLen)
	if err != nil {
		return RLPItem{}, nil, err
	}
	start := 1 + lenOfLen
	if len(data) < start+n {
		return RLPItem{}, nil, ErrRLPTruncated
	}
	// Long form must not be used for lengths that fit the short form.
	if n < 56 {
		return RLPItem{}, nil, ErrRLPCanonical
	}
	return RLPItem{Str: append([]byte(nil), data[start:start+n]...)}, data[start+n:], nil
}

func decodeShortList(data []byte, prefix byte) (RLPItem, []byte, error) {
	n := int(prefix - 0xc0)
	if len(data) < 1+n {
		return RLPItem{}, nil, ErrRLPTruncated
	}
	items, err := decodeList(data[1 : 1+n])
	if err != nil {
		return RLPItem{}, nil, err
	}
	return RLPItem{IsList: true, List: items}, data[1+n:], nil
}

func decodeLongList(data []byte, prefix byte) (RLPItem, []byte, error) {
	lenOfLen := int(prefix - 0xf7)
	n, err := decodeLengthHeader(data, lenOfLen)
	if err != nil {
		return RLPItem{}, nil, err
	}
	start := 1 + lenOfLen
	if len(data) < start+n {
		return RLPItem{}, nil, ErrRLPTruncated
	}
	if n < 56 {
		return RLPItem{}, nil, ErrRLPCanonical
	}
	items, err := decodeList(data[start : start+n])
	if err != nil {
		return RLPItem{}, nil, err
	}
	return RLPItem{IsList: true, List: items}, data[start+n:], nil
}

// decodeLengthHeader reads a big-endian length of lenOfLen bytes following the
// prefix byte, enforcing canonical (no leading zero, minimal) form.
func decodeLengthHeader(data []byte, lenOfLen int) (int, error) {
	if lenOfLen <= 0 || len(data) < 1+lenOfLen {
		return 0, ErrRLPTruncated
	}
	if data[1] == 0 {
		return 0, ErrRLPCanonical // leading zero in length
	}
	n := 0
	for i := 0; i < lenOfLen; i++ {
		n = n<<8 | int(data[1+i])
	}
	if n < 0 {
		return 0, fmt.Errorf("hdwallet: RLP length overflow")
	}
	return n, nil
}

// decodeList decodes a payload consisting of zero or more concatenated items.
func decodeList(payload []byte) ([]RLPItem, error) {
	var items []RLPItem
	for len(payload) > 0 {
		item, rest, err := decodeItem(payload)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
		payload = rest
	}
	return items, nil
}
