package hdwallet

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// EIP-712 typed structured data hashing.
//
// The final signing digest is
//
//	keccak256(0x19 || 0x01 || domainSeparator || hashStruct(message))
//
// where domainSeparator = hashStruct("EIP712Domain", domain) and
// hashStruct(s) = keccak256(typeHash(s) || encodeData(s)). Typed data is accepted
// as JSON in the standard MetaMask shape:
//
//	{ "types": {...}, "primaryType": "...", "domain": {...}, "message": {...} }
//
// This is a pure-Go port; it depends only on encoding/json, math/big, and the
// existing keccak256.

// EIP-712-related errors.
var (
	// ErrEIP712 is returned for malformed typed data or unsupported types.
	ErrEIP712 = errors.New("hdwallet: invalid EIP-712 typed data")
)

// eip712Type is one member of a struct type: {name, type}.
type eip712Type struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// eip712TypedData is the decoded MetaMask-shape JSON document.
type eip712TypedData struct {
	Types       map[string][]eip712Type `json:"types"`
	PrimaryType string                  `json:"primaryType"`
	Domain      json.RawMessage         `json:"domain"`
	Message     json.RawMessage         `json:"message"`
}

// EIP712Hash parses MetaMask-shape typed-data JSON and returns the 32-byte
// keccak256 digest to sign (the 0x1901-prefixed hash).
func EIP712Hash(typedDataJSON []byte) ([]byte, error) {
	var td eip712TypedData
	if err := json.Unmarshal(typedDataJSON, &td); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEIP712, err)
	}
	if td.PrimaryType == "" {
		return nil, fmt.Errorf("%w: missing primaryType", ErrEIP712)
	}
	if _, ok := td.Types["EIP712Domain"]; !ok {
		return nil, fmt.Errorf("%w: missing EIP712Domain type", ErrEIP712)
	}

	var domain map[string]json.RawMessage
	if err := json.Unmarshal(td.Domain, &domain); err != nil {
		return nil, fmt.Errorf("%w: domain: %v", ErrEIP712, err)
	}
	domainSep, err := hashStruct(td.Types, "EIP712Domain", domain)
	if err != nil {
		return nil, err
	}

	var message map[string]json.RawMessage
	if err := json.Unmarshal(td.Message, &message); err != nil {
		return nil, fmt.Errorf("%w: message: %v", ErrEIP712, err)
	}
	msgHash, err := hashStruct(td.Types, td.PrimaryType, message)
	if err != nil {
		return nil, err
	}

	preimage := make([]byte, 0, 2+64)
	preimage = append(preimage, 0x19, 0x01)
	preimage = append(preimage, domainSep...)
	preimage = append(preimage, msgHash...)
	return keccak256(preimage), nil
}

// hashStruct computes keccak256(typeHash(primaryType) || encodeData).
func hashStruct(types map[string][]eip712Type, primaryType string, data map[string]json.RawMessage) ([]byte, error) {
	th := typeHash(types, primaryType)
	enc, err := encodeData(types, primaryType, data)
	if err != nil {
		return nil, err
	}
	return keccak256(append(th, enc...)), nil
}

// typeHash returns keccak256 of the canonical encodeType string.
func typeHash(types map[string][]eip712Type, primaryType string) []byte {
	return keccak256([]byte(encodeType(types, primaryType)))
}

// encodeType builds the canonical type string: the primary type's encoding
// followed by every referenced struct type, sorted alphabetically.
func encodeType(types map[string][]eip712Type, primaryType string) string {
	deps := collectDeps(types, primaryType, map[string]bool{})
	// Remove the primary type, sort the rest, then prepend the primary type.
	sorted := make([]string, 0, len(deps))
	for name := range deps {
		if name != primaryType {
			sorted = append(sorted, name)
		}
	}
	sort.Strings(sorted)
	ordered := append([]string{primaryType}, sorted...)

	var sb strings.Builder
	for _, name := range ordered {
		sb.WriteString(name)
		sb.WriteByte('(')
		for i, member := range types[name] {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(member.Type)
			sb.WriteByte(' ')
			sb.WriteString(member.Name)
		}
		sb.WriteByte(')')
	}
	return sb.String()
}

// collectDeps gathers the transitive set of struct type names referenced by
// primaryType (including itself), following array element types too.
func collectDeps(types map[string][]eip712Type, primaryType string, found map[string]bool) map[string]bool {
	if found[primaryType] {
		return found
	}
	members, ok := types[primaryType]
	if !ok {
		return found // not a struct (a base type used as a name); ignore
	}
	found[primaryType] = true
	for _, m := range members {
		base := baseType(m.Type)
		if _, isStruct := types[base]; isStruct {
			collectDeps(types, base, found)
		}
	}
	return found
}

// baseType strips all trailing array brackets from a type ("Person[2][]" -> "Person").
func baseType(t string) string {
	if i := strings.IndexByte(t, '['); i >= 0 {
		return t[:i]
	}
	return t
}

// encodeData encodes the members of a struct value (each as a 32-byte word).
func encodeData(types map[string][]eip712Type, primaryType string, data map[string]json.RawMessage) ([]byte, error) {
	members, ok := types[primaryType]
	if !ok {
		return nil, fmt.Errorf("%w: unknown type %q", ErrEIP712, primaryType)
	}
	out := make([]byte, 0, len(members)*32)
	for _, m := range members {
		raw, present := data[m.Name]
		if !present {
			// Missing member encodes as a zero word's worth of "empty" value.
			raw = json.RawMessage("null")
		}
		word, err := encodeField(types, m.Type, raw)
		if err != nil {
			return nil, fmt.Errorf("%w: field %q: %v", ErrEIP712, m.Name, err)
		}
		out = append(out, word...)
	}
	return out, nil
}

// encodeField encodes a single typed value to its 32-byte EIP-712 word.
func encodeField(types map[string][]eip712Type, typ string, raw json.RawMessage) ([]byte, error) {
	// Arrays: keccak256 of the concatenated encoded elements.
	if elem, isArray := arrayElem(typ); isArray {
		var elems []json.RawMessage
		if err := json.Unmarshal(raw, &elems); err != nil {
			return nil, fmt.Errorf("array %s: %v", typ, err)
		}
		var concat []byte
		for _, e := range elems {
			word, err := encodeField(types, elem, e)
			if err != nil {
				return nil, err
			}
			concat = append(concat, word...)
		}
		return keccak256(concat), nil
	}

	// Nested struct: recurse into hashStruct.
	if _, isStruct := types[typ]; isStruct {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("struct %s: %v", typ, err)
		}
		return hashStruct(types, typ, obj)
	}

	return encodeAtom(typ, raw)
}

// encodeAtom encodes a non-struct, non-array atomic EIP-712 value to 32 bytes.
func encodeAtom(typ string, raw json.RawMessage) ([]byte, error) {
	switch {
	case typ == "string":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("string: %v", err)
		}
		return keccak256([]byte(s)), nil
	case typ == "bytes":
		b, err := decodeBytesValue(raw)
		if err != nil {
			return nil, err
		}
		return keccak256(b), nil
	case typ == "bool":
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			// bools sometimes arrive as strings/ints; tolerate "true"/"1".
			b = parseLooseBool(raw)
		}
		n := big.NewInt(0)
		if b {
			n = big.NewInt(1)
		}
		return leftPad(n.Bytes(), 32), nil
	case typ == "address":
		b, err := decodeAddressValue(raw)
		if err != nil {
			return nil, err
		}
		return leftPad(b, 32), nil
	case strings.HasPrefix(typ, "uint"):
		n, err := decodeIntValue(raw)
		if err != nil {
			return nil, err
		}
		return leftPad(n.Bytes(), 32), nil
	case strings.HasPrefix(typ, "int"):
		n, err := decodeIntValue(raw)
		if err != nil {
			return nil, err
		}
		return encodeInt(n), nil // two's complement, reuses eth_abi helper
	case strings.HasPrefix(typ, "bytes"):
		b, err := decodeBytesValue(raw)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 32)
		copy(out, b) // right-padded fixed bytesN
		return out, nil
	default:
		return nil, fmt.Errorf("%w: unsupported atom type %q", ErrEIP712, typ)
	}
}

// arrayElem returns the element type and true if t is an array type. It strips
// only the outermost (rightmost) bracket pair.
func arrayElem(t string) (string, bool) {
	if !strings.HasSuffix(t, "]") {
		return "", false
	}
	open := strings.LastIndexByte(t, '[')
	if open < 0 {
		return "", false
	}
	return t[:open], true
}

// decodeIntValue accepts a JSON number or a decimal/hex string and returns it as
// a big.Int. EIP-712 values are commonly transmitted as strings to preserve
// precision beyond float64.
func decodeIntValue(raw json.RawMessage) (*big.Int, error) {
	s := strings.TrimSpace(string(raw))
	s = strings.Trim(s, `"`)
	if s == "" || s == "null" {
		return big.NewInt(0), nil
	}
	n := new(big.Int)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if _, ok := n.SetString(s[2:], 16); !ok {
			return nil, fmt.Errorf("%w: bad hex integer %q", ErrEIP712, s)
		}
		return n, nil
	}
	if _, ok := n.SetString(s, 10); !ok {
		return nil, fmt.Errorf("%w: bad integer %q", ErrEIP712, s)
	}
	return n, nil
}

// decodeBytesValue accepts a 0x-hex string (the standard form for bytes).
func decodeBytesValue(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("bytes: %v", err)
	}
	return hexToBytes(s)
}

// decodeAddressValue accepts a 0x-hex 20-byte address string.
func decodeAddressValue(raw json.RawMessage) ([]byte, error) {
	b, err := decodeBytesValue(raw)
	if err != nil {
		return nil, err
	}
	if len(b) != 20 {
		return nil, fmt.Errorf("%w: address must be 20 bytes, got %d", ErrEIP712, len(b))
	}
	return b, nil
}

// hexToBytes decodes an optional-0x-prefixed hex string.
func hexToBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: bad hex %q", ErrEIP712, s)
	}
	return b, nil
}

// parseLooseBool maps "true"/"1" to true and everything else to false.
func parseLooseBool(raw json.RawMessage) bool {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	return s == "true" || s == "1"
}
