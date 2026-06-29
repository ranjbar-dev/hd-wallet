package hdwallet

import (
	"encoding/json"
	"strings"
)

// ContractABIParam is one named parameter in an ABI function.
type ContractABIParam struct {
	Name string
	Type string
}

// ContractABIFunction is a parsed ABI function entry.
type ContractABIFunction struct {
	Name   string
	Inputs []ContractABIParam
}

// ContractABIMap is a selector-indexed ABI returned by ParseContractABI.
// The key is the 4-byte function selector.
type ContractABIMap map[[4]byte]ContractABIFunction

// ContractCallParam is one decoded parameter: name, type, and decoded value.
// Value holds the same Go types as ABIValue.Value.
type ContractCallParam struct {
	Name  string
	Type  string
	Value any
}

// ParseContractABI parses a JSON ABI array (the format returned by solc) and
// returns a map from 4-byte selector to function definition. Non-function
// entries (events, errors, constructor, fallback) are silently ignored.
func ParseContractABI(jsonABI []byte) (ContractABIMap, error) {
	var entries []struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		Inputs []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal(jsonABI, &entries); err != nil {
		return nil, err
	}
	result := make(ContractABIMap, len(entries))
	for _, e := range entries {
		if e.Type != "function" {
			continue
		}
		fn := ContractABIFunction{
			Name:   e.Name,
			Inputs: make([]ContractABIParam, len(e.Inputs)),
		}
		types := make([]string, len(e.Inputs))
		for i, inp := range e.Inputs {
			fn.Inputs[i] = ContractABIParam{Name: inp.Name, Type: inp.Type}
			types[i] = inp.Type
		}
		var sel [4]byte
		copy(sel[:], ABIFunctionSelector(fn.Name, types))
		result[sel] = fn
	}
	return result, nil
}

// GetFunctionSignature returns the canonical signature string for a function,
// e.g. "transfer(address,uint256)".
func GetFunctionSignature(fn ContractABIFunction) string {
	types := make([]string, len(fn.Inputs))
	for i, p := range fn.Inputs {
		types[i] = canonicalType(p.Type)
	}
	return fn.Name + "(" + strings.Join(types, ",") + ")"
}

// DecodeContractCall decodes ABI calldata using the parsed ABI map.
// Returns the matched function name, the decoded named parameters, and any error.
// Returns ErrABIDecode if calldata is shorter than 4 bytes or the selector is not found.
func DecodeContractCall(abiMap ContractABIMap, calldata []byte) (string, []ContractCallParam, error) {
	if len(calldata) < 4 {
		return "", nil, ErrABIDecode
	}
	var sel [4]byte
	copy(sel[:], calldata[:4])
	fn, ok := abiMap[sel]
	if !ok {
		return "", nil, ErrABIDecode
	}
	types := make([]string, len(fn.Inputs))
	for i, p := range fn.Inputs {
		types[i] = p.Type
	}
	vals, err := ABIDecodeParams(types, calldata[4:])
	if err != nil {
		return "", nil, err
	}
	params := make([]ContractCallParam, len(fn.Inputs))
	for i, p := range fn.Inputs {
		params[i] = ContractCallParam{Name: p.Name, Type: vals[i].Type, Value: vals[i].Value}
	}
	return fn.Name, params, nil
}
