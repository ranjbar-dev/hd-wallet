package hdwallet

// "What am I signing?" decoder for Cosmos SDK (protobuf direct-mode) transactions.
//
// DecodeCosmosTx parses a broadcast TxRaw blob back into its plain fields so a
// client can render a confirmation screen WITHOUT touching a private key, a
// derivation path or any secret. It is the inverse of the tx_cosmos.go signer:
//
//	TxRaw    { 1: body_bytes, 2: auth_info_bytes, 3: signatures (repeated) }
//	TxBody   { 1: messages (repeated Any), 2: memo }
//	  Any { 1: type_url, 2: value }
//	    MsgSend          { 1: from, 2: to, 3: amount(repeated Coin) }
//	    MsgDelegate      { 1: delegator, 2: validator, 3: amount(Coin) }
//	    MsgUndelegate    { 1: delegator, 2: validator, 3: amount(Coin) }
//	    MsgWithdrawReward{ 1: delegator, 2: validator }
//	    Coin { 1: denom, 2: amount }
//	AuthInfo { 1: signer_infos (repeated SignerInfo), 2: Fee }
//	  SignerInfo { 1: public_key, 2: mode_info, 3: sequence }
//	  Fee        { 1: amount(repeated Coin), 2: gas_limit }
//
// It reuses google.golang.org/protobuf/encoding/protowire (the same library the
// signer serializes with) via the small pbParse walker defined here, which Tron
// also reuses (tx_decode_tron.go) — mirroring how tx_cosmos.go's appendBytesField
// helpers are shared across the proto families.
//
// This file adds no signer/registry/proto changes; it is display-only. Every read
// is bounds-checked through protowire: malformed/truncated input returns
// ErrTxDecode and the decoder never panics.

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
)

// CosmosCoin is one decoded { denom, amount } coin (amount is a decimal string,
// the on-wire Cosmos representation).
type CosmosCoin struct {
	Denom  string
	Amount string
}

// CosmosMessage is one decoded transaction message. TypeURL is always set; the
// remaining fields are populated according to the message type (only the relevant
// subset is non-empty).
type CosmosMessage struct {
	TypeURL string

	// MsgSend.
	FromAddress string
	ToAddress   string

	// MsgDelegate / MsgUndelegate / MsgWithdrawDelegatorReward.
	DelegatorAddress string
	ValidatorAddress string

	// Amount: MsgSend carries a repeated coin set; MsgDelegate / MsgUndelegate
	// carry a single coin (one element). MsgWithdrawReward carries none.
	Amount []CosmosCoin
}

// CosmosTxFields holds the decoded, display-ready fields of a Cosmos transaction.
type CosmosTxFields struct {
	Messages   []CosmosMessage
	Memo       string
	FeeAmount  []CosmosCoin
	GasLimit   uint64
	Sequence   uint64
	Signatures [][]byte
}

// DecodeCosmosTx decodes a raw (broadcast) Cosmos TxRaw blob into its display
// fields. Malformed or truncated input returns ErrTxDecode; the function never
// panics.
func DecodeCosmosTx(raw []byte) (*CosmosTxFields, error) {
	top, err := pbParse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: cosmos: %v", ErrTxDecode, err)
	}

	bodyBytes, ok := pbFieldBytes(top, 1)
	if !ok {
		return nil, fmt.Errorf("%w: cosmos: missing body_bytes", ErrTxDecode)
	}
	authBytes, ok := pbFieldBytes(top, 2)
	if !ok {
		return nil, fmt.Errorf("%w: cosmos: missing auth_info_bytes", ErrTxDecode)
	}

	f := &CosmosTxFields{Signatures: pbFieldAllBytesCopy(top, 3)}

	if err := decodeCosmosBody(f, bodyBytes); err != nil {
		return nil, err
	}
	if err := decodeCosmosAuthInfo(f, authBytes); err != nil {
		return nil, err
	}
	return f, nil
}

// decodeCosmosBody fills Messages and Memo from the TxBody bytes.
func decodeCosmosBody(f *CosmosTxFields, body []byte) error {
	fields, err := pbParse(body)
	if err != nil {
		return fmt.Errorf("%w: cosmos body: %v", ErrTxDecode, err)
	}
	for _, anyBytes := range pbFieldAll(fields, 1) {
		msg, err := decodeCosmosMessage(anyBytes)
		if err != nil {
			return err
		}
		f.Messages = append(f.Messages, msg)
	}
	if memo, ok := pbFieldBytes(fields, 2); ok {
		f.Memo = string(memo)
	}
	return nil
}

// decodeCosmosMessage decodes one google.protobuf.Any { type_url, value } and the
// inner Msg according to the type URL.
func decodeCosmosMessage(anyBytes []byte) (CosmosMessage, error) {
	fields, err := pbParse(anyBytes)
	if err != nil {
		return CosmosMessage{}, fmt.Errorf("%w: cosmos message: %v", ErrTxDecode, err)
	}
	urlBytes, ok := pbFieldBytes(fields, 1)
	if !ok {
		return CosmosMessage{}, fmt.Errorf("%w: cosmos message: missing type_url", ErrTxDecode)
	}
	value, ok := pbFieldBytes(fields, 2)
	if !ok {
		return CosmosMessage{}, fmt.Errorf("%w: cosmos message: missing value", ErrTxDecode)
	}

	url := string(urlBytes)
	msg := CosmosMessage{TypeURL: url}
	inner, err := pbParse(value)
	if err != nil {
		return CosmosMessage{}, fmt.Errorf("%w: cosmos %s: %v", ErrTxDecode, url, err)
	}

	switch url {
	case cosmosMsgSendTypeURL:
		msg.FromAddress = pbFieldString(inner, 1)
		msg.ToAddress = pbFieldString(inner, 2)
		coins, err := decodeCosmosCoins(inner, 3)
		if err != nil {
			return CosmosMessage{}, err
		}
		msg.Amount = coins
	case cosmosMsgDelegateTypeURL, cosmosMsgUndelegateTypeURL:
		msg.DelegatorAddress = pbFieldString(inner, 1)
		msg.ValidatorAddress = pbFieldString(inner, 2)
		coins, err := decodeCosmosCoins(inner, 3)
		if err != nil {
			return CosmosMessage{}, err
		}
		msg.Amount = coins
	case cosmosMsgWithdrawRewardTypeURL:
		msg.DelegatorAddress = pbFieldString(inner, 1)
		msg.ValidatorAddress = pbFieldString(inner, 2)
	default:
		// Unknown message type: surface the type URL only (no decoded body).
	}
	return msg, nil
}

// decodeCosmosAuthInfo fills FeeAmount, GasLimit and Sequence from the AuthInfo
// bytes (sequence comes from the first signer_info).
func decodeCosmosAuthInfo(f *CosmosTxFields, auth []byte) error {
	fields, err := pbParse(auth)
	if err != nil {
		return fmt.Errorf("%w: cosmos auth_info: %v", ErrTxDecode, err)
	}

	if signerInfos := pbFieldAll(fields, 1); len(signerInfos) > 0 {
		si, err := pbParse(signerInfos[0])
		if err != nil {
			return fmt.Errorf("%w: cosmos signer_info: %v", ErrTxDecode, err)
		}
		f.Sequence, _ = pbFieldVarint(si, 3)
	}

	if feeBytes, ok := pbFieldBytes(fields, 2); ok {
		fee, err := pbParse(feeBytes)
		if err != nil {
			return fmt.Errorf("%w: cosmos fee: %v", ErrTxDecode, err)
		}
		coins, err := decodeCosmosCoins(fee, 1)
		if err != nil {
			return err
		}
		f.FeeAmount = coins
		f.GasLimit, _ = pbFieldVarint(fee, 2)
	}
	return nil
}

// decodeCosmosCoins decodes every repeated Coin { 1: denom, 2: amount } under the
// given field number.
func decodeCosmosCoins(fields []pbField, num protowire.Number) ([]CosmosCoin, error) {
	var coins []CosmosCoin
	for _, cb := range pbFieldAll(fields, num) {
		cf, err := pbParse(cb)
		if err != nil {
			return nil, fmt.Errorf("%w: cosmos coin: %v", ErrTxDecode, err)
		}
		coins = append(coins, CosmosCoin{
			Denom:  pbFieldString(cf, 1),
			Amount: pbFieldString(cf, 2),
		})
	}
	return coins, nil
}

// ---- shared protobuf walker (reused by Tron; see tx_decode_tron.go) ----

// pbField is one parsed top-level protobuf field. For BytesType, bytes holds the
// length-delimited content (a sub-slice of the input). For VarintType / Fixed32 /
// Fixed64, varint holds the integer value.
type pbField struct {
	num    protowire.Number
	typ    protowire.Type
	bytes  []byte
	varint uint64
}

// pbParse parses the top-level fields of a protobuf message in wire order. It
// returns ErrTxDecode on any malformed/truncated field. It does NOT recurse:
// callers re-invoke it on the nested message bytes for the specific fields they
// expect, so recursion depth is bounded by the (fixed) schema, never by attacker
// input.
func pbParse(b []byte) ([]pbField, error) {
	var out []pbField
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, fmt.Errorf("bad tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return nil, fmt.Errorf("bad varint: %w", protowire.ParseError(m))
			}
			out = append(out, pbField{num: num, typ: typ, varint: v})
			b = b[m:]
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, fmt.Errorf("bad length-delimited field: %w", protowire.ParseError(m))
			}
			out = append(out, pbField{num: num, typ: typ, bytes: v})
			b = b[m:]
		case protowire.Fixed32Type:
			v, m := protowire.ConsumeFixed32(b)
			if m < 0 {
				return nil, fmt.Errorf("bad fixed32: %w", protowire.ParseError(m))
			}
			out = append(out, pbField{num: num, typ: typ, varint: uint64(v)})
			b = b[m:]
		case protowire.Fixed64Type:
			v, m := protowire.ConsumeFixed64(b)
			if m < 0 {
				return nil, fmt.Errorf("bad fixed64: %w", protowire.ParseError(m))
			}
			out = append(out, pbField{num: num, typ: typ, varint: v})
			b = b[m:]
		default:
			return nil, fmt.Errorf("unsupported wire type %d", typ)
		}
	}
	return out, nil
}

// pbFieldBytes returns the content of the first BytesType field with the given
// number.
func pbFieldBytes(fields []pbField, num protowire.Number) ([]byte, bool) {
	for _, f := range fields {
		if f.num == num && f.typ == protowire.BytesType {
			return f.bytes, true
		}
	}
	return nil, false
}

// pbFieldString returns the first BytesType field with the given number as a
// string (empty if absent).
func pbFieldString(fields []pbField, num protowire.Number) string {
	if b, ok := pbFieldBytes(fields, num); ok {
		return string(b)
	}
	return ""
}

// pbFieldVarint returns the first VarintType field with the given number.
func pbFieldVarint(fields []pbField, num protowire.Number) (uint64, bool) {
	for _, f := range fields {
		if f.num == num && f.typ == protowire.VarintType {
			return f.varint, true
		}
	}
	return 0, false
}

// pbFieldAll returns the content of every BytesType field with the given number
// (for repeated length-delimited fields).
func pbFieldAll(fields []pbField, num protowire.Number) [][]byte {
	var out [][]byte
	for _, f := range fields {
		if f.num == num && f.typ == protowire.BytesType {
			out = append(out, f.bytes)
		}
	}
	return out
}

// pbFieldAllBytesCopy is pbFieldAll with each element copied, so the result does
// not alias the input buffer (used for surfaced signatures).
func pbFieldAllBytesCopy(fields []pbField, num protowire.Number) [][]byte {
	src := pbFieldAll(fields, num)
	if len(src) == 0 {
		return nil
	}
	out := make([][]byte, len(src))
	for i, b := range src {
		out[i] = append([]byte(nil), b...)
	}
	return out
}
