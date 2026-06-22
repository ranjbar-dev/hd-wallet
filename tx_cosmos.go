package hdwallet

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// Cosmos SDK transaction signing (DIRECT / protobuf sign mode), single bank
// MsgSend.
//
// Direct mode signs sha256(SignDoc), where:
//
//	SignDoc { 1: body_bytes, 2: auth_info_bytes, 3: chain_id, 4: account_number }
//	TxBody  { 1: messages (repeated Any), 2: memo }
//	  message Any { 1: type_url "/cosmos.bank.v1beta1.MsgSend", 2: value(MsgSend) }
//	  MsgSend { 1: from_address, 2: to_address, 3: amount (repeated Coin) }
//	  Coin    { 1: denom, 2: amount }
//	AuthInfo { 1: signer_infos (repeated SignerInfo), 2: Fee }
//	  SignerInfo { 1: public_key Any, 2: ModeInfo, 3: sequence }
//	    PubKey Any { 1: "/cosmos.crypto.secp256k1.PubKey", 2: { 1: 33-byte key } }
//	    ModeInfo   { 1: Single { 1: mode = SIGN_MODE_DIRECT(1) } }
//	  Fee { 1: amount (repeated Coin), 2: gas_limit }
//
// The signature is the 64-byte r||s secp256k1 signature (canonical low-S). The
// broadcast tx is TxRaw { 1: body_bytes, 2: auth_info_bytes, 3: signatures }.
//
// All messages are serialized by hand with protowire so the bytes match Trust
// Wallet Core / the Cosmos SDK exactly; verified byte-for-byte (including the
// signature) against TWC's Cosmos AnySigner direct-mode vector (tx_cosmos_test.go).

const (
	cosmosMsgSendTypeURL           = "/cosmos.bank.v1beta1.MsgSend"
	cosmosMsgDelegateTypeURL       = "/cosmos.staking.v1beta1.MsgDelegate"
	cosmosMsgUndelegateTypeURL     = "/cosmos.staking.v1beta1.MsgUndelegate"
	cosmosMsgWithdrawRewardTypeURL = "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward"
	cosmosPubKeyTypeURL            = "/cosmos.crypto.secp256k1.PubKey"
	cosmosSignModeDirect           = 1 // SIGN_MODE_DIRECT
)

// signCosmosTx builds, signs and serializes a Cosmos direct-mode transaction
// (one or more bank/staking/distribution messages).
func (w *HDWallet) signCosmosTx(symbol Symbol, index uint32, in *txcosmos.SigningInput) (*txcosmos.SigningOutput, error) {
	fee := in.GetFee()
	if fee == nil {
		return nil, fmt.Errorf("%w: cosmos: missing fee", ErrTxInput)
	}

	anyMsgs, err := cosmosMessageAnys(in)
	if err != nil {
		return nil, err
	}

	pub, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(pub) != 33 {
		return nil, fmt.Errorf("%w: cosmos: expected 33-byte compressed key", ErrTxInput)
	}

	bodyBytes := cosmosTxBody(anyMsgs, in.GetMemo())
	authInfoBytes := cosmosAuthInfo(fee, pub, in.GetSequence())

	// SignDoc { body_bytes, auth_info_bytes, chain_id, account_number }.
	signDoc := cosmosSignDoc(bodyBytes, authInfoBytes, in.GetChainId(), in.GetAccountNumber())
	digest := sha256Sum(signDoc)

	sig, err := w.SignIndex(symbol, index, digest)
	if err != nil {
		return nil, err
	}
	rs := sig.Bytes() // 64-byte r||s
	if len(rs) != 64 {
		return nil, fmt.Errorf("%w: cosmos: expected 64-byte signature", ErrTxInput)
	}

	// TxRaw { 1: body_bytes, 2: auth_info_bytes, 3: signatures }.
	var txRaw []byte
	txRaw = appendBytesField(txRaw, 1, bodyBytes)
	txRaw = appendBytesField(txRaw, 2, authInfoBytes)
	txRaw = appendBytesField(txRaw, 3, rs)

	return &txcosmos.SigningOutput{
		Encoded:   txRaw,
		TxBytes:   base64Std(txRaw),
		Signature: rs,
	}, nil
}

// cosmosTxBody serializes TxBody { 1: messages (repeated Any), 2: memo }.
func cosmosTxBody(anyMsgs [][]byte, memo string) []byte {
	var body []byte
	for _, a := range anyMsgs {
		body = appendBytesField(body, 1, a)
	}
	if memo != "" {
		body = appendStringField(body, 2, memo)
	}
	return body
}

// cosmosMessageAnys resolves the SigningInput's message set to a list of
// serialized google.protobuf.Any messages. The repeated `messages` field takes
// precedence; otherwise the legacy single `send` field is used (back-compat).
func cosmosMessageAnys(in *txcosmos.SigningInput) ([][]byte, error) {
	if msgs := in.GetMessages(); len(msgs) > 0 {
		out := make([][]byte, 0, len(msgs))
		for _, m := range msgs {
			anyMsg, err := cosmosMessageAny(m)
			if err != nil {
				return nil, err
			}
			out = append(out, anyMsg)
		}
		return out, nil
	}
	if send := in.GetSend(); send != nil {
		return [][]byte{cosmosAny(cosmosMsgSendTypeURL, cosmosSendBody(send))}, nil
	}
	return nil, fmt.Errorf("%w: cosmos: no message (set send or messages)", ErrTxInput)
}

// cosmosMessageAny serializes one Message oneof to its google.protobuf.Any.
func cosmosMessageAny(m *txcosmos.Message) ([]byte, error) {
	switch {
	case m.GetSend() != nil:
		return cosmosAny(cosmosMsgSendTypeURL, cosmosSendBody(m.GetSend())), nil
	case m.GetDelegate() != nil:
		return cosmosAny(cosmosMsgDelegateTypeURL, cosmosDelegateBody(m.GetDelegate())), nil
	case m.GetUndelegate() != nil:
		return cosmosAny(cosmosMsgUndelegateTypeURL, cosmosDelegateBody(m.GetUndelegate())), nil
	case m.GetWithdrawReward() != nil:
		return cosmosAny(cosmosMsgWithdrawRewardTypeURL, cosmosWithdrawRewardBody(m.GetWithdrawReward())), nil
	default:
		return nil, fmt.Errorf("%w: cosmos: empty message", ErrTxInput)
	}
}

// cosmosSendBody serializes MsgSend { 1: from, 2: to, 3: amount(Coin) }.
func cosmosSendBody(send *txcosmos.SendCoinsMessage) []byte {
	coin := cosmosCoin(send.GetDenom(), send.GetAmount())
	var msg []byte
	msg = appendStringField(msg, 1, send.GetFromAddress())
	msg = appendStringField(msg, 2, send.GetToAddress())
	msg = appendBytesField(msg, 3, coin)
	return msg
}

// cosmosDelegateBody serializes MsgDelegate/MsgUndelegate
// { 1: delegator, 2: validator, 3: amount(Coin) }.
func cosmosDelegateBody(d *txcosmos.MsgDelegate) []byte {
	coin := cosmosCoin(d.GetDenom(), d.GetAmount())
	var msg []byte
	msg = appendStringField(msg, 1, d.GetDelegatorAddress())
	msg = appendStringField(msg, 2, d.GetValidatorAddress())
	msg = appendBytesField(msg, 3, coin)
	return msg
}

// cosmosWithdrawRewardBody serializes MsgWithdrawDelegatorReward
// { 1: delegator, 2: validator }.
func cosmosWithdrawRewardBody(r *txcosmos.MsgWithdrawReward) []byte {
	var msg []byte
	msg = appendStringField(msg, 1, r.GetDelegatorAddress())
	msg = appendStringField(msg, 2, r.GetValidatorAddress())
	return msg
}

// cosmosAuthInfo serializes AuthInfo { 1: signer_infos[SignerInfo], 2: Fee }.
func cosmosAuthInfo(fee *txcosmos.Fee, pub []byte, sequence uint64) []byte {
	// PubKey Any: value is { 1: 33-byte key }.
	var pubKeyInner []byte
	pubKeyInner = appendBytesField(pubKeyInner, 1, pub)
	pubKeyAny := cosmosAny(cosmosPubKeyTypeURL, pubKeyInner)

	// ModeInfo { 1: Single { 1: mode } }.
	var single []byte
	single = appendVarintField(single, 1, cosmosSignModeDirect)
	var modeInfo []byte
	modeInfo = appendBytesField(modeInfo, 1, single)

	// SignerInfo { 1: public_key, 2: mode_info, 3: sequence }.
	var signerInfo []byte
	signerInfo = appendBytesField(signerInfo, 1, pubKeyAny)
	signerInfo = appendBytesField(signerInfo, 2, modeInfo)
	signerInfo = appendVarintField(signerInfo, 3, sequence)

	// Fee { 1: amount[Coin], 2: gas_limit }.
	feeCoin := cosmosCoin(fee.GetDenom(), fee.GetAmount())
	var feeMsg []byte
	feeMsg = appendBytesField(feeMsg, 1, feeCoin)
	feeMsg = appendVarintField(feeMsg, 2, fee.GetGas())

	var authInfo []byte
	authInfo = appendBytesField(authInfo, 1, signerInfo)
	authInfo = appendBytesField(authInfo, 2, feeMsg)
	return authInfo
}

// cosmosSignDoc serializes SignDoc { body, auth_info, chain_id, account_number }.
func cosmosSignDoc(body, authInfo []byte, chainID string, accountNumber uint64) []byte {
	var doc []byte
	doc = appendBytesField(doc, 1, body)
	doc = appendBytesField(doc, 2, authInfo)
	doc = appendStringField(doc, 3, chainID)
	doc = appendVarintField(doc, 4, accountNumber)
	return doc
}

// cosmosCoin serializes Coin { 1: denom, 2: amount }. amount is a decimal string.
func cosmosCoin(denom, amount string) []byte {
	var coin []byte
	coin = appendStringField(coin, 1, denom)
	coin = appendStringField(coin, 2, amount)
	return coin
}

// cosmosAny serializes google.protobuf.Any { 1: type_url, 2: value }.
func cosmosAny(typeURL string, value []byte) []byte {
	var anyMsg []byte
	anyMsg = appendStringField(anyMsg, 1, typeURL)
	anyMsg = appendBytesField(anyMsg, 2, value)
	return anyMsg
}

// ---- small protowire helpers (shared by Cosmos; safe for other families) ----

// appendBytesField appends a length-delimited (wire type 2) field.
func appendBytesField(dst []byte, field protowire.Number, value []byte) []byte {
	dst = protowire.AppendTag(dst, field, protowire.BytesType)
	return protowire.AppendBytes(dst, value)
}

// appendStringField appends a length-delimited string field.
func appendStringField(dst []byte, field protowire.Number, value string) []byte {
	dst = protowire.AppendTag(dst, field, protowire.BytesType)
	return protowire.AppendString(dst, value)
}

// appendVarintField appends a varint (wire type 0) field.
func appendVarintField(dst []byte, field protowire.Number, value uint64) []byte {
	dst = protowire.AppendTag(dst, field, protowire.VarintType)
	return protowire.AppendVarint(dst, value)
}
