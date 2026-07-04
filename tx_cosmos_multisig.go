package hdwallet

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/bech32"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// Cosmos LegacyAminoMultisig — m-of-n threshold signing for standard
// (secp256k1-keyed) Cosmos SDK chains, single bank MsgSend.
//
// Flow (mirrors the Bitcoin multisig build→sign→combine split):
//
//	addr, _ := CosmosMultisigAddress("cosmos", 2, pubkeys)      // fund this
//	sig0, _ := w0.SignCosmosMultisigPartial(ATOM, 0, in)        // each signer
//	sig2, _ := w2.SignCosmosMultisigPartial(ATOM, 0, in)
//	out, _  := CombineCosmosMultisig(2, pubkeys, in, map[int][]byte{0: sig0, 2: sig2})
//
// Each participant signs sha256 of the LEGACY_AMINO_JSON StdSignDoc (sorted
// keys, no whitespace — the CosmJS/Keplr multisig format; SIGN_MODE 127). The
// combiner assembles AuthInfo with a LegacyAminoPubKey (threshold + ordered
// keys), a CompactBitArray marking which key indices signed, and a
// MultiSignature carrying the partials in ascending key order.
//
// The multisig ADDRESS is sha256(amino(LegacyAminoPubKey))[:20] — amino, NOT
// hash160 like single keys. Everything here is pinned byte-for-byte
// (amino bytes, sign doc, partials, final TxRaw, tx id) to a vector generated
// by the reference cosmos-sdk implementation (_oracle_cosmos/,
// testdata/cosmos_multisig_vector.json). Ethermint-keyed chains (EVMOS/INJ)
// are rejected: their keccak digest + eth_secp256k1 pubkey type has no
// authoritative multisig vector.

const (
	cosmosMultisigPubKeyTypeURL   = "/cosmos.crypto.multisig.LegacyAminoPubKey"
	cosmosSignModeLegacyAminoJSON = 127 // SIGN_MODE_LEGACY_AMINO_JSON
	cosmosMaxMultisigKeys         = 32
)

// Registered amino type prefixes (tendermint crypto codec).
var (
	aminoPrefixPubKeyMultisigThreshold = []byte{0x22, 0xC1, 0xF7, 0xE2} // tendermint/PubKeyMultisigThreshold
	aminoPrefixPubKeySecp256k1         = []byte{0xEB, 0x5A, 0xE9, 0x87} // tendermint/PubKeySecp256k1
)

// validateCosmosMultisigKeys checks threshold and 33-byte compressed keys.
func validateCosmosMultisigKeys(threshold int, pubkeys [][]byte) error {
	if threshold < 1 || threshold > len(pubkeys) || len(pubkeys) > cosmosMaxMultisigKeys {
		return fmt.Errorf("%w: cosmos multisig: invalid threshold %d of %d keys", ErrTxInput, threshold, len(pubkeys))
	}
	for i, pk := range pubkeys {
		if len(pk) != 33 {
			return fmt.Errorf("%w: cosmos multisig: pubkey %d is %d bytes, want 33 compressed", ErrTxInput, i, len(pk))
		}
		if _, err := btcec.ParsePubKey(pk); err != nil {
			return fmt.Errorf("%w: cosmos multisig: pubkey %d: %v", ErrTxInput, i, err)
		}
	}
	return nil
}

// cosmosMultisigAminoBytes encodes LegacyAminoPubKey in amino binary:
// prefix ‖ field-1 uvarint threshold ‖ per-key field-2 bytes(EB5AE987 ‖ 0x21 ‖ key).
// Pinned to the oracle's amino_pubkey_hex.
func cosmosMultisigAminoBytes(threshold int, pubkeys [][]byte) []byte {
	var body []byte
	body = appendVarintField(body, 1, uint64(threshold)) // #nosec G115 -- validated 1..32
	for _, pk := range pubkeys {
		inner := make([]byte, 0, 4+1+33)
		inner = append(inner, aminoPrefixPubKeySecp256k1...)
		inner = append(inner, 0x21)
		inner = append(inner, pk...)
		body = appendBytesField(body, 2, inner)
	}
	return append(append([]byte{}, aminoPrefixPubKeyMultisigThreshold...), body...)
}

// CosmosMultisigAddress returns the bech32 address of an m-of-n
// LegacyAminoMultisig account under hrp (e.g. "cosmos"). Key ORDER matters:
// the same ordered key list must be used for partial-signature indices and
// CombineCosmosMultisig. Pure function, no secrets.
func CosmosMultisigAddress(hrp string, threshold int, pubkeys [][]byte) (string, error) {
	if hrp == "" {
		return "", fmt.Errorf("%w: cosmos multisig: empty hrp", ErrTxInput)
	}
	if err := validateCosmosMultisigKeys(threshold, pubkeys); err != nil {
		return "", err
	}
	payload := sha256Sum(cosmosMultisigAminoBytes(threshold, pubkeys))[:20]
	conv, err := bech32.ConvertBits(payload, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("%w: cosmos multisig: %v", ErrTxInput, err)
	}
	return bech32.Encode(hrp, conv)
}

// cosmosDenomValid enforces the Cosmos SDK coin-denom charset.
func cosmosDenomValid(d string) bool {
	if len(d) < 3 || len(d) > 128 {
		return false
	}
	for i, c := range d {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '/' || c == ':' || c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

func cosmosAmountValid(a string) bool {
	if a == "" {
		return false
	}
	for _, c := range a {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// jsonStr marshals s as a JSON string (handles escaping for memo/chain_id).
func jsonStr(s string) string {
	b, _ := json.Marshal(s) // marshaling a string cannot fail
	return string(b)
}

// cosmosMultisigSignBytes builds the canonical LEGACY_AMINO_JSON StdSignDoc
// for a single MsgSend — byte-identical to cosmos-sdk legacytx.StdSignBytes
// (sorted keys, no whitespace; every numeric field a decimal string). All
// embedded strings are validated or JSON-escaped: no injection is possible.
func cosmosMultisigSignBytes(in *txcosmos.SigningInput) ([]byte, error) {
	send := in.GetSend()
	if send == nil {
		return nil, fmt.Errorf("%w: cosmos multisig: missing send message (only MsgSend is supported)", ErrTxInput)
	}
	fee := in.GetFee()
	if fee == nil {
		return nil, fmt.Errorf("%w: cosmos multisig: missing fee", ErrTxInput)
	}
	for _, addr := range []string{send.GetFromAddress(), send.GetToAddress()} {
		if hrp, _, err := bech32.Decode(addr); err != nil || hrp == "" {
			return nil, fmt.Errorf("%w: cosmos multisig: %q is not a valid bech32 address", ErrTxInput, addr)
		}
	}
	if !cosmosDenomValid(send.GetDenom()) || !cosmosAmountValid(send.GetAmount()) {
		return nil, fmt.Errorf("%w: cosmos multisig: invalid send coin", ErrTxInput)
	}
	if fee.GetAmount() != "" && (!cosmosDenomValid(fee.GetDenom()) || !cosmosAmountValid(fee.GetAmount())) {
		return nil, fmt.Errorf("%w: cosmos multisig: invalid fee coin", ErrTxInput)
	}

	feeCoins := "[]"
	if fee.GetAmount() != "" {
		feeCoins = `[{"amount":"` + fee.GetAmount() + `","denom":"` + fee.GetDenom() + `"}]`
	}
	var b strings.Builder
	b.WriteString(`{"account_number":"`)
	b.WriteString(strconv.FormatUint(in.GetAccountNumber(), 10))
	b.WriteString(`","chain_id":`)
	b.WriteString(jsonStr(in.GetChainId()))
	b.WriteString(`,"fee":{"amount":`)
	b.WriteString(feeCoins)
	b.WriteString(`,"gas":"`)
	b.WriteString(strconv.FormatUint(in.GetFee().GetGas(), 10))
	b.WriteString(`"},"memo":`)
	b.WriteString(jsonStr(in.GetMemo()))
	b.WriteString(`,"msgs":[{"type":"cosmos-sdk/MsgSend","value":{"amount":[{"amount":"`)
	b.WriteString(send.GetAmount())
	b.WriteString(`","denom":"`)
	b.WriteString(send.GetDenom())
	b.WriteString(`"}],"from_address":"`)
	b.WriteString(send.GetFromAddress())
	b.WriteString(`","to_address":"`)
	b.WriteString(send.GetToAddress())
	b.WriteString(`"}}],"sequence":"`)
	b.WriteString(strconv.FormatUint(in.GetSequence(), 10))
	b.WriteString(`"}`)
	return []byte(b.String()), nil
}

// SignCosmosMultisigPartial produces this wallet's partial signature (64-byte
// r‖s over sha256 of the amino-JSON sign doc) for a multisig MsgSend.
// in.Send.FromAddress must be the MULTISIG address and in.AccountNumber /
// in.Sequence the multisig account's values. symbol must be a standard
// (non-Ethermint) Cosmos chain. The derived key is wiped after signing.
func (w *HDWallet) SignCosmosMultisigPartial(symbol Symbol, index uint32, in *txcosmos.SigningInput) ([]byte, error) {
	if _, ethermint := ethermintTxChains[symbol]; ethermint {
		return nil, fmt.Errorf("%w: %s (no authoritative Ethermint multisig vector)", ErrTxUnsupported, symbol)
	}
	if _, ok := cosmosTxChains[symbol]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrTxUnsupported, symbol)
	}
	signBytes, err := cosmosMultisigSignBytes(in)
	if err != nil {
		return nil, err
	}
	sig, err := w.SignIndex(symbol, index, sha256Sum(signBytes))
	if err != nil {
		return nil, err
	}
	rs := sig.Bytes()
	if len(rs) != 64 {
		return nil, fmt.Errorf("%w: cosmos multisig: expected 64-byte signature", ErrTxInput)
	}
	return rs, nil
}

// CombineCosmosMultisig assembles the broadcastable TxRaw from at least
// `threshold` partial signatures, keyed by index into pubkeys (the same
// ordered list used for CosmosMultisigAddress). Every partial is VERIFIED
// against its public key before combining (fund-critical guard). Pure
// function: no wallet, no secrets.
func CombineCosmosMultisig(threshold int, pubkeys [][]byte, in *txcosmos.SigningInput, sigs map[int][]byte) (*txcosmos.SigningOutput, error) {
	if err := validateCosmosMultisigKeys(threshold, pubkeys); err != nil {
		return nil, err
	}
	if len(sigs) < threshold {
		return nil, fmt.Errorf("%w: cosmos multisig: %d signatures for threshold %d", ErrTxInput, len(sigs), threshold)
	}
	fee := in.GetFee()
	if fee == nil {
		return nil, fmt.Errorf("%w: cosmos multisig: missing fee", ErrTxInput)
	}
	send := in.GetSend()
	if send == nil {
		return nil, fmt.Errorf("%w: cosmos multisig: missing send message", ErrTxInput)
	}

	signBytes, err := cosmosMultisigSignBytes(in)
	if err != nil {
		return nil, err
	}
	digest := sha256Sum(signBytes)

	signed := make([]int, 0, len(sigs))
	for idx, sig := range sigs {
		if idx < 0 || idx >= len(pubkeys) {
			return nil, fmt.Errorf("%w: cosmos multisig: signature index %d out of range", ErrTxInput, idx)
		}
		if len(sig) != 64 {
			return nil, fmt.Errorf("%w: cosmos multisig: signature %d is %d bytes, want 64", ErrTxInput, idx, len(sig))
		}
		sigStruct := &Signature{Curve: Secp256k1, R: sig[:32], S: sig[32:64], raw: sig}
		if !Verify(Secp256k1, pubkeys[idx], digest, sigStruct) {
			return nil, fmt.Errorf("%w: cosmos multisig: signature %d does not verify against pubkey %d", ErrTxInput, idx, idx)
		}
		signed = append(signed, idx)
	}
	sort.Ints(signed)

	bodyBytes := cosmosTxBody([][]byte{cosmosAny(cosmosMsgSendTypeURL, cosmosSendBody(send))}, in.GetMemo())
	authInfoBytes := cosmosMultisigAuthInfo(threshold, pubkeys, signed, fee, in.GetSequence())

	// MultiSignature { 1: repeated bytes signatures } in ascending key order.
	var multiSig []byte
	for _, idx := range signed {
		multiSig = appendBytesField(multiSig, 1, sigs[idx])
	}

	var txRaw []byte
	txRaw = appendBytesField(txRaw, 1, bodyBytes)
	txRaw = appendBytesField(txRaw, 2, authInfoBytes)
	txRaw = appendBytesField(txRaw, 3, multiSig)

	txID := strings.ToUpper(bytesToHex(sha256Sum(txRaw)))
	return &txcosmos.SigningOutput{
		Encoded:   txRaw,
		TxBytes:   base64Std(txRaw),
		Signature: multiSig,
		TxId:      txID,
	}, nil
}

// cosmosMultisigAuthInfo serializes AuthInfo for a multisig signer:
// SignerInfo { 1: Any(LegacyAminoPubKey), 2: ModeInfo{ 2: Multi{ 1: CompactBitArray,
// 2: repeated ModeInfo{ 1: Single{ 1: 127 } } } }, 3: sequence }, plus Fee.
func cosmosMultisigAuthInfo(threshold int, pubkeys [][]byte, signed []int, fee *txcosmos.Fee, sequence uint64) []byte {
	// LegacyAminoPubKey proto { 1: threshold, 2: repeated Any(secp256k1 PubKey) }.
	var lapk []byte
	lapk = appendVarintField(lapk, 1, uint64(threshold)) // #nosec G115 -- validated 1..32
	for _, pk := range pubkeys {
		var inner []byte
		inner = appendBytesField(inner, 1, pk)
		lapk = appendBytesField(lapk, 2, cosmosAny(cosmosPubKeyTypeURL, inner))
	}
	pubKeyAny := cosmosAny(cosmosMultisigPubKeyTypeURL, lapk)

	// CompactBitArray { 1: extra_bits_stored, 2: elems }; bit i is MSB-first.
	bits := len(pubkeys)
	elems := make([]byte, (bits+7)/8)
	for _, idx := range signed {
		elems[idx/8] |= 0x80 >> (idx % 8) // #nosec G115 -- idx validated < bits <= 32
	}
	var cba []byte
	cba = appendVarintField(cba, 1, uint64(bits%8)) // #nosec G115 -- bits <= 32
	cba = appendBytesField(cba, 2, elems)

	// Multi { 1: bitarray, 2: mode_infos (Single{mode=127} per signature) }.
	var multi []byte
	multi = appendBytesField(multi, 1, cba)
	for range signed {
		var single []byte
		single = appendVarintField(single, 1, cosmosSignModeLegacyAminoJSON)
		var mi []byte
		mi = appendBytesField(mi, 1, single)
		multi = appendBytesField(multi, 2, mi)
	}
	var modeInfo []byte
	modeInfo = appendBytesField(modeInfo, 2, multi) // ModeInfo.multi is field 2

	var signerInfo []byte
	signerInfo = appendBytesField(signerInfo, 1, pubKeyAny)
	signerInfo = appendBytesField(signerInfo, 2, modeInfo)
	signerInfo = appendVarintField(signerInfo, 3, sequence)

	var authInfo []byte
	authInfo = appendBytesField(authInfo, 1, signerInfo)
	authInfo = appendBytesField(authInfo, 2, cosmosFeeBytes(fee))
	return authInfo
}
