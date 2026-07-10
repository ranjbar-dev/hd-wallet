package hdwallet

// Unified broadcast-payload helper.
//
// BroadcastPayload is the single accessor that returns the exact string each
// chain's RPC endpoint expects, hiding the per-family differences in encoding
// and field naming behind a single call.  It is the output-side complement of
// SignTransaction: given the proto.Message produced by SignTransaction it returns
// the ready-to-submit RPC value for that family.
//
// Dispatch style mirrors TransactionID (tx_txid.go): switch on the concrete
// output type, then validate the chain's family for mismatch detection.
//
// No re-signing, no network I/O — pure formatting over existing output fields.

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
	txdot "github.com/ranjbar-dev/hd-wallet/txproto/polkadot"
	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
	txton "github.com/ranjbar-dev/hd-wallet/txproto/ton"
	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// BroadcastPayload returns the RPC-ready string for submitting a signed
// transaction produced by (*HDWallet).SignTransaction, hiding the per-family
// differences in encoding and field naming behind a single accessor.
//
// chain selects the expected output type; if the concrete type of out does not
// correspond to chain's transaction family, ErrTxInput is returned.
//
// The returned value, by family:
//
//   - EVM (ETH/BNB/MATIC/… and all evmTxChains)
//     "0x"-prefixed lowercase hex of the signed RLP (eth_sendRawTransaction).
//
//   - Bitcoin/UTXO (BTC/LTC/DOGE/DASH/BCH/ZEC/… and all utxoTxChains)
//     Lowercase hex of the signed wire-format tx (sendrawtransaction /
//     sendrawtx).
//
//   - Solana (SOL)
//     Standard (padded) base64 of the signed transaction bytes, suitable for
//     sendTransaction with encoding="base64".
//
//   - Cosmos (ATOM/OSMO/… and all cosmosTxChains; also ethermint EVMOS/INJ)
//     Standard base64 of the TxRaw broadcast bytes (the tx_bytes field of a
//     cosmos.tx.v1beta1.BroadcastTxRequest).
//
//   - Tron (TRX)
//     JSON object accepted by TronGrid POST /wallet/broadcasttransaction:
//     {"txID":"<hex>","raw_data_hex":"<hex>","signature":["<hex>"]}.
//
//   - XRP/Ripple (XRP)
//     Uppercase hex of the signed transaction (the tx_blob parameter of the
//     rippled submit command).
//
//   - Polkadot (DOT)
//     "0x"-prefixed lowercase hex of the signed extrinsic, the exact form
//     accepted by the author_submitExtrinsic RPC method.
//
// Pure formatting over existing output fields — no re-signing, no network I/O.
// A nil or unrecognised out type returns ErrTxInput.
func BroadcastPayload(chain Chain, out proto.Message) (string, error) {
	family := txFamilyOf(chain)

	switch o := out.(type) {
	case *txeth.SigningOutput:
		if family != familyEthereum {
			return "", fmt.Errorf("%w: %s does not produce *ethereum.SigningOutput", ErrTxInput, chain)
		}
		encoded := o.GetEncoded()
		if len(encoded) == 0 {
			return "", fmt.Errorf("%w: ethereum SigningOutput: missing encoded bytes", ErrTxInput)
		}
		return "0x" + bytesToHex(encoded), nil

	case *txbtc.SigningOutput:
		if family != familyBitcoin {
			return "", fmt.Errorf("%w: %s does not produce *bitcoin.SigningOutput", ErrTxInput, chain)
		}
		encoded := o.GetEncoded()
		if len(encoded) == 0 {
			return "", fmt.Errorf("%w: bitcoin SigningOutput: missing encoded bytes", ErrTxInput)
		}
		return bytesToHex(encoded), nil

	case *txsolana.SigningOutput:
		if family != familySolana {
			return "", fmt.Errorf("%w: %s does not produce *solana.SigningOutput", ErrTxInput, chain)
		}
		raw := o.GetRaw()
		if len(raw) == 0 {
			return "", fmt.Errorf("%w: solana SigningOutput: missing raw bytes", ErrTxInput)
		}
		return base64Std(raw), nil

	case *txcosmos.SigningOutput:
		if family != familyCosmos && family != familyCosmosEthermint {
			return "", fmt.Errorf("%w: %s does not produce *cosmos.SigningOutput", ErrTxInput, chain)
		}
		txBytes := o.GetTxBytes()
		if txBytes == "" {
			return "", fmt.Errorf("%w: cosmos SigningOutput: missing tx_bytes", ErrTxInput)
		}
		return txBytes, nil

	case *txtron.SigningOutput:
		if family != familyTron {
			return "", fmt.Errorf("%w: %s does not produce *tron.SigningOutput", ErrTxInput, chain)
		}
		id := o.GetId()
		rawData := o.GetRawData()
		sig := o.GetSignature()
		if len(id) == 0 || len(rawData) == 0 || len(sig) == 0 {
			return "", fmt.Errorf("%w: tron SigningOutput: missing required fields", ErrTxInput)
		}
		// TronGrid /wallet/broadcasttransaction JSON format.  All three fields
		// are lowercase hex strings; the signature is a single-element array.
		return fmt.Sprintf(`{"txID":"%s","raw_data_hex":"%s","signature":["%s"]}`,
			bytesToHex(id), bytesToHex(rawData), bytesToHex(sig)), nil

	case *txripple.SigningOutput:
		if family != familyRipple {
			return "", fmt.Errorf("%w: %s does not produce *ripple.SigningOutput", ErrTxInput, chain)
		}
		encoded := o.GetEncoded()
		if len(encoded) == 0 {
			return "", fmt.Errorf("%w: ripple SigningOutput: missing encoded bytes", ErrTxInput)
		}
		// rippled submit accepts the tx_blob as hex; uppercase matches the form
		// rippled itself uses when returning transaction data.
		return strings.ToUpper(bytesToHex(encoded)), nil

	case *txton.SigningOutput:
		if family != familyTON {
			return "", fmt.Errorf("%w: %s does not produce *ton.SigningOutput", ErrTxInput, chain)
		}
		encoded := o.GetEncoded()
		if encoded == "" {
			return "", fmt.Errorf("%w: ton SigningOutput: missing encoded BoC", ErrTxInput)
		}
		// toncenter sendBocReturnHash accepts the base64 BoC in the "boc" field.
		return encoded, nil

	case *txdot.SigningOutput:
		if family != familyPolkadot {
			return "", fmt.Errorf("%w: %s does not produce *polkadot.SigningOutput", ErrTxInput, chain)
		}
		encodedHex := o.GetEncodedHex()
		if encodedHex == "" {
			return "", fmt.Errorf("%w: polkadot SigningOutput: missing encoded_hex", ErrTxInput)
		}
		// author_submitExtrinsic accepts the "0x"-prefixed hex extrinsic as-is.
		return encodedHex, nil

	default:
		return "", fmt.Errorf("%w: unrecognised SigningOutput type for %s", ErrTxInput, chain)
	}
}
