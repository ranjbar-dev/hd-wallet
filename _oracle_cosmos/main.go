// Oracle program: uses the reference cosmos-sdk implementation to build a
// 2-of-3 LegacyAminoMultisig MsgSend transaction and emit every intermediate
// and final byte string as JSON. The output is committed as
// testdata/cosmos_multisig_vector.json and pinned by tx_cosmos_multisig_test.go
// (same pattern as _oracle/ for the go-ethereum EIP-4844/7702 vectors).
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	kmultisig "github.com/cosmos/cosmos-sdk/crypto/keys/multisig"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/crypto/types/multisig"
	sdk "github.com/cosmos/cosmos-sdk/types"
	moduletestutil "github.com/cosmos/cosmos-sdk/types/module/testutil"
	signingtypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/migrations/legacytx"
	"github.com/cosmos/cosmos-sdk/x/bank"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

const (
	chainID       = "cosmoshub-4"
	accountNumber = 1234
	sequence      = 7
	memo          = "hd-wallet multisig vector"
	denom         = "uatom"
	sendAmount    = 1000000
	feeAmount     = 5000
	gasLimit      = 200000
	threshold     = 2
)

type vector struct {
	Threshold       int               `json:"threshold"`
	PubKeysHex      []string          `json:"pubkeys_hex"`
	MultisigAddress string            `json:"multisig_address"`
	AminoPubKeyHex  string            `json:"amino_pubkey_hex"`
	ToAddress       string            `json:"to_address"`
	ChainID         string            `json:"chain_id"`
	AccountNumber   uint64            `json:"account_number"`
	Sequence        uint64            `json:"sequence"`
	Memo            string            `json:"memo"`
	Denom           string            `json:"denom"`
	SendAmount      string            `json:"send_amount"`
	FeeAmount       string            `json:"fee_amount"`
	Gas             uint64            `json:"gas"`
	SignDocJSON     string            `json:"sign_doc_json"`
	SignerIndices   []int             `json:"signer_indices"`
	PartialSigsHex  map[string]string `json:"partial_sigs_hex"`
	TxRawBase64     string            `json:"tx_raw_base64"`
	TxIDHex         string            `json:"tx_id_hex"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// scalarKey returns the secp256k1 private key whose scalar is n (1..255).
func scalarKey(n byte) *secp256k1.PrivKey {
	b := make([]byte, 32)
	b[31] = n
	return &secp256k1.PrivKey{Key: b}
}

func main() {
	var privs []*secp256k1.PrivKey
	var pubs []cryptotypes.PubKey
	var pubsHex []string
	for n := byte(1); n <= 3; n++ {
		p := scalarKey(n)
		privs = append(privs, p)
		pubs = append(pubs, p.PubKey())
		pubsHex = append(pubsHex, hex.EncodeToString(p.PubKey().Bytes()))
	}
	multisigPub := kmultisig.NewLegacyAminoPubKey(threshold, pubs)
	msAddr := sdk.AccAddress(multisigPub.Address()).String()
	toAddr := sdk.AccAddress(scalarKey(4).PubKey().Address()).String()

	msg := banktypes.NewMsgSend(
		sdk.MustAccAddressFromBech32(msAddr),
		sdk.MustAccAddressFromBech32(toAddr),
		sdk.NewCoins(sdk.NewInt64Coin(denom, sendAmount)),
	)
	fee := legacytx.NewStdFee(gasLimit, sdk.NewCoins(sdk.NewInt64Coin(denom, feeAmount))) //nolint:staticcheck // reference amino path
	signBytes := legacytx.StdSignBytes(chainID, accountNumber, sequence, 0, fee, []sdk.Msg{msg}, memo, nil)

	signerIdx := []int{0, 2}
	partials := map[string]string{}
	multisigSig := multisig.NewMultisig(len(pubs))
	for _, i := range signerIdx {
		sig, err := privs[i].Sign(signBytes) // sha256 + RFC6979 low-S, 64-byte r||s
		must(err)
		partials[fmt.Sprint(i)] = hex.EncodeToString(sig)
		sd := &signingtypes.SingleSignatureData{
			SignMode:  signingtypes.SignMode_SIGN_MODE_LEGACY_AMINO_JSON,
			Signature: sig,
		}
		must(multisig.AddSignatureFromPubKey(multisigSig, sd, pubs[i], pubs))
	}

	encCfg := moduletestutil.MakeTestEncodingConfig(bank.AppModuleBasic{})
	txb := encCfg.TxConfig.NewTxBuilder()
	must(txb.SetMsgs(msg))
	txb.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin(denom, feeAmount)))
	txb.SetGasLimit(gasLimit)
	txb.SetMemo(memo)
	must(txb.SetSignatures(signingtypes.SignatureV2{
		PubKey:   multisigPub,
		Data:     multisigSig,
		Sequence: sequence,
	}))
	txBytes, err := encCfg.TxConfig.TxEncoder()(txb.GetTx())
	must(err)
	sum := sha256.Sum256(txBytes)

	v := vector{
		Threshold:       threshold,
		PubKeysHex:      pubsHex,
		MultisigAddress: msAddr,
		AminoPubKeyHex:  hex.EncodeToString(multisigPub.Bytes()),
		ToAddress:       toAddr,
		ChainID:         chainID,
		AccountNumber:   accountNumber,
		Sequence:        sequence,
		Memo:            memo,
		Denom:           denom,
		SendAmount:      fmt.Sprint(sendAmount),
		FeeAmount:       fmt.Sprint(feeAmount),
		Gas:             gasLimit,
		SignDocJSON:     string(signBytes),
		SignerIndices:   signerIdx,
		PartialSigsHex:  partials,
		TxRawBase64:     base64.StdEncoding.EncodeToString(txBytes),
		TxIDHex:         strings.ToUpper(hex.EncodeToString(sum[:])),
	}
	out, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.WriteFile("../testdata/cosmos_multisig_vector.json", append(out, '\n'), 0o644))
	fmt.Println(string(out))
}
