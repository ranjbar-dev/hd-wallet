package hdwallet

import (
	"encoding/hex"
	"strings"
	"testing"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
)

// Cosmos DIRECT-mode bank MsgSend signing verified against Trust Wallet Core's
// Cosmos AnySigner vector (tests/chains/Cosmos/SignerTests.cpp SignTxProtobuf).
// The expected tx_bytes (base64) and 64-byte signature pin the SignDoc protobuf
// serialization and the secp256k1-over-sha256 signature: any wrong byte in the
// TxBody/AuthInfo/SignDoc changes the digest and thus the signature.
func TestSignTxCosmosMsgSend(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHexTx(t, "80e81ea269e66a0a05b11236df7919fb7fbeedba87452d667489d7403a02f005"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txcosmos.SigningInput{
		AccountNumber: 1037,
		ChainId:       "gaia-13003",
		Sequence:      8,
		Memo:          "",
		Fee: &txcosmos.Fee{
			Amount: "200",
			Denom:  "muon",
			Gas:    200000,
		},
		Send: &txcosmos.SendCoinsMessage{
			FromAddress: "cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02",
			ToAddress:   "cosmos1zt50azupanqlfam5afhv3hexwyutnukeh4c573",
			Amount:      "1",
			Denom:       "muon",
		},
	}

	const (
		wantTxBytes = "CowBCokBChwvY29zbW9zLmJhbmsudjFiZXRhMS5Nc2dTZW5kEmkKLWNvc21vczFoc2s2anJ5eXFqZmhwNWRoYzU1dGM5anRja3lneDBlcGg2ZGQwMhItY29zbW9zMXp0NTBhenVwYW5xbGZhbTVhZmh2M2hleHd5dXRudWtlaDRjNTczGgkKBG11b24SATESZQpQCkYKHy9jb3Ntb3MuY3J5cHRvLnNlY3AyNTZrMS5QdWJLZXkSIwohAlcobsPzfTNVe7uqAAsndErJAjqplnyudaGB0f+R+p3FEgQKAggBGAgSEQoLCgRtdW9uEgMyMDAQwJoMGkD54fQAFlekIAnE62hZYl0uQelh/HLv0oQpCciY5Dn8H1SZFuTsrGdu41PH1Uxa4woptCELi/8Ov9yzdeEFAC9H"
		wantSig     = "f9e1f4001657a42009c4eb6859625d2e41e961fc72efd2842909c898e439fc1f549916e4ecac676ee353c7d54c5ae30a29b4210b8bff0ebfdcb375e105002f47"
	)

	out, err := w.SignTransaction(ATOM, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	co, ok := out.(*txcosmos.SigningOutput)
	if !ok {
		t.Fatalf("output type = %T, want *cosmos.SigningOutput", out)
	}
	if co.GetError() != "" {
		t.Fatalf("signing error: %s", co.GetError())
	}
	if got := hex.EncodeToString(co.GetSignature()); got != wantSig {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", got, wantSig)
	}
	if co.GetTxBytes() != wantTxBytes {
		t.Fatalf("tx_bytes mismatch:\n got  %s\n want %s", co.GetTxBytes(), wantTxBytes)
	}
	// tx_id is the Cosmos tx hash: upper-case hex of sha256 over the (locked)
	// TxRaw bytes. Derived from the pinned output to pin and wire-check the field.
	wantTxID := strings.ToUpper(hex.EncodeToString(sha256Sum(co.GetEncoded())))
	if co.GetTxId() != wantTxID {
		t.Fatalf("tx_id mismatch:\n got  %s\n want %s", co.GetTxId(), wantTxID)
	}
}
