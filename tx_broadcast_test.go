package hdwallet

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"google.golang.org/protobuf/proto"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// TestBroadcastPayload verifies BroadcastPayload returns the correct
// RPC-ready string for each transaction family. Each sub-test signs with the
// same input as the corresponding per-family signer test (TWC-pinned) so the
// expected payload is derived directly from the signer's output fields rather
// than hard-coded constants — this way the broadcast test and the signer test
// stay in lock-step.
func TestBroadcastPayload(t *testing.T) {
	t.Run("ethereum", func(t *testing.T) {
		// TWC "Vitalik" legacy transfer vector (same key / input as
		// TestSignTxEthereumLegacyNative in tx_ethereum_test.go).
		w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
		defer w.Destroy()

		in := &txeth.SigningInput{
			ChainId:   mustHexTx(t, "01"),
			Nonce:     mustHexTx(t, "09"),
			TxMode:    EthTxModeLegacy,
			GasPrice:  mustHexTx(t, "04a817c800"),
			GasLimit:  mustHexTx(t, "5208"),
			ToAddress: "0x3535353535353535353535353535353535353535",
			Transaction: &txeth.Transaction{
				TransactionOneof: &txeth.Transaction_Transfer_{
					Transfer: &txeth.Transaction_Transfer{
						Amount: mustHexTx(t, "0de0b6b3a7640000"),
					},
				},
			},
		}
		out, err := w.SignTransaction(ETH, 0, in)
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		eo := out.(*txeth.SigningOutput)
		// Expected: "0x" + lower-hex of the signed RLP bytes.
		want := "0x" + eo.GetEncodedHex()

		got, err := BroadcastPayload(ETH, out)
		if err != nil {
			t.Fatalf("BroadcastPayload: %v", err)
		}
		if got != want {
			t.Fatalf("ETH broadcast payload mismatch:\n got  %s\n want %s", got, want)
		}
		if !strings.HasPrefix(got, "0x") {
			t.Fatalf("ETH payload missing 0x prefix: %s", got)
		}
	})

	t.Run("bitcoin", func(t *testing.T) {
		// Same key and UTXO setup as the P2WPKH test in tx_bitcoin_test.go.
		w, err := FromMnemonic(canonicalMnemonic)
		if err != nil {
			t.Fatalf("FromMnemonic: %v", err)
		}
		defer w.Destroy()

		pub, err := w.PublicKeyIndex(BTC, 0)
		if err != nil {
			t.Fatalf("PublicKeyIndex: %v", err)
		}
		utxoScript := append([]byte{0x00, 0x14}, btcutil.Hash160(pub)...)
		to, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 0, 1)
		change, _ := w.BitcoinAddress(BTC, P2WPKH, 0, 1, 0)

		in := &txbtc.SigningInput{
			HashType:      0x01,
			Amount:        1500,
			ByteFee:       1,
			ToAddress:     to,
			ChangeAddress: change,
			Utxo: []*txbtc.UnspentTransaction{{
				OutPointHash:     mustHex(t, dummyPrevTxid),
				OutPointIndex:    0,
				OutPointSequence: 0xffffffff,
				Amount:           10000,
				Script:           utxoScript,
			}},
		}
		out, err := w.SignTransaction(BTC, 0, in)
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		bo := out.(*txbtc.SigningOutput)
		// Expected: lower-hex of the signed wire-format tx (no 0x prefix).
		want := bo.GetEncodedHex()

		got, err := BroadcastPayload(BTC, out)
		if err != nil {
			t.Fatalf("BroadcastPayload: %v", err)
		}
		if got != want {
			t.Fatalf("BTC broadcast payload mismatch:\n got  %s\n want %s", got, want)
		}
		if strings.HasPrefix(got, "0x") {
			t.Fatalf("BTC payload must not have 0x prefix: %s", got)
		}
	})

	t.Run("solana", func(t *testing.T) {
		// Same key and transfer input as TestSignTxSolanaTransfer.
		priv, err := base58Decode(base58BTC, "A7psj2GW7ZMdY4E5hJq14KMeYg7HFjULSsWSrTXZLvYr")
		if err != nil {
			t.Fatalf("base58 decode private key: %v", err)
		}
		w, err := FromPrivateKeyBytes(priv, Ed25519)
		if err != nil {
			t.Fatalf("FromPrivateKeyBytes: %v", err)
		}
		defer w.Destroy()

		in := &txsolana.SigningInput{
			RecentBlockhash: "11111111111111111111111111111111",
			TransactionType: &txsolana.SigningInput_TransferTransaction{
				TransferTransaction: &txsolana.Transfer{
					Recipient: "EN2sCsJ1WDV8UFqsiTXHcUPUxQ4juE71eCknHYYMifkd",
					Value:     42,
				},
			},
		}
		out, err := w.SignTransaction(SOL, 0, in)
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		so := out.(*txsolana.SigningOutput)
		// Expected: standard (padded) base64 of the raw signed transaction bytes.
		want := base64.StdEncoding.EncodeToString(so.GetRaw())

		got, err := BroadcastPayload(SOL, out)
		if err != nil {
			t.Fatalf("BroadcastPayload: %v", err)
		}
		if got != want {
			t.Fatalf("SOL broadcast payload mismatch:\n got  %s\n want %s", got, want)
		}
		// The TWC-pinned base58 encoded tx from TestSignTxSolanaTransfer is
		// "3p2kzZ1…"; the base64 form is a different encoding of the same bytes.
		// Verify the round-trip: decode our base64 and re-encode the first 65
		// bytes as base58 — must match the signer's own tx_id.
		raw, err := base64.StdEncoding.DecodeString(got)
		if err != nil {
			t.Fatalf("base64 decode broadcast payload: %v", err)
		}
		txID := base58Encode(base58BTC, raw[1:65])
		if txID != so.GetTxId() {
			t.Fatalf("Solana round-trip txid mismatch:\n got  %s\n want %s", txID, so.GetTxId())
		}
	})

	t.Run("cosmos", func(t *testing.T) {
		// Same key and MsgSend input as TestSignTxCosmosMsgSend.
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
		out, err := w.SignTransaction(ATOM, 0, in)
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		co := out.(*txcosmos.SigningOutput)
		// Expected: the signer's tx_bytes field — already standard base64 of the
		// TxRaw broadcast bytes (cosmos.tx.v1beta1.BroadcastTxRequest.tx_bytes).
		want := co.GetTxBytes()

		got, err := BroadcastPayload(ATOM, out)
		if err != nil {
			t.Fatalf("BroadcastPayload: %v", err)
		}
		if got != want {
			t.Fatalf("ATOM broadcast payload mismatch:\n got  %s\n want %s", got, want)
		}
		// Confirm it is valid base64 that decodes to the raw TxRaw bytes (the
		// signer stores those in the Encoded field).
		decoded, err := base64.StdEncoding.DecodeString(got)
		if err != nil {
			t.Fatalf("base64 decode cosmos broadcast payload: %v", err)
		}
		if string(decoded) != string(co.GetEncoded()) {
			t.Fatalf("cosmos broadcast payload decode mismatch with GetEncoded()")
		}
		// TWC-pinned tx_bytes from TestSignTxCosmosMsgSend (spot-check prefix).
		const wantPinnedPrefix = "CowBCok"
		if !strings.HasPrefix(got, wantPinnedPrefix) {
			t.Fatalf("ATOM payload prefix mismatch:\n got  %.30s\n want prefix %s", got, wantPinnedPrefix)
		}
	})

	t.Run("tron", func(t *testing.T) {
		// Same key and TransferContract input as TestSignTxTronTransfer.
		w, err := FromPrivateKeyBytes(
			mustHexTx(t, "ba005cd605d8a02e3d5dfd04234cef3a3ee4f76bfbad2722d1fb5af8e12e6764"),
			Secp256k1,
		)
		if err != nil {
			t.Fatalf("FromPrivateKeyBytes: %v", err)
		}
		defer w.Destroy()

		in := &txtron.SigningInput{
			Transaction: &txtron.Transaction{
				Timestamp:  1539295479000,
				Expiration: 1539331479000,
				BlockHeader: &txtron.BlockHeader{
					Timestamp:      1539295479000,
					TxTrieRoot:     mustHexTx(t, "64288c2db0641316762a99dbb02ef7c90f968b60f9f2e410835980614332f86d"),
					ParentHash:     mustHexTx(t, "00000000002f7b3af4f5f8b9e23a30c530f719f165b742e7358536b280eead2d"),
					Number:         3111739,
					WitnessAddress: mustHexTx(t, "415863f6091b8e71766da808b1dd3159790f61de7d"),
					Version:        3,
				},
				ContractOneof: &txtron.Transaction_Transfer{
					Transfer: &txtron.TransferContract{
						OwnerAddress: "415cd0fb0ab3ce40f3051414c604b27756e69e43db",
						ToAddress:    "41521ea197907927725ef36d70f25f850d1659c7c7",
						Amount:       2000000,
					},
				},
			},
		}
		out, err := w.SignTransaction(TRX, 0, in)
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		to := out.(*txtron.SigningOutput)

		got, err := BroadcastPayload(TRX, out)
		if err != nil {
			t.Fatalf("BroadcastPayload: %v", err)
		}
		// Expected JSON shape: {"txID":"<hex>","raw_data_hex":"<hex>","signature":["<hex>"]}
		wantJSON := fmt.Sprintf(`{"txID":"%s","raw_data_hex":"%s","signature":["%s"]}`,
			bytesToHex(to.GetId()),
			bytesToHex(to.GetRawData()),
			bytesToHex(to.GetSignature()),
		)
		if got != wantJSON {
			t.Fatalf("TRX broadcast payload mismatch:\n got  %s\n want %s", got, wantJSON)
		}
		// TWC-pinned txID (TestSignTxTronTransfer): sha256(raw_data).
		const wantTxID = "dc6f6d9325ee44ab3c00528472be16e1572ab076aa161ccd12515029869d0451"
		if !strings.Contains(got, `"txID":"`+wantTxID+`"`) {
			t.Fatalf("TRX broadcast payload does not contain TWC txID %s", wantTxID)
		}
	})

	t.Run("ripple", func(t *testing.T) {
		// Same key and Payment input as TestSignTxRipplePayment.
		w, err := FromPrivateKeyBytes(
			mustHexTx(t, "a5576c0f63da10e584568c8d134569ff44017b0a249eb70657127ae04f38cc77"),
			Secp256k1,
		)
		if err != nil {
			t.Fatalf("FromPrivateKeyBytes: %v", err)
		}
		defer w.Destroy()

		in := &txripple.SigningInput{
			Fee:                10,
			Sequence:           32268248,
			LastLedgerSequence: 32268269,
			Account:            "rfxdLwsZnoespnTDDb1Xhvbc8EFNdztaoq",
			Transaction: &txripple.SigningInput_Payment{Payment: &txripple.Payment{
				Amount:      10,
				Destination: "rU893viamSnsfP3zjzM2KPxjqZjXSXK6VF",
			}},
		}
		out, err := w.SignTransaction(XRP, 0, in)
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		ro := out.(*txripple.SigningOutput)
		// Expected: uppercase hex of the signed serialized tx (rippled submit tx_blob).
		want := strings.ToUpper(ro.GetEncodedHex())

		got, err := BroadcastPayload(XRP, out)
		if err != nil {
			t.Fatalf("BroadcastPayload: %v", err)
		}
		if got != want {
			t.Fatalf("XRP broadcast payload mismatch:\n got  %s\n want %s", got, want)
		}
		// TWC-pinned blob from TestSignTxRipplePayment (uppercase of the lower-hex).
		const wantPinned = "12000022000000002401EC5FD8201B01EC5FED61400000000000000A68400000000000000A732103D13E1152965A51A4A9FD9A8B4EA3DD82A4EBA6B25FCAD5F460A2342BB650333F74463044022037D32835C9394F39B2CFD4EAF5B0A80E0DB397ACE06630FA2B099FF73E425DBC02205288F780330B7A88A1980FA83C647B5908502AD7DE9A44500C08F0750B0D9E8481144C55F5A78067206507580BE7BB2686C8460ADFF983148132E4E20AECF29090AC428A9C43F230A829220D"
		if got != wantPinned {
			t.Fatalf("XRP broadcast payload does not match TWC-pinned blob:\n got  %s\n want %s", got, wantPinned)
		}
	})

	t.Run("evm_alias_bnb", func(t *testing.T) {
		// BNB is in evmTxChains — BroadcastPayload should accept it with an
		// ethereum.SigningOutput and return "0x"-prefixed hex.
		w := ethWallet(t, "0x4646464646464646464646464646464646464646464646464646464646464646")
		defer w.Destroy()

		in := &txeth.SigningInput{
			ChainId:   mustHexTx(t, "38"),
			Nonce:     mustHexTx(t, "00"),
			GasPrice:  mustHexTx(t, "04a817c800"),
			GasLimit:  mustHexTx(t, "5208"),
			ToAddress: "0x3535353535353535353535353535353535353535",
			Transaction: &txeth.Transaction{
				TransactionOneof: &txeth.Transaction_Transfer_{
					Transfer: &txeth.Transaction_Transfer{Amount: mustHexTx(t, "0de0b6b3a7640000")},
				},
			},
		}
		out, err := w.SignTransaction(BNB, 0, in)
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		got, err := BroadcastPayload(BNB, out)
		if err != nil {
			t.Fatalf("BroadcastPayload(BNB): %v", err)
		}
		if !strings.HasPrefix(got, "0x") {
			t.Fatalf("BNB payload missing 0x prefix: %s", got)
		}
	})
}

// TestBroadcastPayloadErrors verifies that BroadcastPayload returns ErrTxInput
// for wrong/nil output types, mismatched chain/family, and empty required fields.
func TestBroadcastPayloadErrors(t *testing.T) {
	t.Run("nil_message", func(t *testing.T) {
		if _, err := BroadcastPayload(ETH, nil); !errors.Is(err, ErrTxInput) {
			t.Fatalf("nil proto: want ErrTxInput, got %v", err)
		}
	})

	t.Run("unrecognised_type", func(t *testing.T) {
		// A SigningInput is not a SigningOutput.
		if _, err := BroadcastPayload(ETH, &txeth.SigningInput{}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("unrecognised type: want ErrTxInput, got %v", err)
		}
	})

	t.Run("family_mismatch_eth_output_for_btc", func(t *testing.T) {
		// BTC expects *bitcoin.SigningOutput; passing an eth one is a mismatch.
		if _, err := BroadcastPayload(BTC, &txeth.SigningOutput{EncodedHex: "aa"}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("ETH output for BTC: want ErrTxInput, got %v", err)
		}
	})

	t.Run("family_mismatch_btc_output_for_eth", func(t *testing.T) {
		if _, err := BroadcastPayload(ETH, &txbtc.SigningOutput{EncodedHex: "aa"}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("BTC output for ETH: want ErrTxInput, got %v", err)
		}
	})

	t.Run("empty_ethereum_encoded", func(t *testing.T) {
		if _, err := BroadcastPayload(ETH, &txeth.SigningOutput{}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("empty ETH encoded: want ErrTxInput, got %v", err)
		}
	})

	t.Run("empty_bitcoin_encoded", func(t *testing.T) {
		if _, err := BroadcastPayload(BTC, &txbtc.SigningOutput{}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("empty BTC encoded: want ErrTxInput, got %v", err)
		}
	})

	t.Run("empty_solana_raw", func(t *testing.T) {
		if _, err := BroadcastPayload(SOL, &txsolana.SigningOutput{}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("empty SOL raw: want ErrTxInput, got %v", err)
		}
	})

	t.Run("empty_cosmos_tx_bytes", func(t *testing.T) {
		if _, err := BroadcastPayload(ATOM, &txcosmos.SigningOutput{}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("empty ATOM tx_bytes: want ErrTxInput, got %v", err)
		}
	})

	t.Run("empty_tron_fields", func(t *testing.T) {
		if _, err := BroadcastPayload(TRX, &txtron.SigningOutput{}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("empty TRX fields: want ErrTxInput, got %v", err)
		}
	})

	t.Run("empty_ripple_encoded", func(t *testing.T) {
		if _, err := BroadcastPayload(XRP, &txripple.SigningOutput{}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("empty XRP encoded: want ErrTxInput, got %v", err)
		}
	})

	t.Run("unsupported_chain", func(t *testing.T) {
		// An unregistered chain has no transaction family; the ethereum output type
		// does not match it either, so the default branch fires and returns ErrTxInput.
		if _, err := BroadcastPayload(Chain("NOPE"), &txeth.SigningOutput{}); !errors.Is(err, ErrTxInput) {
			t.Fatalf("unsupported chain: want ErrTxInput, got %v", err)
		}
	})

	t.Run("proto_interface_nil", func(t *testing.T) {
		// Passing the typed nil of a proto.Message interface (not the untyped nil)
		// falls through to the default case as well.
		var msg proto.Message
		if _, err := BroadcastPayload(ETH, msg); !errors.Is(err, ErrTxInput) {
			t.Fatalf("typed-nil proto.Message: want ErrTxInput, got %v", err)
		}
	})
}
