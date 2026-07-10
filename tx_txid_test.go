package hdwallet

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"google.golang.org/protobuf/proto"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txeth "github.com/ranjbar-dev/hd-wallet/txproto/ethereum"
	txdot "github.com/ranjbar-dev/hd-wallet/txproto/polkadot"
	txripple "github.com/ranjbar-dev/hd-wallet/txproto/ripple"
	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// TransactionID is the single canonical txid accessor across all signing
// families. Each subtest signs a minimal (TWC-pinned) transaction with the
// canonical test key, then asserts TransactionID(out) round-trips the very id
// the signer already exposed — normalised to lower-case hex with no "0x" for the
// five hash-based families, and returned verbatim (base58) for Solana.
func TestTransactionID(t *testing.T) {
	t.Run("ethereum", func(t *testing.T) {
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
		// Signer stores "0x"+lower-hex; helper strips the prefix.
		want := strings.TrimPrefix(strings.ToLower(eo.GetTxId()), "0x")
		assertTxID(t, out, want)
	})

	t.Run("tron", func(t *testing.T) {
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
		// Byte-typed Id = sha256(raw_data); helper hex-encodes as-is. This is the
		// TWC-pinned txID from tx_tron_test.go.
		want := hex.EncodeToString(to.GetId())
		if want != "dc6f6d9325ee44ab3c00528472be16e1572ab076aa161ccd12515029869d0451" {
			t.Fatalf("unexpected pinned tron id: %s", want)
		}
		assertTxID(t, out, want)
	})

	t.Run("cosmos", func(t *testing.T) {
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
		// Signer stores upper-case hex; helper lower-cases it.
		want := strings.ToLower(co.GetTxId())
		// Independent recomputation: lower-hex(sha256(TxRaw)).
		if recomputed := hex.EncodeToString(sha256Sum(co.GetEncoded())); recomputed != want {
			t.Fatalf("cosmos id recompute mismatch:\n got  %s\n want %s", recomputed, want)
		}
		assertTxID(t, out, want)
	})

	t.Run("ripple", func(t *testing.T) {
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
		// Signer stores upper-case hex; helper lower-cases it.
		want := strings.ToLower(ro.GetTxId())
		if recomputed := hex.EncodeToString(sha512Half(ro.GetEncoded())); recomputed != want {
			t.Fatalf("ripple id recompute mismatch:\n got  %s\n want %s", recomputed, want)
		}
		assertTxID(t, out, want)
	})

	t.Run("solana", func(t *testing.T) {
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
		// Solana id is base58 of the fee-payer signature — returned verbatim
		// (NOT hex-normalised). The signed tx is [u16 count=1][64-byte sig][msg],
		// so the fee-payer signature is raw[1:65].
		want := so.GetTxId()
		if want != base58Encode(base58BTC, so.GetRaw()[1:65]) {
			t.Fatalf("solana id is not the base58 fee-payer signature: %s", want)
		}
		assertTxID(t, out, want)
	})

	t.Run("bitcoin", func(t *testing.T) {
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
		// Byte-typed TransactionId = reverse(sha256d(no-witness)); helper encodes
		// as-is, so it equals the displayed big-endian txid.
		want := hex.EncodeToString(bo.GetTransactionId())
		assertTxID(t, out, want)
	})

	t.Run("polkadot", func(t *testing.T) {
		w, err := FromPrivateKeyBytes(dotTestPrivKey(), Ed25519)
		if err != nil {
			t.Fatalf("FromPrivateKeyBytes: %v", err)
		}
		defer w.Destroy()

		out, err := w.SignTransaction(DOT, 0, dotVectorInput())
		if err != nil {
			t.Fatalf("SignTransaction: %v", err)
		}
		do := out.(*txdot.SigningOutput)
		// Substrate extrinsic hash = BLAKE2b-256(Encoded). Authoritative pin:
		// the on-chain extrinsic hash for this exact (TWC-pinned) extrinsic,
		// per https://polkadot.subscan.io/extrinsic/0x9fd06208a6023e489147d8d93f0182b0cb7e45a40165247319b87278e08362d8
		const wantSubscanHash = "9fd06208a6023e489147d8d93f0182b0cb7e45a40165247319b87278e08362d8"
		if recomputed := hex.EncodeToString(blake2bPersonal(32, nil, do.GetEncoded())); recomputed != wantSubscanHash {
			t.Fatalf("polkadot id recompute mismatch:\n got  %s\n want %s", recomputed, wantSubscanHash)
		}
		assertTxID(t, out, wantSubscanHash)
	})

	t.Run("errors", func(t *testing.T) {
		// A nil proto.Message is an unknown type.
		if _, err := TransactionID(nil); !errors.Is(err, ErrNoTxID) {
			t.Fatalf("nil message error = %v, want ErrNoTxID", err)
		}
		// A proto that is not a recognised SigningOutput (a SigningInput).
		if _, err := TransactionID(&txeth.SigningInput{}); !errors.Is(err, ErrNoTxID) {
			t.Fatalf("unknown type error = %v, want ErrNoTxID", err)
		}
		// A recognised SigningOutput with an empty id field.
		if _, err := TransactionID(&txbtc.SigningOutput{}); !errors.Is(err, ErrNoTxID) {
			t.Fatalf("empty bitcoin id error = %v, want ErrNoTxID", err)
		}
		if _, err := TransactionID(&txeth.SigningOutput{}); !errors.Is(err, ErrNoTxID) {
			t.Fatalf("empty ethereum id error = %v, want ErrNoTxID", err)
		}
		if _, err := TransactionID(&txsolana.SigningOutput{}); !errors.Is(err, ErrNoTxID) {
			t.Fatalf("empty solana id error = %v, want ErrNoTxID", err)
		}
		if _, err := TransactionID(&txdot.SigningOutput{}); !errors.Is(err, ErrNoTxID) {
			t.Fatalf("empty polkadot id error = %v, want ErrNoTxID", err)
		}
	})
}

// assertTxID asserts TransactionID(out) succeeds and equals want.
func assertTxID(t *testing.T, out proto.Message, want string) {
	t.Helper()
	got, err := TransactionID(out)
	if err != nil {
		t.Fatalf("TransactionID: %v", err)
	}
	if got != want {
		t.Fatalf("TransactionID mismatch:\n got  %s\n want %s", got, want)
	}
}
