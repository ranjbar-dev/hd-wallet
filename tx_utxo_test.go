package hdwallet

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// TestSignTxBitcoinCashVector pins our Bitcoin Cash signer byte-for-byte to Trust
// Wallet Core's BitcoinCash SignTransaction vector
// (tests/chains/BitcoinCash/TWBitcoinCashTests.cpp), a mainnet transaction. BCH is
// non-SegWit but signs with a BIP-143 preimage carrying SIGHASH_FORKID (0x41), so
// this exercises the FORKID sighash path and legacy P2PKH serialization at once.
func TestSignTxBitcoinCashVector(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHex(t, "7fdafb9db5bc501f2096e7d13d331dc7a75d9594af3d251313ba8b6200f4e384"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	in := &txbtc.SigningInput{
		HashType:      0x41, // SIGHASH_ALL | SIGHASH_FORKID
		Amount:        600,
		ByteFee:       1,
		ToAddress:     "1Bp9U1ogV3A14FMvKbRJms7ctyso4Z4Tcx",
		ChangeAddress: "1FQc5LdgGHMHEN9nwkjmz6tWkxhPpxBvBU",
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash:     mustHex(t, "e28c2b955293159898e34c6840d99bf4d390e2ee1c6f606939f18ee1e2000d05"),
			OutPointIndex:    2,
			OutPointSequence: 0xffffffff,
			Amount:           5151,
			Script:           mustHex(t, "76a914aff1e0789e5fe316b729577665aa0a04d5b0f8c788ac"),
		}},
	}

	outMsg, err := w.SignTransaction(BCH, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	out := outMsg.(*txbtc.SigningOutput)

	const wantHex = "0100000001e28c2b955293159898e34c6840d99bf4d390e2ee1c6f606939f18ee1e2000d05020000006b483045022100b70d158b43cbcded60e6977e93f9a84966bc0cec6f2dfd1463d1223a90563f0d02207548d081069de570a494d0967ba388ff02641d91cadb060587ead95a98d4e3534121038eab72ec78e639d02758e7860cdec018b49498c307791f785aa3019622f4ea5bffffffff0258020000000000001976a914769bdff96a02f9135a1d19b749db6a78fe07dc9088ace5100000000000001976a9149e089b6889e032d46e3b915a3392edfd616fb1c488ac00000000"
	if out.EncodedHex != wantHex {
		t.Fatalf("bch tx hex mismatch\n got: %s\nwant: %s", out.EncodedHex, wantHex)
	}
	if out.Fee != 226 {
		t.Fatalf("bch fee = %d, want 226", out.Fee)
	}
}

// TestSignTxDogecoinOracle / TestSignTxDashOracle assert our DOGE/DASH legacy
// P2PKH transactions are byte-identical to github.com/btcsuite/btcd's signer.
// DOGE and DASH use the exact same legacy SIGHASH_ALL P2PKH sighash as Bitcoin,
// so the btcd oracle (built with Bitcoin params over the same unsigned tx) is a
// valid authority for them (it is NOT for BCH/ZEC, which btcd cannot model).
func TestSignTxDogecoinOracle(t *testing.T) { utxoLegacyOracleTest(t, DOGE) }
func TestSignTxDashOracle(t *testing.T)     { utxoLegacyOracleTest(t, DASH) }

func utxoLegacyOracleTest(t *testing.T, chain Chain) {
	t.Helper()
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(chain, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	utxoScript := p2pkhScript(hash160(pub))

	to, err := w.AddressIndex(chain, 1)
	if err != nil {
		t.Fatalf("AddressIndex(to): %v", err)
	}
	change, err := w.AddressIndex(chain, 2)
	if err != nil {
		t.Fatalf("AddressIndex(change): %v", err)
	}

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

	outMsg, err := w.SignTransaction(chain, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	out := outMsg.(*txbtc.SigningOutput)

	// Re-sign the same unsigned tx with btcd's legacy signer and compare bytes.
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(out.Encoded)); err != nil {
		t.Fatalf("wire deserialize: %v", err)
	}
	var priv *btcec.PrivateKey
	if err := w.WithPrivateKey(chain, 0, func(raw []byte) error {
		priv, _ = btcec.PrivKeyFromBytes(raw)
		return nil
	}); err != nil {
		t.Fatalf("WithPrivateKey: %v", err)
	}
	for i := range msg.TxIn {
		sigScript, err := txscript.SignatureScript(&msg, i, utxoScript, txscript.SigHashAll, priv, true)
		if err != nil {
			t.Fatalf("oracle SignatureScript: %v", err)
		}
		msg.TxIn[i].SignatureScript = sigScript
		msg.TxIn[i].Witness = nil
	}
	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("oracle serialize: %v", err)
	}
	if want := hex.EncodeToString(buf.Bytes()); out.EncodedHex != want {
		t.Fatalf("%s tx hex mismatch\n got: %s\nwant: %s", chain, out.EncodedHex, want)
	}
	if got := hex.EncodeToString(out.TransactionId); got != msg.TxHash().String() {
		t.Fatalf("%s txid = %s, want %s", chain, got, msg.TxHash().String())
	}
}

// TestUtxoTxRouting is the routing-drift guard: every chain in utxoTxChains must
// be a registered coin and must route to familyBitcoin.
func TestUtxoTxRouting(t *testing.T) {
	for s := range utxoTxChains {
		if _, ok := coins[s]; !ok {
			t.Errorf("utxoTxChains member %s is not in the coin registry", s)
		}
		if got := txFamilyOf(s); got != familyBitcoin {
			t.Errorf("txFamilyOf(%s) = %v, want familyBitcoin", s, got)
		}
	}
}

// TestUtxoOutputDecode checks the recipient/change address decoders for the new
// UTXO chains: BCH CashAddr (bare and prefixed) and legacy base58, plus the
// base58 forms for DOGE/DASH/ZEC, each map to the expected scriptPubKey.
func TestUtxoOutputDecode(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	for _, chain := range []Chain{BCH, DOGE, DASH, ZEC} {
		pub, err := w.PublicKeyIndex(chain, 0)
		if err != nil {
			t.Fatalf("PublicKeyIndex(%s): %v", chain, err)
		}
		addr, err := w.AddressIndex(chain, 0) // registry encoder (P2PKH / CashAddr)
		if err != nil {
			t.Fatalf("AddressIndex(%s): %v", chain, err)
		}
		got, err := bitcoinDecodeScript(chain, addr)
		if err != nil {
			t.Fatalf("bitcoinDecodeScript(%s, %q): %v", chain, addr, err)
		}
		if want := p2pkhScript(hash160(pub)); !bytes.Equal(got, want) {
			t.Fatalf("%s decode(%q) = %x, want %x", chain, addr, got, want)
		}
	}

	// The encoder yields a "bitcoincash:"-prefixed CashAddr (covered above); the
	// bare (no-prefix) form must decode identically.
	bchPub, _ := w.PublicKeyIndex(BCH, 0)
	prefixed, _ := w.AddressIndex(BCH, 0)
	bare := prefixed[len("bitcoincash:"):]
	got, err := bitcoinDecodeScript(BCH, bare)
	if err != nil {
		t.Fatalf("bitcoinDecodeScript(BCH, bare): %v", err)
	}
	if want := p2pkhScript(hash160(bchPub)); !bytes.Equal(got, want) {
		t.Fatalf("BCH bare decode = %x, want %x", got, want)
	}
}

// TestSignTxUtxoErrors covers malformed-input rejection for the new chains.
func TestSignTxUtxoErrors(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(DOGE, 0)
	dogeScript := p2pkhScript(hash160(pub))
	dogeTo, _ := w.AddressIndex(DOGE, 1)

	// No UTXOs.
	if _, err := w.SignTransaction(DOGE, 0, &txbtc.SigningInput{Amount: 1, ByteFee: 1, ToAddress: dogeTo}); !errors.Is(err, ErrTxInput) {
		t.Fatalf("no-utxo error = %v, want ErrTxInput", err)
	}

	// Missing to_address.
	if _, err := w.SignTransaction(DOGE, 0, &txbtc.SigningInput{
		Amount: 1, ByteFee: 1,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 10000, Script: dogeScript, OutPointSequence: 0xffffffff}},
	}); !errors.Is(err, ErrTxInput) {
		t.Fatalf("missing-to error = %v, want ErrTxInput", err)
	}

	// Insufficient funds.
	if _, err := w.SignTransaction(DOGE, 0, &txbtc.SigningInput{
		Amount: 1_000_000, ByteFee: 1, ToAddress: dogeTo,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 5000, Script: dogeScript, OutPointSequence: 0xffffffff}},
	}); !errors.Is(err, ErrTxInput) {
		t.Fatalf("insufficient-funds error = %v, want ErrTxInput", err)
	}

	// Bad to_address (not a valid DOGE address).
	if _, err := w.SignTransaction(DOGE, 0, &txbtc.SigningInput{
		Amount: 1, ByteFee: 1, ToAddress: "not-an-address",
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 10000, Script: dogeScript, OutPointSequence: 0xffffffff}},
	}); !errors.Is(err, ErrTxInput) {
		t.Fatalf("bad-to error = %v, want ErrTxInput", err)
	}
}
