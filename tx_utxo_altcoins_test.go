package hdwallet

// Tests for the additional Bitcoin-family UTXO altcoins wired in Gap 6. These
// coins add NO new signing logic — only per-coin address params — so each spend
// is proven byte-for-byte against github.com/btcsuite/btcd's signer (the same
// oracle BTC/LTC/DOGE/DASH already use): btcd signs a P2PKH / P2WPKH script
// identically regardless of the coin's address version bytes, so a byte-identical
// re-sign of the exact unsigned tx proves the altcoin spend is correct.
//
// Coins proven here:
//   - native-SegWit (standard BIP-143 P2WPKH): DGB, SYS, VIA, STRAX
//   - legacy-P2PKH  (standard double-SHA256):  QTUM, RVN, FIRO, MONA, PIVX

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// legacyAltcoins are the base58-P2PKH altcoins wired in this gap.
var legacyAltcoins = []Chain{QTUM, RVN, FIRO, MONA, PIVX}

// segwitAltcoins are the native-SegWit altcoins wired in this gap.
var segwitAltcoins = []Chain{DGB, SYS, VIA, STRAX}

// TestSignTxLegacyAltcoinsOracle asserts each legacy-P2PKH altcoin's signed
// transaction is byte-identical to btcd's legacy signer for the same unsigned tx.
func TestSignTxLegacyAltcoinsOracle(t *testing.T) {
	for _, chain := range legacyAltcoins {
		chain := chain
		t.Run(string(chain), func(t *testing.T) {
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

			want := legacyOracleResign(t, w, chain, out.Encoded, utxoScript)
			if out.EncodedHex != want {
				t.Fatalf("%s tx hex mismatch\n got: %s\nwant: %s", chain, out.EncodedHex, want)
			}
		})
	}
}

// TestSignTxSegwitAltcoinsOracle asserts each native-SegWit altcoin's signed
// P2WPKH transaction is byte-identical to btcd's witness signer.
func TestSignTxSegwitAltcoinsOracle(t *testing.T) {
	for _, chain := range segwitAltcoins {
		chain := chain
		t.Run(string(chain), func(t *testing.T) {
			w, err := FromMnemonic(canonicalMnemonic)
			if err != nil {
				t.Fatalf("FromMnemonic: %v", err)
			}
			defer w.Destroy()

			pub, err := w.PublicKeyIndex(chain, 0)
			if err != nil {
				t.Fatalf("PublicKeyIndex: %v", err)
			}
			utxoScript := append([]byte{0x00, 0x14}, hash160(pub)...) // P2WPKH

			// The registry encoder yields the native-SegWit (P2WPKH) address for
			// these coins, which is exactly what we want for recipient/change.
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

			want, msg := segwitOracleResign(t, w, chain, out.Encoded, in.Utxo)
			if out.EncodedHex != want {
				t.Fatalf("%s tx hex mismatch\n got: %s\nwant: %s", chain, out.EncodedHex, want)
			}
			if got := hex.EncodeToString(out.TransactionId); got != msg.TxHash().String() {
				t.Fatalf("%s txid = %s, want %s", chain, got, msg.TxHash().String())
			}
		})
	}
}

// legacyOracleResign deserializes our signed legacy tx, re-signs each input with
// btcd's legacy SignatureScript, and returns the resulting hex. (Legacy P2PKH
// sighash is identical across these chains and Bitcoin, so the Bitcoin-params
// oracle is authoritative.)
func legacyOracleResign(t *testing.T, w *HDWallet, chain Chain, encoded, utxoScript []byte) string {
	t.Helper()
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(encoded)); err != nil {
		t.Fatalf("wire deserialize: %v", err)
	}
	priv := altcoinWalletKey(t, w, chain)
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
	return hex.EncodeToString(buf.Bytes())
}

// segwitOracleResign re-signs every (P2WPKH) input of our signed tx with btcd's
// witness signer and returns the resulting hex plus the parsed message.
func segwitOracleResign(t *testing.T, w *HDWallet, chain Chain, encoded []byte, utxos []*txbtc.UnspentTransaction) (string, *wire.MsgTx) {
	t.Helper()
	var msg wire.MsgTx
	if err := msg.Deserialize(bytes.NewReader(encoded)); err != nil {
		t.Fatalf("wire deserialize: %v", err)
	}

	prevOuts := make(map[wire.OutPoint]*wire.TxOut)
	for _, u := range utxos {
		var h chainhash.Hash
		copy(h[:], u.GetOutPointHash())
		prevOuts[wire.OutPoint{Hash: h, Index: u.GetOutPointIndex()}] = wire.NewTxOut(u.GetAmount(), u.GetScript())
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(&msg, fetcher)
	priv := altcoinWalletKey(t, w, chain)

	for i := range msg.TxIn {
		prevOut := prevOuts[msg.TxIn[i].PreviousOutPoint]
		wit, err := txscript.WitnessSignature(&msg, sigHashes, i, prevOut.Value, prevOut.PkScript, txscript.SigHashAll, priv, true)
		if err != nil {
			t.Fatalf("oracle WitnessSignature: %v", err)
		}
		msg.TxIn[i].Witness = wit
	}

	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		t.Fatalf("oracle serialize: %v", err)
	}
	return hex.EncodeToString(buf.Bytes()), &msg
}

// altcoinWalletKey extracts the (chain,0) secp256k1 private key for the oracle.
func altcoinWalletKey(t *testing.T, w *HDWallet, chain Chain) *btcec.PrivateKey {
	t.Helper()
	var priv *btcec.PrivateKey
	if err := w.WithPrivateKey(chain, 0, func(raw []byte) error {
		priv, _ = btcec.PrivKeyFromBytes(raw)
		return nil
	}); err != nil {
		t.Fatalf("WithPrivateKey: %v", err)
	}
	return priv
}

// TestUtxoAltcoinOutputDecode round-trips each wired altcoin's own recipient
// address (the registry encoder output) back to the expected scriptPubKey, so
// sending coin → same-coin address works for both the input spend and the output.
func TestUtxoAltcoinOutputDecode(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	all := append(append([]Chain{}, legacyAltcoins...), segwitAltcoins...)
	for _, chain := range all {
		pub, err := w.PublicKeyIndex(chain, 0)
		if err != nil {
			t.Fatalf("PublicKeyIndex(%s): %v", chain, err)
		}
		addr, err := w.AddressIndex(chain, 0)
		if err != nil {
			t.Fatalf("AddressIndex(%s): %v", chain, err)
		}
		got, err := bitcoinDecodeScript(chain, addr)
		if err != nil {
			t.Fatalf("bitcoinDecodeScript(%s, %q): %v", chain, addr, err)
		}

		// Native-SegWit coins encode to a P2WPKH (00 14 keyhash) scriptPubKey;
		// the legacy coins encode to P2PKH.
		var want []byte
		if _, segwit := btcAddrParams[chain]; segwit {
			want = append([]byte{0x00, 0x14}, hash160(pub)...)
		} else {
			want = p2pkhScript(hash160(pub))
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s decode(%q) = %x, want %x", chain, addr, got, want)
		}
	}
}

// TestUtxoAltcoinP2SHDecode checks the P2SH version bytes by encoding a P2SH
// address for each wired coin and decoding it back to the expected P2SH script.
func TestUtxoAltcoinP2SHDecode(t *testing.T) {
	scriptHash := make([]byte, 20)
	for i := range scriptHash {
		scriptHash[i] = byte(i + 1)
	}
	wantScript := p2shScript(scriptHash)

	// Legacy/2-byte coins: build the P2SH address from utxoOutParams and decode.
	for _, chain := range legacyAltcoins {
		p := utxoOutParams[chain]
		addr := base58CheckEncode(base58BTC, p.p2shVer, scriptHash)
		got, err := bitcoinDecodeScript(chain, addr)
		if err != nil {
			t.Fatalf("bitcoinDecodeScript(%s P2SH, %q): %v", chain, addr, err)
		}
		if !bytes.Equal(got, wantScript) {
			t.Fatalf("%s P2SH decode(%q) = %x, want %x", chain, addr, got, wantScript)
		}
	}

	// Native-SegWit coins: build the P2SH address from btcAddrParams.
	for _, chain := range segwitAltcoins {
		p := btcAddrParams[chain]
		addr := base58CheckEncode(base58BTC, []byte{p.p2shVer}, scriptHash)
		got, err := bitcoinDecodeScript(chain, addr)
		if err != nil {
			t.Fatalf("bitcoinDecodeScript(%s P2SH, %q): %v", chain, addr, err)
		}
		if !bytes.Equal(got, wantScript) {
			t.Fatalf("%s P2SH decode(%q) = %x, want %x", chain, addr, got, wantScript)
		}
	}
}

// TestUtxoAltcoinTxVersion pins the per-coin transaction version: native-SegWit
// altcoins use version 2, legacy altcoins version 1.
func TestUtxoAltcoinTxVersion(t *testing.T) {
	for _, chain := range segwitAltcoins {
		if v := btcTxVersion(chain); v != 2 {
			t.Errorf("btcTxVersion(%s) = %d, want 2", chain, v)
		}
	}
	for _, chain := range legacyAltcoins {
		if v := btcTxVersion(chain); v != 1 {
			t.Errorf("btcTxVersion(%s) = %d, want 1", chain, v)
		}
	}
}
