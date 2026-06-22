package hdwallet

import (
	"errors"
	"testing"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// TestSignTxBitcoinP2WPKH records the Bitcoin P2WPKH family as roadmap: it is
// intentionally NOT shipped until a native-P2WPKH Trust Wallet Core AnySigner
// vector can be reproduced byte-for-byte (a wrong tx loses funds). The builder
// currently returns ErrTxRoadmap. See tx_roadmap.go for why.
//
// Missing vector (to be filled when an unambiguous native-segwit TWC vector is
// available): a single 0014<hash> P2WPKH UTXO, a bech32 bc1 recipient, an
// explicit fee/change, SIGHASH_ALL, and TWC's exact witness-format expected hex
// (output beginning with the "0001" segwit marker+flag).
func TestSignTxBitcoinP2WPKH(t *testing.T) {
	t.Skip("roadmap: native-P2WPKH Trust Wallet Core AnySigner vector not yet reproduced byte-for-byte; builder returns ErrTxRoadmap")

	// When a vector is available, the shape is:
	//
	//   w, _ := FromPrivateKeyBytes(<twc priv>, Secp256k1)
	//   in := &txbtc.SigningInput{
	//       HashType:      0x01, // SIGHASH_ALL
	//       Amount:        <send sats>,
	//       ByteFee:       <fee/byte>,
	//       ToAddress:     "bc1...",
	//       ChangeAddress: "bc1...",
	//       Utxo: []*txbtc.UnspentTransaction{{
	//           OutPointHash:     <32-byte txid, internal order>,
	//           OutPointIndex:    <vout>,
	//           OutPointSequence: 0xffffffff,
	//           Amount:           <utxo sats>,
	//           Script:           <0014 || 20-byte hash>,
	//       }},
	//   }
	//   out, _ := w.SignTransaction(BTC, 0, in)
	//   // assert out.(*txbtc.SigningOutput).EncodedHex == <twc expected hex>
	_ = (*txbtc.SigningInput)(nil)
}

// TestSignTxBitcoinRoadmapError confirms the family currently reports the roadmap
// sentinel rather than silently producing a (possibly wrong) transaction.
func TestSignTxBitcoinRoadmapError(t *testing.T) {
	w, err := FromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	_, err = w.SignTransaction(BTC, 0, &txbtc.SigningInput{})
	if !errors.Is(err, ErrTxRoadmap) {
		t.Fatalf("BTC SignTransaction error = %v, want ErrTxRoadmap", err)
	}
}
