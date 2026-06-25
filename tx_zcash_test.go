package hdwallet

import (
	"encoding/hex"
	"testing"

	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// TestSignTxZcashSaplingVector pins our Zcash Sapling v4 / ZIP-243 transparent
// signer byte-for-byte to Trust Wallet Core's Zcash AnySigner vector
// (tests/chains/Zcash/TWAnySignerTests.cpp, "SignSapplingV2"), which was
// broadcast on mainnet (txid ec9033…949256). A single wrong byte in the wire
// format, the personalized BLAKE2b hashes, or the consensus branch id would
// change the signature and fail this assertion.
func TestSignTxZcashSaplingVector(t *testing.T) {
	w, err := FromPrivateKeyBytes(
		mustHex(t, "a9684f5bebd0e1208aae2e02bc9e9163bd1965ad23d8538644e1df8b99b99559"),
		Secp256k1,
	)
	if err != nil {
		t.Fatalf("FromPrivateKeyBytes: %v", err)
	}
	defer w.Destroy()

	pub, err := w.PublicKeyIndex(ZEC, 0)
	if err != nil {
		t.Fatalf("PublicKeyIndex: %v", err)
	}
	// The input is the sender's transparent P2PKH (t1gWVE2uyrET2CxSmCaBiKzmWxQdHhnvMSz).
	utxoScript := p2pkhScript(hash160(pub))

	// TWC sets the out-point hash from the display txid reversed to internal order.
	outPoint := reverseBytes(mustHex(t, "3a19dd44032dfed61bfca5ba5751aab8a107b30609cbd5d70dc5ef09885b6853"))

	in := &txbtc.SigningInput{
		HashType:  0x01,
		Amount:    488000,
		ByteFee:   26, // folds the 124-sat remainder into the fee → single 6000-sat-fee output, matching the vector
		ToAddress: "t1QahNjDdibyE4EdYkawUSKBBcVTSqv64CS",
		Utxo: []*txbtc.UnspentTransaction{{
			OutPointHash:     outPoint,
			OutPointIndex:    0,
			OutPointSequence: 0xffffffff,
			Amount:           494000,
			Script:           utxoScript,
		}},
	}

	outMsg, err := w.SignTransaction(ZEC, 0, in)
	if err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	out := outMsg.(*txbtc.SigningOutput)

	const wantHex = "0400008085202f890153685b8809efc50dd7d5cb0906b307a1b8aa5157baa5fc1bd6fe2d0344dd193a000000006b483045022100ca0be9f37a4975432a52bb65b25e483f6f93d577955290bb7fb0060a93bfc92002203e0627dff004d3c72a957dc9f8e4e0e696e69d125e4d8e275d119001924d3b48012103b243171fae5516d1dc15f9178cfcc5fdc67b0a883055c117b01ba8af29b953f6ffffffff0140720700000000001976a91449964a736f3713d64283fd0018626ba50091c7e988ac00000000000000000000000000000000000000"
	if out.EncodedHex != wantHex {
		t.Fatalf("zcash tx hex mismatch\n got: %s\nwant: %s", out.EncodedHex, wantHex)
	}
	const wantTxid = "ec9033381c1cc53ada837ef9981c03ead1c7c41700ff3a954389cfaddc949256"
	if got := hex.EncodeToString(out.TransactionId); got != wantTxid {
		t.Fatalf("zcash txid = %s, want %s", got, wantTxid)
	}
	if out.Fee != 6000 {
		t.Fatalf("zcash fee = %d, want 6000", out.Fee)
	}
}

// TestSignTxZcashRejectsNonP2PKH confirms a non-transparent-P2PKH input is
// rejected rather than mis-signed (only t-addr P2PKH spending is supported).
func TestSignTxZcashRejectsNonP2PKH(t *testing.T) {
	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatalf("FromMnemonic: %v", err)
	}
	defer w.Destroy()

	pub, _ := w.PublicKeyIndex(ZEC, 0)
	// A native-SegWit script is not a valid Zcash input type.
	p2wpkh := append([]byte{0x00, 0x14}, hash160(pub)...)
	to, _ := w.AddressIndex(ZEC, 1)

	_, err = w.SignTransaction(ZEC, 0, &txbtc.SigningInput{
		Amount: 1000, ByteFee: 1, ToAddress: to,
		Utxo: []*txbtc.UnspentTransaction{{OutPointHash: mustHex(t, dummyPrevTxid), Amount: 100000, Script: p2wpkh, OutPointSequence: 0xffffffff}},
	})
	if err == nil {
		t.Fatal("expected error for non-P2PKH zcash input, got nil")
	}
}
