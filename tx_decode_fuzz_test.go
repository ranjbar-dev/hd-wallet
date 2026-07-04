package hdwallet

// Fuzz coverage for every "what am I signing?" transaction decoder plus the
// JSON-ABI contract-call decoder and the EVM event-log decoder. Each target is
// seeded with real signed-tx bytes copied from (or produced the same way as) that
// decoder's own pinned-vector test, then handed to Go's mutation-based fuzzer.
// None of these decoders should ever panic on attacker-controlled bytes — a
// crash here is fund-critical (a wallet UI calling these to render a
// confirmation screen must not crash on a malformed/malicious blob) — so every
// target's only assertion is "does not panic"; the decoders already return
// ErrTxDecode/ErrABIDecode on malformed input via their own bounds-checked
// cursors.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	txcosmos "github.com/ranjbar-dev/hd-wallet/txproto/cosmos"
	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// fuzzMaxInput caps how large a mutated input the target will actually decode:
// these decoders are for transactions (bytes to low-KB range), not arbitrary
// blobs, so a pathological multi-MB mutation is skipped rather than decoded.
const fuzzMaxInput = 1 << 20

// mustHexBytes hex-decodes a compile-time-known-good literal; it panics on a
// malformed literal (a bug in this test file, never in fuzzer input).
func mustHexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("tx_decode_fuzz_test: bad hex literal: " + err.Error())
	}
	return b
}

// ---------- seed builders (real bytes from each family's own signer/vector) ----------

// fuzzSeedEthereumLegacy is the canonical Vitalik legacy tx hex pinned in
// TestDecodeEthereumVectorLegacy (tx_decode_ethereum_test.go).
func fuzzSeedEthereumLegacy() []byte {
	return mustHexBytes("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
}

// fuzzSeedEthereumERC20 is the pinned legacy ERC-20 DAI transfer from
// TestDecodeEthereumVectorERC20.
func fuzzSeedEthereumERC20() []byte {
	return mustHexBytes("f8aa808509c7652400830130b9946b175474e89094c44da98b954eedeac495271d0f80b844a9059cbb0000000000000000000000005322b34c88ed0691971bf52a7047448f0f4efc840000000000000000000000000000000000000000000000001bc16d674ec8000025a0724c62ad4fbf47346b02de06e603e013f26f26b56fdc0be7ba3d6273401d98cea0032131cae15da7ddcda66963e8bef51ca0d9962bfef0547d3f02597a4a58c931")
}

// fuzzSeedBitcoinTx builds the same minimal valid P2WPKH-output BTC transaction
// used as the malformed-test baseline in TestDecodeBitcoinMalformed
// (tx_decode_bitcoin_test.go): one input spending dummyPrevTxid, one P2WPKH
// output. Real btcd-serialized wire bytes, not made up.
func fuzzSeedBitcoinTx() []byte {
	msg := wire.NewMsgTx(2)
	var prevHash chainhash.Hash
	copy(prevHash[:], mustHexBytes(dummyPrevTxid))
	msg.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevHash, 0), nil, nil))
	msg.AddTxOut(wire.NewTxOut(1000, append([]byte{0x00, 0x14}, bytes.Repeat([]byte{0x11}, 20)...)))
	var buf bytes.Buffer
	if err := msg.Serialize(&buf); err != nil {
		return nil
	}
	return buf.Bytes()
}

// fuzzSeedSolanaTx builds the same hand-constructed Compute Budget
// SetComputeUnitLimit transaction used in TestDecodeSolanaComputeBudget
// (tx_decode_solana_test.go) — a minimal but wire-correct Solana legacy message.
func fuzzSeedSolanaTx() []byte {
	fromKey := make([]byte, 32)
	fromKey[0] = 0x01

	cbKey, err := base58DecodeFixed(solanaComputeBudgetProgramID, 32)
	if err != nil {
		return nil
	}

	data := make([]byte, 5)
	data[0] = 2
	binary.LittleEndian.PutUint32(data[1:5], 200000)

	var msg []byte
	msg = append(msg, 1, 0, 1)                // header
	msg = append(msg, solanaCompactU16(2)...) // 2 account keys
	msg = append(msg, fromKey...)
	msg = append(msg, cbKey...)
	msg = append(msg, make([]byte, 32)...)    // recent blockhash (zeros)
	msg = append(msg, solanaCompactU16(1)...) // 1 instruction
	msg = append(msg, 1)                      // programIdIndex = 1
	msg = append(msg, solanaCompactU16(0)...) // 0 accounts
	msg = append(msg, solanaCompactU16(5)...) // 5 bytes data
	msg = append(msg, data...)

	var tx []byte
	tx = append(tx, solanaCompactU16(1)...) // 1 signature
	tx = append(tx, make([]byte, 64)...)    // fake signature (zeros)
	tx = append(tx, msg...)
	return tx
}

// fuzzSeedCosmosTx signs the same TWC MsgSend vector input as
// TestDecodeCosmosRoundTripMsgSend (tx_decode_cosmos_test.go) with the real
// signer, producing genuine signed TxRaw bytes.
func fuzzSeedCosmosTx() []byte {
	w, err := FromPrivateKeyBytes(
		mustHexBytes("80e81ea269e66a0a05b11236df7919fb7fbeedba87452d667489d7403a02f005"),
		Secp256k1,
	)
	if err != nil {
		return nil
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
		return nil
	}
	return out.(*txcosmos.SigningOutput).GetEncoded()
}

// fuzzSeedTronTx signs the same TWC TransferContract vector input as
// TestDecodeTronRoundTripTransfer (tx_decode_tron_test.go) with the real signer.
func fuzzSeedTronTx() []byte {
	w, err := FromPrivateKeyBytes(
		mustHexBytes("ba005cd605d8a02e3d5dfd04234cef3a3ee4f76bfbad2722d1fb5af8e12e6764"),
		Secp256k1,
	)
	if err != nil {
		return nil
	}
	defer w.Destroy()

	in := &txtron.SigningInput{
		Transaction: &txtron.Transaction{
			Timestamp:  1539295479000,
			Expiration: 1539331479000,
			FeeLimit:   1000000,
			BlockHeader: &txtron.BlockHeader{
				Timestamp:      1539295479000,
				TxTrieRoot:     mustHexBytes("64288c2db0641316762a99dbb02ef7c90f968b60f9f2e410835980614332f86d"),
				ParentHash:     mustHexBytes("00000000002f7b3af4f5f8b9e23a30c530f719f165b742e7358536b280eead2d"),
				Number:         3111739,
				WitnessAddress: mustHexBytes("415863f6091b8e71766da808b1dd3159790f61de7d"),
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
		return nil
	}
	return out.(*txtron.SigningOutput).GetRawData()
}

// fuzzSeedRippleTx is the exact published Trust Wallet Core Ripple AnySigner
// output pinned in TestDecodeRippleVector (tx_decode_ripple_test.go).
func fuzzSeedRippleTx() []byte {
	return mustHexBytes("12000022000000002401ec5fd8201b01ec5fed61400000000000000a68400000000000000a732103d13e1152965a51a4a9fd9a8b4ea3dd82a4eba6b25fcad5f460a2342bb650333f74463044022037d32835c9394f39b2cfd4eaf5b0a80e0db397ace06630fa2b099ff73e425dbc02205288f780330b7a88a1980fa83c647b5908502ad7de9a44500c08f0750b0d9e8481144c55f5a78067206507580be7bb2686c8460adff983148132e4e20aecf29090ac428a9c43f230a829220d")
}

// fuzzApproveJSONABI and fuzzApproveCalldata are the ERC-20 approve vector
// pinned in TestDecodeContractCall_Approve (eth_contractcall_test.go).
const fuzzApproveJSONABI = `[{"name":"approve","type":"function","inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}]}]`

func fuzzApproveCalldata() []byte {
	return mustHexBytes("095ea7b3" +
		"0000000000000000000000005aaeb6053f3e94c9b9a09f33669435e7ef1beaed" +
		"0000000000000000000000000000000000000000000000000000000000000001")
}

// ---------- fuzz targets ----------

func FuzzDecodeEthereumTx(f *testing.F) {
	f.Add(fuzzSeedEthereumLegacy())
	f.Add(fuzzSeedEthereumERC20())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		_, _ = DecodeEthereumTx(data)
	})
}

func FuzzDecodeBitcoinTx(f *testing.F) {
	if seed := fuzzSeedBitcoinTx(); seed != nil {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		_, _ = DecodeBitcoinTx(BTC, data)
	})
}

func FuzzDecodeSolanaTx(f *testing.F) {
	if seed := fuzzSeedSolanaTx(); seed != nil {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		_, _ = DecodeSolanaTx(data)
	})
}

func FuzzDecodeCosmosTx(f *testing.F) {
	if seed := fuzzSeedCosmosTx(); seed != nil {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		_, _ = DecodeCosmosTx(data)
	})
}

func FuzzDecodeTronTx(f *testing.F) {
	if seed := fuzzSeedTronTx(); seed != nil {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		_, _ = DecodeTronTx(data)
	})
}

func FuzzDecodeRippleTx(f *testing.F) {
	f.Add(fuzzSeedRippleTx())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		_, _ = DecodeRippleTx(data)
	})
}

// FuzzParseContractABI fuzzes the JSON-ABI parser directly (it wraps
// encoding/json.Unmarshal, which does not panic on malformed JSON, but the
// selector-building loop over decoded entries is library code worth fuzzing).
func FuzzParseContractABI(f *testing.F) {
	f.Add([]byte(fuzzApproveJSONABI))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		_, _ = ParseContractABI(data)
	})
}

// FuzzDecodeContractCall fuzzes calldata decoding against a fixed, known-good
// ABI map (built once from the approve() vector) — the interesting surface is
// the selector lookup + ABIDecodeParams path, not the ABI JSON itself (that is
// FuzzParseContractABI's job).
func FuzzDecodeContractCall(f *testing.F) {
	abiMap, err := ParseContractABI([]byte(fuzzApproveJSONABI))
	if err != nil {
		f.Fatalf("ParseContractABI: %v", err)
	}
	f.Add(fuzzApproveCalldata())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		_, _, _ = DecodeContractCall(abiMap, data)
	})
}

// FuzzDecodeEthLog fuzzes the EVM event-log decode path (topics + data) using
// the same shape of Transfer(address,address,uint256) log constructed in
// tx_decode_log_test.go's makeTransferLog: a real event signature topic, two
// zero-padded address topics, a fourth (tokenId) topic, and a uint256 amount
// in Data. topicCount selects how many of the four topic strings actually go
// into log.Topics — with a fixed 3-topic signature, ERC721TransferLog's
// len(Topics)>=4 guard always fails and its tokenID-parsing body
// (decodeLogTopic on Topics[3]) is never reached by mutation; letting the
// fuzzer mutate topicCount up to 4 lets it actually get past that guard and
// into the real parsing code, not just the length check.
func FuzzDecodeEthLog(f *testing.F) {
	transferSig := "0x" + bytesToHex(keccak256([]byte("Transfer(address,address,uint256)")))
	zeroPad := "0x" + bytesToHex(make([]byte, 32))
	amountData := make([]byte, 32)
	amountData[31] = 100

	// tokenIdTopic mirrors tx_decode_log_test.go's makeTransferLog(erc721=true)
	// encoding of tokenId=42 as an indexed (right-aligned) topic.
	tokenIDTopic := make([]byte, 32)
	tokenIDTopic[31] = 42
	tokenIDTopicHex := "0x" + bytesToHex(tokenIDTopic)

	// ERC-20 Transfer seed: 3 topics (sig, from, to), amount in Data.
	f.Add(transferSig, zeroPad, zeroPad, tokenIDTopicHex, uint8(3), amountData)
	// ERC-721 Transfer seed: 4 topics (sig, from, to, tokenId), empty Data —
	// this is the seed that actually reaches ERC721TransferLog's body.
	f.Add(transferSig, zeroPad, zeroPad, tokenIDTopicHex, uint8(4), []byte{})

	f.Fuzz(func(t *testing.T, topic0, topic1, topic2, topic3 string, topicCount uint8, data []byte) {
		if len(data) > fuzzMaxInput {
			return
		}
		allTopics := []string{topic0, topic1, topic2, topic3}
		n := int(topicCount) % (len(allTopics) + 1) // 0..4
		log := &EthLog{
			Topics: allTopics[:n],
			Data:   data,
		}
		_, _, _, _ = ERC20TransferLog(log)
		_, _, _, _ = ERC721TransferLog(log)
		_, _ = DecodeEthLog(log, []string{"uint256"})
		_, _ = DecodeEthLog(log, []string{"address", "uint256"})
	})
}
