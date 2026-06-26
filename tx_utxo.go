package hdwallet

// UTXO transaction-chain helpers for the Bitcoin-family signer beyond BTC/LTC:
// Dogecoin, Dash, Bitcoin Cash and Zcash.
//
// These chains reuse the Bitcoin wire signer (tx_bitcoin.go) / Zcash builder
// (tx_zcash.go) and the deterministic coin-selection plan, differing only in:
//   - how a recipient/change address decodes to a scriptPubKey (base58check with
//     chain-specific version prefixes, or BCH CashAddr) — utxoOutParams below;
//   - the transaction version (btcTxVersion);
//   - the default SIGHASH byte (bitcoinDefaultHashType — BCH adds FORKID);
//   - the sighash algorithm itself (legacy / BIP-143+FORKID / ZIP-243), selected
//     in signBitcoinInput and signZcashInput.
//
// They are pinned to authoritative vectors: DOGE/DASH to the btcd legacy signer
// (their P2PKH sighash is byte-identical to Bitcoin's), BCH to Trust Wallet
// Core's BitcoinCash AnySigner vector, ZEC to TWC's Zcash Sapling-v4 vector.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// utxoOutParam describes how a recipient/change address decodes into a
// scriptPubKey for a non-BTC/LTC UTXO chain. BTC/LTC keep using btcAddrParams
// (which also handles bech32); these chains are base58check-only — plus CashAddr
// for Bitcoin Cash — with chain-specific version prefixes.
type utxoOutParam struct {
	p2pkhVer []byte // base58check version prefix for a P2PKH address
	p2shVer  []byte // base58check version prefix for a P2SH address
	cashHRP  string // CashAddr human-readable prefix (BCH); "" if the chain has none
}

// utxoOutParams maps each non-BTC/LTC UTXO chain to its address-decode constants.
//   - DOGE: P2PKH 0x1e, P2SH 0x16.
//   - DASH: P2PKH 0x4c, P2SH 0x10.
//   - BCH:  legacy base58 P2PKH 0x00 / P2SH 0x05, or CashAddr ("bitcoincash").
//   - ZEC:  transparent t-addr two-byte prefixes (P2PKH 0x1cb8, P2SH 0x1cbd).
//
// The legacy-P2PKH altcoins below sign with the exact same pre-segwit
// double-SHA256 SIGHASH_ALL sighash as Bitcoin/DOGE/DASH (only the address
// version bytes differ — they never enter the signed bytes), so the btcd oracle
// proves each one byte-for-byte (tx_utxo_altcoins_test.go). Version bytes are
// from Trust Wallet Core's registry.json.
//
// Deliberately NOT here (the engine would emit a wrong, fund-losing signature):
//   - BCD (Bitcoin Diamond): appends a length-prefixed "sbtc" string to the
//     sighash preimage for replay protection — not the standard legacy sighash.
//   - XEC (eCash): a Bitcoin Cash ABC continuation that signs with the BIP-143 +
//     SIGHASH_FORKID path; that branch lives in tx_bitcoin.go (owned elsewhere)
//     and currently keys only off BCH, so XEC would fall through to the legacy
//     sighash and produce an invalid FORKID signature.
//   - KMD/ZEN/FLUX: Zcash-derived (ZIP-143/ZIP-243 BLAKE2b sighash, Overwinter/
//     Sapling wire format; ZEN also has a CHECKBLOCKATHEIGHT scriptPubKey suffix).
//   - NEBL/XVG: Peercoin-style PoS forks with an extra nTime field in the tx.
var utxoOutParams = map[Symbol]utxoOutParam{
	DOGE: {p2pkhVer: []byte{0x1e}, p2shVer: []byte{0x16}},
	DASH: {p2pkhVer: []byte{0x4c}, p2shVer: []byte{0x10}},
	BCH:  {p2pkhVer: []byte{0x00}, p2shVer: []byte{0x05}, cashHRP: "bitcoincash"},
	ZEC:  {p2pkhVer: []byte{0x1c, 0xb8}, p2shVer: []byte{0x1c, 0xbd}},
	// Legacy-P2PKH altcoins (standard double-SHA256 sighash, btcd-oracle-proven).
	QTUM: {p2pkhVer: []byte{0x3a}, p2shVer: []byte{0x32}}, // Qtum: P2PKH 58, P2SH 50
	RVN:  {p2pkhVer: []byte{0x3c}, p2shVer: []byte{0x7a}}, // Ravencoin: P2PKH 60, P2SH 122
	FIRO: {p2pkhVer: []byte{0x52}, p2shVer: []byte{0x07}}, // Firo: P2PKH 82, P2SH 7
	MONA: {p2pkhVer: []byte{0x32}, p2shVer: []byte{0x37}}, // MonaCoin: P2PKH 50, P2SH 55
	PIVX: {p2pkhVer: []byte{0x1e}, p2shVer: []byte{0x0d}}, // PIVX: P2PKH 30, P2SH 13
}

// decodeScript decodes addr into its scriptPubKey for the chain described by p.
// Bitcoin Cash CashAddr is tried first (when supported); base58check (P2PKH /
// P2SH) covers the remaining cases, including BCH legacy addresses.
//
// Single-byte-version chains decode through btcd's base58.CheckDecode (which
// returns version + 20-byte payload); two-byte-version chains (e.g. ZEC's
// transparent t-addr) use the local multi-byte base58check decoder.
func (p utxoOutParam) decodeScript(symbol Symbol, addr string) ([]byte, error) {
	if p.cashHRP != "" {
		if script, err := decodeCashAddrScript(p.cashHRP, addr); err == nil {
			return script, nil
		}
		// Not a CashAddr — fall through to legacy base58check (BCH accepts both).
	}
	body, err := decodeBase58CheckBody(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrInvalidAddress, symbol, err)
	}
	switch {
	case len(body) == len(p.p2pkhVer)+20 && bytesEqual(body[:len(p.p2pkhVer)], p.p2pkhVer):
		return p2pkhScript(body[len(p.p2pkhVer):]), nil
	case len(body) == len(p.p2shVer)+20 && bytesEqual(body[:len(p.p2shVer)], p.p2shVer):
		return p2shScript(body[len(p.p2shVer):]), nil
	default:
		return nil, fmt.Errorf("%w: %s: unrecognized address version/length", ErrInvalidAddress, symbol)
	}
}

// decodeBase58CheckBody decodes a base58check address and returns its
// version+payload (the bytes before the 4-byte checksum). It uses btcd's
// single-byte base58.CheckDecode first — the canonical decoder, correct for every
// 1-byte-version chain — and falls back to the local multi-byte decoder for
// addresses whose version prefix is longer than one byte (e.g. ZEC).
func decodeBase58CheckBody(addr string) ([]byte, error) {
	if payload, ver, err := base58.CheckDecode(addr); err == nil {
		return append([]byte{ver}, payload...), nil
	}
	return base58CheckDecode(base58BTC, addr)
}

// p2pkhScript returns the 25-byte P2PKH scriptPubKey for a 20-byte key hash:
// OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG.
func p2pkhScript(hash20 []byte) []byte {
	s := make([]byte, 0, 25)
	s = append(s, 0x76, 0xa9, 0x14)
	s = append(s, hash20...)
	return append(s, 0x88, 0xac)
}

// p2shScript returns the 23-byte P2SH scriptPubKey for a 20-byte script hash:
// OP_HASH160 <20> OP_EQUAL.
func p2shScript(hash20 []byte) []byte {
	s := make([]byte, 0, 23)
	s = append(s, 0xa9, 0x14)
	s = append(s, hash20...)
	return append(s, 0x87)
}

// decodeCashAddrScript decodes a Bitcoin Cash CashAddr (with or without the
// "bitcoincash:" prefix) into its scriptPubKey. The CashAddr version byte's type
// bits select P2PKH (type 0) or P2SH (type 1). It reuses cashCharset /
// cashPolymodCheck from the encoder/validator code.
func decodeCashAddrScript(prefix, addr string) ([]byte, error) {
	body := addr
	if idx := strings.IndexByte(addr, ':'); idx >= 0 {
		if !strings.EqualFold(addr[:idx], prefix) {
			return nil, fmt.Errorf("wrong cashaddr prefix %q", addr[:idx])
		}
		body = addr[idx+1:]
	}
	body = strings.ToLower(body)

	values := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		pos := strings.IndexByte(cashCharset, body[i])
		if pos < 0 {
			return nil, fmt.Errorf("invalid cashaddr character %q", body[i])
		}
		values = append(values, byte(pos)) // #nosec G115 -- pos is a 0..31 charset index
	}
	if len(values) < 8 {
		return nil, errors.New("cashaddr too short")
	}
	if cashPolymodCheck(prefix, values) != 0 {
		return nil, errors.New("bad cashaddr checksum")
	}
	payload, err := bech32.ConvertBits(values[:len(values)-8], 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("invalid cashaddr payload: %v", err)
	}
	if len(payload) != 21 {
		return nil, fmt.Errorf("cashaddr payload length %d (want 21)", len(payload))
	}
	hash := payload[1:]
	switch payload[0] >> 3 { // bits 3..7 = address type
	case 0x00:
		return p2pkhScript(hash), nil
	case 0x01:
		return p2shScript(hash), nil
	default:
		return nil, fmt.Errorf("unsupported cashaddr type %d", payload[0]>>3)
	}
}

// bitcoinTxSupported reports whether the standard Bitcoin-wire signer
// (signBitcoinTx) handles symbol. ZEC is excluded — it has its own Sapling
// builder (signZcashTx), dispatched ahead of this check.
//
// A symbol is supported when it is a native-SegWit chain (btcAddrParams: BTC,
// LTC, DGB, SYS, VIA, STRAX) or one of the legacy/CashAddr chains that decode via
// utxoOutParams (DOGE, DASH, BCH, QTUM, RVN, KMD, FIRO, MONA, XVG, PIVX, NEBL,
// ZEN, FLUX). ZEC is also a utxoOutParams entry but is intercepted by signZcashTx
// before this check, so its membership here is never reached.
func bitcoinTxSupported(symbol Symbol) bool {
	if _, ok := btcAddrParams[symbol]; ok { // BTC, LTC, DGB, SYS, VIA, STRAX
		return true
	}
	_, ok := utxoOutParams[symbol]
	return ok
}

// btcTxVersion returns the transaction version for a Bitcoin-family chain.
// Native-SegWit chains (BTC/LTC and the DGB/SYS/VIA/STRAX altcoins, all in
// btcAddrParams) use version 2; the legacy non-SegWit chains (DOGE/DASH/BCH and
// the base58-only altcoins) use version 1, matching the reference signers their
// vectors come from.
func btcTxVersion(symbol Symbol) uint32 {
	if _, ok := btcAddrParams[symbol]; ok { // BTC, LTC, DGB, SYS, VIA, STRAX
		return 2
	}
	return 1
}

// bitcoinDefaultHashType returns the SIGHASH byte used when the input leaves
// hash_type unset. Bitcoin Cash defaults to SIGHASH_ALL|FORKID (0x41); every
// other chain uses SIGHASH_ALL (0x01).
func bitcoinDefaultHashType(symbol Symbol) uint32 {
	if symbol == BCH {
		return 0x41
	}
	return 0x01
}
