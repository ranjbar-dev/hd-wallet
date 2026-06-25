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
var utxoOutParams = map[Symbol]utxoOutParam{
	DOGE: {p2pkhVer: []byte{0x1e}, p2shVer: []byte{0x16}},
	DASH: {p2pkhVer: []byte{0x4c}, p2shVer: []byte{0x10}},
	BCH:  {p2pkhVer: []byte{0x00}, p2shVer: []byte{0x05}, cashHRP: "bitcoincash"},
	ZEC:  {p2pkhVer: []byte{0x1c, 0xb8}, p2shVer: []byte{0x1c, 0xbd}},
}

// decodeScript decodes addr into its scriptPubKey for the chain described by p.
// Bitcoin Cash CashAddr is tried first (when supported); base58check (P2PKH /
// P2SH) covers the remaining cases, including BCH legacy addresses.
func (p utxoOutParam) decodeScript(symbol Symbol, addr string) ([]byte, error) {
	if p.cashHRP != "" {
		if script, err := decodeCashAddrScript(p.cashHRP, addr); err == nil {
			return script, nil
		}
		// Not a CashAddr — fall through to legacy base58check (BCH accepts both).
	}
	body, err := base58CheckDecode(base58BTC, addr)
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
func bitcoinTxSupported(symbol Symbol) bool {
	if _, ok := btcAddrParams[symbol]; ok { // BTC, LTC
		return true
	}
	switch symbol {
	case DOGE, DASH, BCH:
		return true
	default:
		return false
	}
}

// btcTxVersion returns the transaction version for a Bitcoin-family chain.
// BTC/LTC use version 2; the legacy non-SegWit chains (DOGE/DASH/BCH) use version
// 1, matching the reference signers their vectors come from.
func btcTxVersion(symbol Symbol) uint32 {
	switch symbol {
	case BTC, LTC:
		return 2
	default:
		return 1
	}
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
