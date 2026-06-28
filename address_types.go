package hdwallet

// Bitcoin address types.
//
// The registry holds ONE encoder per coin (BTC/LTC default to native SegWit,
// BIP-84). Real wallets need the other standard Bitcoin script formats too, so
// this file adds them without touching the registry (which would change the
// AllAddresses set / the 129-network count): legacy P2PKH (BIP-44), nested
// SegWit P2SH-P2WPKH (BIP-49), native SegWit P2WPKH (BIP-84, the registry
// default), and Taproot P2TR (BIP-86, bech32m). They are reached through the
// BitcoinAddress method, which derives at the type's standard BIP purpose path
// and encodes accordingly. Verified against the official BIP-44/49/84/86 test
// vectors (address_types_test.go), which use this repo's canonical mnemonic.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/txscript"
)

// BitcoinAddressType selects which standard Bitcoin script/address format
// BitcoinAddress produces. Each maps to a BIP "purpose" derivation path.
type BitcoinAddressType int

const (
	// P2PKH is a legacy pay-to-public-key-hash address (base58check, "1..."),
	// derived under BIP-44 (m/44').
	P2PKH BitcoinAddressType = iota
	// P2SHP2WPKH is a nested SegWit pay-to-witness-public-key-hash wrapped in
	// pay-to-script-hash (base58check, "3..."), derived under BIP-49 (m/49').
	P2SHP2WPKH
	// P2WPKH is a native SegWit v0 address (bech32, "bc1q..."), derived under
	// BIP-84 (m/84'). This is the registry default for BTC/LTC.
	P2WPKH
	// P2TR is a Taproot v1 key-path address (bech32m, "bc1p..."), derived under
	// BIP-86 (m/86').
	P2TR
)

// String returns a short human-readable name for the address type.
func (t BitcoinAddressType) String() string {
	switch t {
	case P2PKH:
		return "p2pkh"
	case P2SHP2WPKH:
		return "p2sh-p2wpkh"
	case P2WPKH:
		return "p2wpkh"
	case P2TR:
		return "p2tr"
	default:
		return "unknown(" + strconv.Itoa(int(t)) + ")"
	}
}

// purpose returns the BIP-44/49/84/86 purpose number for the address type.
func (t BitcoinAddressType) purpose() (uint32, error) {
	switch t {
	case P2PKH:
		return 44, nil
	case P2SHP2WPKH:
		return 49, nil
	case P2WPKH:
		return 84, nil
	case P2TR:
		return 86, nil
	default:
		return 0, fmt.Errorf("hdwallet: unknown bitcoin address type %d", int(t))
	}
}

// btcParams holds the per-chain constants needed to encode the four address
// types: the bech32/bech32m HRP and the base58check version bytes for P2PKH and
// P2SH. Only chains that support all four formats are listed.
type btcParams struct {
	hrp      string
	p2pkhVer byte
	p2shVer  byte
}

// btcAddrParams maps a symbol to its address-encoding constants. BTC and LTC are
// the wired/tested chains; the other native-SegWit UTXO altcoins below sign with
// the same standard BIP-143 (double-SHA256) P2WPKH/legacy P2PKH sighash and are
// proven by the btcd oracle (tx_utxo_altcoins_test.go). Per-coin version bytes are
// taken from Trust Wallet Core's registry.json (and the chains' own
// chainparams for STRAX).
//
// Deliberately NOT here (would emit a wrong, fund-losing signature with this
// engine):
//   - GRS (Groestlcoin): base58Hasher is groestl512d and its sighash is not the
//     standard double-SHA256, so btcd cannot model it and it needs a Groestl dep.
//   - BTG (Bitcoin Gold): signs with a BIP-143 SIGHASH_FORKID (ForkID 79) that the
//     standard Bitcoin P2WPKH sighash does not match.
var btcAddrParams = map[Symbol]btcParams{
	BTC: {hrp: "bc", p2pkhVer: 0x00, p2shVer: 0x05},
	LTC: {hrp: "ltc", p2pkhVer: 0x30, p2shVer: 0x32},
	// Native-SegWit altcoins (standard BIP-143 sighash; btcd-oracle-proven).
	DGB:   {hrp: "dgb", p2pkhVer: 0x1e, p2shVer: 0x3f},   // DigiByte: P2PKH 30, P2SH 63
	SYS:   {hrp: "sys", p2pkhVer: 0x3f, p2shVer: 0x05},   // Syscoin: P2PKH 63, P2SH 5
	VIA:   {hrp: "via", p2pkhVer: 0x47, p2shVer: 0x21},   // Viacoin: P2PKH 71, P2SH 33
	STRAX: {hrp: "strax", p2pkhVer: 0x4b, p2shVer: 0x8c}, // Stratis: P2PKH 75, P2SH 140
}

// BitcoinAddress returns the address for symbol in the given Bitcoin address
// type, derived at the type's standard BIP path
// "m/purpose'/coinType'/account'/change/index" (purpose = 44/49/84/86 for
// P2PKH/P2SHP2WPKH/P2WPKH/P2TR; coinType taken from the coin's registry path).
//
// It is available for chains in btcAddrParams (BTC, LTC); any other symbol
// returns ErrUnsupportedCoin. account/change/index must each be below 2^31. Like
// the other derivation methods it is seed-only and the leaf key is wiped after
// use; a key-only wallet returns ErrKeyOnlyWallet.
func (w *HDWallet) BitcoinAddress(symbol Symbol, t BitcoinAddressType, account, change, index uint32) (string, error) {
	p, ok := btcAddrParams[symbol]
	if !ok {
		return "", fmt.Errorf("%w: %s has no Bitcoin address-type support", ErrUnsupportedCoin, symbol)
	}
	purpose, err := t.purpose()
	if err != nil {
		return "", err
	}
	coinType, err := btcCoinType(symbol)
	if err != nil {
		return "", err
	}
	if account >= hardenedOffset || change >= hardenedOffset || index >= hardenedOffset {
		return "", fmt.Errorf("hdwallet: %s: account/change/index must each be < %d", symbol, hardenedOffset)
	}
	path := fmt.Sprintf("m/%d'/%d'/%d'/%d/%d", purpose, coinType, account, change, index)
	pub, err := w.PublicKeyPath(symbol, path)
	if err != nil {
		return "", err
	}
	return encodeBitcoin(t, p, pub)
}

// btcCoinType extracts the SLIP-44 coin-type number from a coin's registry path
// (the second element, e.g. "0'" in "m/84'/0'/0'/0/0" → 0).
func btcCoinType(symbol Symbol) (uint32, error) {
	parts := strings.Split(coins[symbol].Path, "/")
	if len(parts) < 3 {
		return 0, fmt.Errorf("hdwallet: %s: unexpected path %q", symbol, coins[symbol].Path)
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(parts[2], "'"), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("hdwallet: %s: bad coin type in path %q: %w", symbol, coins[symbol].Path, err)
	}
	return uint32(n), nil
}

// encodeBitcoin encodes a 33-byte compressed public key in the given address
// type using the chain params.
func encodeBitcoin(t BitcoinAddressType, p btcParams, pub []byte) (string, error) {
	switch t {
	case P2PKH:
		return base58.CheckEncode(hash160(pub), p.p2pkhVer), nil
	case P2SHP2WPKH:
		redeem := append([]byte{0x00, 0x14}, hash160(pub)...) // OP_0 <20-byte keyhash>
		return base58.CheckEncode(hash160(redeem), p.p2shVer), nil
	case P2WPKH:
		return segwitAddress(p.hrp, pub)
	case P2TR:
		return encodeP2TR(p.hrp, pub)
	default:
		return "", fmt.Errorf("hdwallet: unknown bitcoin address type %d", int(t))
	}
}

// encodeP2TR builds a BIP-86 Taproot (bech32m, witness v1) address: the 33-byte
// compressed key is taken as the internal key, tweaked with no script
// (ComputeTaprootKeyNoScript), and the x-only output key is bech32m-encoded under
// witness version 1.
func encodeP2TR(hrp string, pub []byte) (string, error) {
	internal, err := btcec.ParsePubKey(pub)
	if err != nil {
		return "", err
	}
	outputKey := txscript.ComputeTaprootKeyNoScript(internal)
	xonly := schnorr.SerializePubKey(outputKey) // 32 bytes
	conv, err := bech32.ConvertBits(xonly, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.EncodeM(hrp, append([]byte{0x01}, conv...)) // witness version 1
}

// ---------------------------------------------------------------------------
// Bitcoin address kind detection
// ---------------------------------------------------------------------------

// BitcoinAddressKind describes the script type of a Bitcoin-family address.
type BitcoinAddressKind int

// BitcoinAddressKindUnknown is the zero value returned when the address format
// is not recognised for the given symbol.
const (
	BitcoinAddressKindUnknown    BitcoinAddressKind = iota
	BitcoinAddressKindP2PKH                         // 1… (base58check, version 0x00 for BTC)
	BitcoinAddressKindP2SHP2WPKH                    // 3… (base58check, version 0x05 for BTC)
	BitcoinAddressKindP2WPKH                        // bc1q… (bech32, witness v0, 20-byte program)
	BitcoinAddressKindP2TR                          // bc1p… (bech32m, witness v1, 32-byte program)
)

// DetectBitcoinAddressKind returns the address type for a Bitcoin-family
// address, using the coin's version bytes and bech32 HRP from btcAddrParams.
// Returns BitcoinAddressKindUnknown if the format is not recognised for that
// symbol (including symbols not in btcAddrParams).
func DetectBitcoinAddressKind(symbol Symbol, addr string) BitcoinAddressKind {
	p, ok := btcAddrParams[symbol]
	if !ok {
		return BitcoinAddressKindUnknown
	}
	lower := strings.ToLower(addr)
	hrp1 := p.hrp + "1"
	if strings.HasPrefix(lower, hrp1) {
		rest := lower[len(hrp1):]
		if strings.HasPrefix(rest, "q") {
			return BitcoinAddressKindP2WPKH
		}
		if strings.HasPrefix(rest, "p") {
			return BitcoinAddressKindP2TR
		}
		return BitcoinAddressKindUnknown
	}
	raw, ver, err := base58.CheckDecode(addr)
	if err != nil || len(raw) != 20 {
		return BitcoinAddressKindUnknown
	}
	switch ver {
	case p.p2pkhVer:
		return BitcoinAddressKindP2PKH
	case p.p2shVer:
		return BitcoinAddressKindP2SHP2WPKH
	}
	return BitcoinAddressKindUnknown
}

// bitcoinValidator validates any of the four standard Bitcoin address types for a
// chain in btcAddrParams (P2PKH, P2SH, P2WPKH, P2TR) and returns the decoded
// payload (20-byte hash for P2PKH/P2SH/P2WPKH, 32-byte output key for P2TR). It
// replaces the single-format SegWit validator so a wallet can validate any
// recipient address the user supplies.
func bitcoinValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		p, ok := btcAddrParams[symbol]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
		}
		_, payload, err := decodeBitcoinAddress(p, addr)
		if err != nil {
			return nil, addrErr(symbol, err.Error())
		}
		return payload, nil
	}
}

// bitcoinDecodeScript decodes a Bitcoin address (any of the four types) for
// symbol and returns its scriptPubKey, used to build transaction outputs to an
// arbitrary destination/change address.
func bitcoinDecodeScript(symbol Symbol, addr string) ([]byte, error) {
	if p, ok := btcAddrParams[symbol]; ok {
		script, _, err := decodeBitcoinAddress(p, addr)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalidAddress, symbol, err)
		}
		return script, nil
	}
	// The non-BTC/LTC UTXO chains (DOGE/DASH/BCH/ZEC) are base58check-only (plus
	// CashAddr for BCH) with chain-specific version prefixes; see tx_utxo.go.
	if up, ok := utxoOutParams[symbol]; ok {
		return up.decodeScript(symbol, addr)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
}

// decodeBitcoinAddress decodes a Bitcoin address into its scriptPubKey and the
// underlying payload. It accepts bech32 v0 (P2WPKH), bech32m v1 (P2TR), and
// base58check P2PKH/P2SH for the given chain params.
func decodeBitcoinAddress(p btcParams, addr string) (script, payload []byte, err error) {
	if strings.HasPrefix(strings.ToLower(addr), p.hrp+"1") {
		return decodeBitcoinSegwit(p, addr)
	}
	raw, ver, err := base58.CheckDecode(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("base58check decode failed: %v", err)
	}
	if len(raw) != 20 {
		return nil, nil, fmt.Errorf("payload length %d (want 20)", len(raw))
	}
	switch ver {
	case p.p2pkhVer:
		// OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
		s := append([]byte{0x76, 0xa9, 0x14}, raw...)
		s = append(s, 0x88, 0xac)
		return s, raw, nil
	case p.p2shVer:
		// OP_HASH160 <20> OP_EQUAL
		s := append([]byte{0xa9, 0x14}, raw...)
		s = append(s, 0x87)
		return s, raw, nil
	default:
		return nil, nil, fmt.Errorf("unknown version 0x%02x", ver)
	}
}

// decodeBitcoinSegwit decodes a bech32/bech32m SegWit address (witness v0
// P2WPKH or v1 P2TR) into its scriptPubKey and witness program.
func decodeBitcoinSegwit(p btcParams, addr string) (script, payload []byte, err error) {
	hrp, data, version, err := bech32.DecodeGeneric(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("bech32 decode failed: %v", err)
	}
	if hrp != p.hrp {
		return nil, nil, fmt.Errorf("wrong prefix %q (want %q)", hrp, p.hrp)
	}
	if len(data) == 0 {
		return nil, nil, errors.New("missing witness version")
	}
	witVer := data[0]
	program, err := bech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid witness program: %v", err)
	}
	switch {
	case witVer == 0 && version == bech32.Version0 && len(program) == 20:
		// OP_0 <20-byte keyhash>
		return append([]byte{0x00, 0x14}, program...), program, nil
	case witVer == 1 && version == bech32.VersionM && len(program) == 32:
		// OP_1 <32-byte output key>
		return append([]byte{0x51, 0x20}, program...), program, nil
	default:
		return nil, nil, fmt.Errorf("unsupported witness v%d (program length %d, bech32m=%t)", witVer, len(program), version == bech32.VersionM)
	}
}
