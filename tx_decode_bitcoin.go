package hdwallet

// "What am I signing?" decoder for Bitcoin / Litecoin transactions.
//
// DecodeBitcoinTx parses a raw (signed or unsigned) Bitcoin-family transaction
// back into its plain fields so a client can render a confirmation screen WITHOUT
// touching a private key, a derivation path or any secret. It is the inverse of
// the serializeBitcoinTx layout in tx_bitcoin.go: version (4 LE), an optional
// SegWit marker/flag (00 01), the vin (varint count, then per-input prevout txid,
// vout index, scriptSig, sequence), the vout (varint count, then per-output
// value + scriptPubKey), the per-input witnesses (when SegWit), and the 4-byte
// locktime.
//
// It reuses, not reimplements, the existing primitives:
//   - tx_bitcoin.go script classifiers isP2PKH / isP2SHP2WPKH / isP2WPKH / isP2TR
//     to classify each output script;
//   - address_types.go btcAddrParams (per-chain HRP + base58 version bytes) plus
//     the btcd base58/bech32 encoders to re-encode an output script's hash back
//     into a renderable address (the reverse of bitcoinDecodeScript).
//
// This file adds no signer/registry/proto changes; it is display-only. Every
// length read is bounds-checked: malformed/truncated input returns ErrTxDecode
// and the decoder never panics or reads past `raw`.

import (
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// BtcVin is one decoded transaction input. TxID is rendered big-endian (the
// display/explorer order, reversed from the internal little-endian wire order).
type BtcVin struct {
	TxID     string // 32-byte prev txid, big-endian hex (explorer order)
	Vout     uint32
	Sequence uint32
}

// BtcVout is one decoded transaction output. Address is the rendered destination
// for a recognised standard script (empty with Type "nonstandard" otherwise).
type BtcVout struct {
	Value     int64  // satoshis
	ScriptHex string // scriptPubKey, hex
	Address   string // rendered address, empty if nonstandard
	Type      string // "p2pkh" / "p2sh" / "p2wpkh" / "p2tr" / "nonstandard"
}

// BtcTxFields holds the decoded, display-ready fields of a Bitcoin-family
// transaction.
type BtcTxFields struct {
	Version    int32
	Vin        []BtcVin
	Vout       []BtcVout
	LockTime   uint32
	HasWitness bool
}

// btcCursor is a bounds-checked forward reader over the transaction bytes. Every
// read validates there are enough bytes remaining and returns ErrTxDecode
// otherwise, so the decoder can never read past the buffer or panic.
type btcCursor struct {
	b   []byte
	pos int
}

func (c *btcCursor) remaining() int { return len(c.b) - c.pos }

// hasAtLeast reports whether at least n more bytes remain. n is an unsigned
// length read from the wire; remaining() is always >= 0, so widening it to
// uint64 is exact and the comparison cannot overflow.
func (c *btcCursor) hasAtLeast(n uint64) bool {
	return n <= uint64(c.remaining()) // #nosec G115 -- remaining() is non-negative; int->uint64 widening is exact
}

func (c *btcCursor) readByte() (byte, error) {
	if c.remaining() < 1 {
		return 0, fmt.Errorf("%w: bitcoin: truncated (want 1 byte)", ErrTxDecode)
	}
	v := c.b[c.pos]
	c.pos++
	return v, nil
}

func (c *btcCursor) readBytes(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, fmt.Errorf("%w: bitcoin: truncated (want %d bytes, have %d)", ErrTxDecode, n, c.remaining())
	}
	out := c.b[c.pos : c.pos+n]
	c.pos += n
	return out, nil
}

func (c *btcCursor) readUint32() (uint32, error) {
	b, err := c.readBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (c *btcCursor) readInt64() (int64, error) {
	b, err := c.readBytes(8)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b)), nil // #nosec G115 -- bit reinterpretation of an 8-byte LE value field
}

// readVarInt reads a Bitcoin compactSize unsigned integer, enforcing canonical
// minimal encoding (rejecting non-minimal multi-byte forms).
func (c *btcCursor) readVarInt() (uint64, error) {
	prefix, err := c.readByte()
	if err != nil {
		return 0, err
	}
	switch {
	case prefix < 0xfd:
		return uint64(prefix), nil
	case prefix == 0xfd:
		b, err := c.readBytes(2)
		if err != nil {
			return 0, err
		}
		n := uint64(binary.LittleEndian.Uint16(b))
		if n < 0xfd {
			return 0, fmt.Errorf("%w: bitcoin: non-canonical varint", ErrTxDecode)
		}
		return n, nil
	case prefix == 0xfe:
		b, err := c.readBytes(4)
		if err != nil {
			return 0, err
		}
		n := uint64(binary.LittleEndian.Uint32(b))
		if n <= 0xffff {
			return 0, fmt.Errorf("%w: bitcoin: non-canonical varint", ErrTxDecode)
		}
		return n, nil
	default: // 0xff
		b, err := c.readBytes(8)
		if err != nil {
			return 0, err
		}
		n := binary.LittleEndian.Uint64(b)
		if n <= 0xffffffff {
			return 0, fmt.Errorf("%w: bitcoin: non-canonical varint", ErrTxDecode)
		}
		return n, nil
	}
}

// readVarBytes reads a varint length followed by that many bytes.
func (c *btcCursor) readVarBytes() ([]byte, error) {
	n, err := c.readVarInt()
	if err != nil {
		return nil, err
	}
	if !c.hasAtLeast(n) {
		return nil, fmt.Errorf("%w: bitcoin: var-bytes length %d exceeds remaining %d", ErrTxDecode, n, c.remaining())
	}
	return c.readBytes(int(n)) // #nosec G115 -- n was just bounds-checked <= remaining(), so it fits in int
}

// DecodeBitcoinTx decodes a raw Bitcoin-family transaction (signed or unsigned)
// for chain, whose btcAddrParams select the HRP / version bytes used to render
// output addresses. Malformed or truncated input returns ErrTxDecode; the
// function never panics and never reads past `raw`.
func DecodeBitcoinTx(chain Chain, raw []byte) (*BtcTxFields, error) {
	p, ok := btcAddrParams[chain]
	if !ok {
		return nil, fmt.Errorf("%w: %s has no Bitcoin address-type support", ErrUnsupportedCoin, chain)
	}
	c := &btcCursor{b: raw}

	version, err := c.readUint32()
	if err != nil {
		return nil, err
	}
	f := &BtcTxFields{Version: int32(version)} // #nosec G115 -- tx version is a 4-byte field carried as int32 (matches serializeBitcoinTx)

	// Peek for the SegWit marker/flag (00 01). It only appears where the input
	// count would otherwise be; a real input count is never 0x00.
	if c.remaining() >= 2 && c.b[c.pos] == 0x00 {
		flag := c.b[c.pos+1]
		if flag != 0x01 {
			return nil, fmt.Errorf("%w: bitcoin: bad segwit flag 0x%02x", ErrTxDecode, flag)
		}
		f.HasWitness = true
		c.pos += 2
	}

	vinCount, err := c.readVarInt()
	if err != nil {
		return nil, err
	}
	if vinCount == 0 {
		return nil, fmt.Errorf("%w: bitcoin: zero inputs", ErrTxDecode)
	}
	if !c.hasAtLeast(vinCount) {
		return nil, fmt.Errorf("%w: bitcoin: input count %d exceeds remaining bytes", ErrTxDecode, vinCount)
	}
	f.Vin = make([]BtcVin, 0, vinCount)
	for i := uint64(0); i < vinCount; i++ {
		vin, err := c.readVin()
		if err != nil {
			return nil, err
		}
		f.Vin = append(f.Vin, vin)
	}

	voutCount, err := c.readVarInt()
	if err != nil {
		return nil, err
	}
	if !c.hasAtLeast(voutCount) {
		return nil, fmt.Errorf("%w: bitcoin: output count %d exceeds remaining bytes", ErrTxDecode, voutCount)
	}
	f.Vout = make([]BtcVout, 0, voutCount)
	for i := uint64(0); i < voutCount; i++ {
		vout, err := c.readVout(p)
		if err != nil {
			return nil, err
		}
		f.Vout = append(f.Vout, vout)
	}

	if f.HasWitness {
		// One witness stack per input; consumed for validation/length-checking but
		// not surfaced (the display fields don't need raw witness items).
		for i := uint64(0); i < vinCount; i++ {
			items, err := c.readVarInt()
			if err != nil {
				return nil, err
			}
			if !c.hasAtLeast(items) {
				return nil, fmt.Errorf("%w: bitcoin: witness item count %d exceeds remaining bytes", ErrTxDecode, items)
			}
			for j := uint64(0); j < items; j++ {
				if _, err := c.readVarBytes(); err != nil {
					return nil, err
				}
			}
		}
	}

	f.LockTime, err = c.readUint32()
	if err != nil {
		return nil, err
	}
	if c.remaining() != 0 {
		return nil, fmt.Errorf("%w: bitcoin: %d trailing bytes", ErrTxDecode, c.remaining())
	}
	return f, nil
}

// readVin reads one input: 32-byte prev txid, 4-byte vout, varint scriptSig,
// 4-byte sequence.
func (c *btcCursor) readVin() (BtcVin, error) {
	txid, err := c.readBytes(32)
	if err != nil {
		return BtcVin{}, err
	}
	vout, err := c.readUint32()
	if err != nil {
		return BtcVin{}, err
	}
	if _, err := c.readVarBytes(); err != nil { // scriptSig (ignored for display)
		return BtcVin{}, err
	}
	seq, err := c.readUint32()
	if err != nil {
		return BtcVin{}, err
	}
	return BtcVin{
		TxID:     bytesToHex(reverseBytes(txid)), // big-endian display order
		Vout:     vout,
		Sequence: seq,
	}, nil
}

// readVout reads one output: 8-byte LE value, varint scriptPubKey, and renders
// its address/type from the script using the chain params.
func (c *btcCursor) readVout(p btcParams) (BtcVout, error) {
	value, err := c.readInt64()
	if err != nil {
		return BtcVout{}, err
	}
	script, err := c.readVarBytes()
	if err != nil {
		return BtcVout{}, err
	}
	typ, addr := renderBitcoinScript(p, script)
	return BtcVout{
		Value:     value,
		ScriptHex: bytesToHex(script),
		Address:   addr,
		Type:      typ,
	}, nil
}

// renderBitcoinScript classifies a scriptPubKey via the existing classifiers and
// re-encodes its hash/program into an address using the chain params (the reverse
// of bitcoinDecodeScript / encodeBitcoin). Unrecognised scripts yield
// ("nonstandard", "").
func renderBitcoinScript(p btcParams, script []byte) (typ, addr string) {
	switch {
	case isP2PKH(script): // 76 a9 14 <20> 88 ac
		return "p2pkh", base58.CheckEncode(script[3:23], p.p2pkhVer)
	case isP2SHP2WPKH(script): // a9 14 <20> 87 (any 23-byte P2SH)
		return "p2sh", base58.CheckEncode(script[2:22], p.p2shVer)
	case isP2WPKH(script): // 00 14 <20>
		a, err := bech32SegwitAddr(p.hrp, 0, script[2:])
		if err != nil {
			return "nonstandard", ""
		}
		return "p2wpkh", a
	case isP2TR(script): // 51 20 <32>
		a, err := bech32SegwitAddr(p.hrp, 1, script[2:])
		if err != nil {
			return "nonstandard", ""
		}
		return "p2tr", a
	default:
		return "nonstandard", ""
	}
}

// bech32SegwitAddr encodes a witness program (version 0 => bech32, version 1 =>
// bech32m) for the given HRP, mirroring segwitAddress / encodeP2TR.
func bech32SegwitAddr(hrp string, witVer byte, program []byte) (string, error) {
	conv, err := bech32.ConvertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	data := append([]byte{witVer}, conv...)
	if witVer == 0 {
		return bech32.Encode(hrp, data)
	}
	return bech32.EncodeM(hrp, data)
}
