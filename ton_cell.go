package hdwallet

// TON "bag of cells" (BoC) primitives — a self-contained, pure-stdlib
// implementation of the small slice of the TON cell model this library needs to
// derive wallet-v4r2 addresses and (in later tasks) sign transactions.
//
// A TON cell holds up to 1023 bits of data and up to 4 references to other
// cells. The security-critical primitive is the *representation hash*: the
// address of a smart contract is the SHA-256 repr hash of its StateInit cell, so
// the exact bit-packing of the cell descriptors (d1/d2) and the completion tag
// must match the TON spec byte-for-byte — a wrong hash silently yields a
// well-formed-looking but wrong (fund-losing) address.
//
// References:
//   - TON whitepaper / "tvm.pdf" §3 (cells, descriptors, representation hash)
//   - crypto.ton.org "Cells and cell serialization"
//   - the standard serialized_boc#b5ee9c72 TL-B schema

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// tonCell is an ordinary, level-0 TON cell: up to 1023 data bits (packed MSB
// first in bits, with bitLen tracking the exact count) and up to 4 child
// references. Exotic/pruned cells are not modelled — the wallet code and every
// cell this library builds are ordinary level-0 cells.
type tonCell struct {
	bits   []byte
	bitLen int
	refs   []*tonCell
}

// appendBit appends a single bit (the low bit of b) to the cell, MSB first.
func (c *tonCell) appendBit(b uint) {
	byteIdx := c.bitLen / 8
	for byteIdx >= len(c.bits) {
		c.bits = append(c.bits, 0)
	}
	if b&1 != 0 {
		c.bits[byteIdx] |= 1 << (7 - uint(c.bitLen%8))
	}
	c.bitLen++
}

// appendUint appends the low `bits` bits of v, most-significant bit first.
func (c *tonCell) appendUint(v uint64, bits int) {
	for i := bits - 1; i >= 0; i-- {
		c.appendBit(uint((v >> uint(i)) & 1))
	}
}

// appendBytes appends every bit of each byte in data (8 bits per byte, MSB
// first). It works whether or not the cell is currently byte-aligned.
func (c *tonCell) appendBytes(data []byte) {
	for _, b := range data {
		c.appendUint(uint64(b), 8)
	}
}

// appendRef adds a child reference.
func (c *tonCell) appendRef(child *tonCell) {
	c.refs = append(c.refs, child)
}

// paddedData returns the cell's data bytes ready for hashing/serialization. For
// a byte-aligned cell this is exactly ceil(bitLen/8) bytes. For a
// non-byte-aligned cell a completion tag is applied to the final byte: the first
// unused bit is set to 1 and the remaining low bits to 0 (TON "augmentation").
func (c *tonCell) paddedData() []byte {
	ceilBytes := (c.bitLen + 7) / 8
	out := make([]byte, ceilBytes)
	copy(out, c.bits[:ceilBytes])
	if rem := c.bitLen % 8; rem != 0 {
		// Keep the top `rem` meaningful bits of the last byte, drop any lower
		// bits, then set the completion tag immediately after them.
		mask := byte(0xFF << uint(8-rem))
		last := out[ceilBytes-1] & mask
		last |= 1 << uint(7-rem)
		out[ceilBytes-1] = last
	}
	return out
}

// depth returns the cell's tree depth: 0 for a leaf, else 1 + max child depth.
func (c *tonCell) depth() int {
	if len(c.refs) == 0 {
		return 0
	}
	maxDepth := 0
	for _, r := range c.refs {
		if d := r.depth(); d > maxDepth {
			maxDepth = d
		}
	}
	return maxDepth + 1
}

// descriptors returns the two cell descriptor bytes (d1, d2) for an ordinary
// level-0 cell:
//
//	d1 = refCount (+ 8*isExotic + 32*level; both 0 here)
//	d2 = floor(bitLen/8) + ceil(bitLen/8)
func (c *tonCell) descriptors() (byte, byte) {
	d1 := byte(len(c.refs))
	full := c.bitLen / 8
	ceil := (c.bitLen + 7) / 8
	d2 := byte(full + ceil)
	return d1, d2
}

// reprHash computes the cell's representation hash:
//
//	SHA-256( d1 ‖ d2 ‖ paddedData ‖ depth(ref_i) as uint16 BE … ‖ reprHash(ref_i) … )
//
// This is the value used as a smart-contract address (over its StateInit cell).
func (c *tonCell) reprHash() []byte {
	d1, d2 := c.descriptors()
	buf := make([]byte, 0, 2+len(c.bits)+len(c.refs)*(2+32))
	buf = append(buf, d1, d2)
	buf = append(buf, c.paddedData()...)
	for _, r := range c.refs {
		d := r.depth()
		buf = append(buf, byte(d>>8), byte(d&0xff))
	}
	for _, r := range c.refs {
		buf = append(buf, r.reprHash()...)
	}
	h := sha256.Sum256(buf)
	return h[:]
}

// ---------------------------------------------------------------------------
// BoC deserialization (serialized_boc#b5ee9c72) — needed to load the wallet
// v4r2 code cell constant, which is distributed as a standard BoC.
// ---------------------------------------------------------------------------

var errTONBoC = errors.New("hdwallet: invalid TON BoC")

// tonCellFromBoCBase64 decodes a standard base64 BoC and returns its single root
// cell. It accepts either base64 alphabet.
func tonCellFromBoCBase64(s string) (*tonCell, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decode: %v", errTONBoC, err)
		}
	}
	return tonCellFromBoC(raw)
}

// tonCellFromBoC parses a serialized bag of cells and returns the root cell.
// Only ordinary, level-0 cells are reconstructed (sufficient for wallet code and
// every cell this library handles); the optional index section and trailing
// CRC32C are skipped, not verified.
func tonCellFromBoC(b []byte) (*tonCell, error) {
	if len(b) < 6 {
		return nil, fmt.Errorf("%w: too short", errTONBoC)
	}
	if b[0] != 0xb5 || b[1] != 0xee || b[2] != 0x9c || b[3] != 0x72 {
		return nil, fmt.Errorf("%w: bad magic", errTONBoC)
	}
	flags := b[4]
	hasIdx := flags&0x80 != 0
	// hasCrc := flags&0x40 != 0  // trailing CRC32C, skipped
	sizeBytes := int(flags & 0x07) // bytes per cell index
	offBytes := int(b[5])          // bytes per data-size field
	if sizeBytes == 0 || sizeBytes > 4 || offBytes == 0 || offBytes > 8 {
		return nil, fmt.Errorf("%w: bad size fields", errTONBoC)
	}

	pos := 6
	readN := func(n int) (int, bool) {
		if pos+n > len(b) {
			return 0, false
		}
		v := 0
		for i := 0; i < n; i++ {
			v = v<<8 | int(b[pos+i])
		}
		pos += n
		return v, true
	}

	cellCount, ok1 := readN(sizeBytes)
	rootCount, ok2 := readN(sizeBytes)
	_, ok3 := readN(sizeBytes) // absent
	_, ok4 := readN(offBytes)  // tot_cells_size
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, fmt.Errorf("%w: truncated header", errTONBoC)
	}
	if cellCount <= 0 || rootCount < 1 {
		return nil, fmt.Errorf("%w: bad cell/root count", errTONBoC)
	}

	rootIdx, ok := readN(sizeBytes)
	if !ok || rootIdx >= cellCount {
		return nil, fmt.Errorf("%w: bad root index", errTONBoC)
	}
	// Remaining roots (unused; single-root BoCs are all this library needs).
	for i := 1; i < rootCount; i++ {
		if _, ok := readN(sizeBytes); !ok {
			return nil, fmt.Errorf("%w: truncated root list", errTONBoC)
		}
	}
	if hasIdx {
		// Skip the offset index: cellCount entries of offBytes each.
		pos += cellCount * offBytes
		if pos > len(b) {
			return nil, fmt.Errorf("%w: truncated index", errTONBoC)
		}
	}

	// Parse each cell's raw record, collecting ref indices for a second pass.
	cells := make([]*tonCell, cellCount)
	refIdx := make([][]int, cellCount)
	for i := 0; i < cellCount; i++ {
		if pos+2 > len(b) {
			return nil, fmt.Errorf("%w: truncated cell %d header", errTONBoC, i)
		}
		d1 := b[pos]
		d2 := b[pos+1]
		pos += 2
		refCount := int(d1 & 0x07)
		if d1&0x08 != 0 || d1>>5 != 0 {
			return nil, fmt.Errorf("%w: cell %d is exotic/leveled (unsupported)", errTONBoC, i)
		}
		dataBytes := int(d2>>1) + int(d2&1)
		completed := d2&1 == 1
		if pos+dataBytes > len(b) {
			return nil, fmt.Errorf("%w: truncated cell %d data", errTONBoC, i)
		}
		data := make([]byte, dataBytes)
		copy(data, b[pos:pos+dataBytes])
		pos += dataBytes

		bitLen := dataBytes * 8
		if completed && dataBytes > 0 {
			// Locate the completion tag (lowest set bit) in the final byte.
			last := data[dataBytes-1]
			p := 0
			for p < 8 && last&(1<<uint(p)) == 0 {
				p++
			}
			if p == 8 {
				// No set bit: last byte is all padding.
				bitLen = (dataBytes - 1) * 8
			} else {
				bitLen = (dataBytes-1)*8 + (7 - p)
			}
		}

		idxs := make([]int, refCount)
		for r := 0; r < refCount; r++ {
			v, ok := readN(sizeBytes)
			if !ok || v >= cellCount {
				return nil, fmt.Errorf("%w: cell %d bad ref", errTONBoC, i)
			}
			idxs[r] = v
		}
		cells[i] = &tonCell{bits: data, bitLen: bitLen}
		refIdx[i] = idxs
	}

	// Link references.
	for i := range cells {
		for _, r := range refIdx[i] {
			cells[i].refs = append(cells[i].refs, cells[r])
		}
	}
	return cells[rootIdx], nil
}

// ---------------------------------------------------------------------------
// BoC serialization — a serialized_boc#b5ee9c72 writer matching Trust Wallet
// Core byte-for-byte (verified by Task 12's TON transfer-signing vector).
//
// TWC's C++ TON serializer (src/Everscale/CommonTON/Cell.cpp) uses FIXED
// reference- and offset-index sizes of sizeof(uint16_t) = 2 bytes each,
// regardless of how few cells/bytes the BoC actually holds (the comment there
// notes "uint16_t will be enough for wallet transactions, e.g. 64k is the size
// of the whole elector"). A minimal-width writer (1 byte for a 4-cell BoC) would
// still be a *valid* BoC but would not reproduce TWC's exact bytes, so this
// writer hard-codes the 2-byte widths to stay byte-identical.
//
// No index section and no trailing CRC32C are emitted (flags byte = 0x02:
// has_idx=0, has_crc32c=0, has_cache_bits=0, ref_size=2).
// ---------------------------------------------------------------------------

// tonBoCRefSize is TWC's fixed reference/offset index width in bytes (uint16_t).
const tonBoCRefSize = 2

// tonCellToBoC serializes cell (as the single root) into a standard BoC without
// an index section and without a trailing CRC32C, byte-for-byte compatible with
// Trust Wallet Core's TON serializer.
func tonCellToBoC(root *tonCell) []byte {
	// Topologically order cells: root first, each cell before its refs, deduped
	// by repr hash so shared subcells are emitted once. For the linear wallet-v4
	// transfer tree this yields [external, signed-body, internal, payload], which
	// matches TWC's ordering.
	order := []*tonCell{}
	indexOf := map[string]int{}
	var visit func(c *tonCell)
	visit = func(c *tonCell) {
		key := string(c.reprHash())
		if _, seen := indexOf[key]; seen {
			return
		}
		indexOf[key] = len(order)
		order = append(order, c)
		for _, r := range c.refs {
			visit(r)
		}
	}
	visit(root)

	cellCount := len(order)

	// Build each cell's serialized record and the total data size.
	var cellData []byte
	for _, c := range order {
		d1, d2 := c.descriptors()
		cellData = append(cellData, d1, d2)
		cellData = append(cellData, c.paddedData()...)
		for _, r := range c.refs {
			ri := indexOf[string(r.reprHash())]
			cellData = append(cellData, intToBytes(ri, tonBoCRefSize)...)
		}
	}

	out := make([]byte, 0, 16+len(cellData))
	out = append(out, 0xb5, 0xee, 0x9c, 0x72)
	// flags byte: no idx, no crc, no cache, flags=0, ref_size=tonBoCRefSize.
	out = append(out, byte(tonBoCRefSize))
	out = append(out, byte(tonBoCRefSize))                     // offset size (fixed uint16_t)
	out = append(out, intToBytes(cellCount, tonBoCRefSize)...) // cells
	out = append(out, intToBytes(1, tonBoCRefSize)...)         // roots
	out = append(out, intToBytes(0, tonBoCRefSize)...)         // absent
	out = append(out, intToBytes(len(cellData), tonBoCRefSize)...)
	out = append(out, intToBytes(0, tonBoCRefSize)...) // root index 0
	out = append(out, cellData...)
	return out
}

// intToBytes encodes v big-endian into exactly n bytes.
func intToBytes(v, n int) []byte {
	out := make([]byte, n)
	for i := n - 1; i >= 0; i-- {
		out[i] = byte(v & 0xff)
		v >>= 8
	}
	return out
}
