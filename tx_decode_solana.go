package hdwallet

// "What am I signing?" decoder for Solana (legacy) transactions.
//
// DecodeSolanaTx parses a raw signed Solana transaction back into its plain
// fields so a client can render a confirmation screen WITHOUT touching a private
// key or any secret. It is the inverse of the tx_solana.go serialization:
//
//	[compact-u16 sigCount][64-byte signatures...]
//	[header: numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned]
//	[compact-u16 keyCount][32-byte account keys...]
//	[32-byte recent blockhash]
//	[compact-u16 instrCount][instructions...]
//	  instruction: [programIdIndex u8]
//	               [compact-u16 accCount][account indices...]
//	               [compact-u16 dataLen][data...]
//
// It reuses the base58 helpers (codec.go / address_validate.go) to render account
// keys, the blockhash and program ids, and recognises the System-Program transfer
// and SPL TransferChecked instructions the signer builds.
//
// This file adds no signer/registry/proto changes; it is display-only. Every read
// is bounds-checked: malformed/truncated input returns ErrTxDecode and the decoder
// never panics or reads past `raw`.

import (
	"encoding/binary"
	"fmt"
)

// SolanaInstruction is one decoded instruction. ProgramID and the decoded
// transfer fields are best-effort: ProgramID is empty if the program index is out
// of range, and Type is "" for an instruction the decoder does not recognise.
type SolanaInstruction struct {
	ProgramIDIndex byte
	ProgramID      string // base58 of the referenced account key ("" if out of range)
	Accounts       []byte // account-key indices the instruction operates on
	Data           []byte // raw instruction data

	// Type names a recognised instruction: "systemTransfer" or
	// "tokenTransferChecked" (empty otherwise).
	Type     string
	Lamports uint64 // systemTransfer
	Amount   uint64 // tokenTransferChecked
	Decimals byte   // tokenTransferChecked
}

// SolanaTxFields holds the decoded, display-ready fields of a Solana transaction.
type SolanaTxFields struct {
	Signatures            [][]byte
	NumRequiredSignatures byte
	NumReadonlySigned     byte
	NumReadonlyUnsigned   byte
	AccountKeys           []string // base58
	RecentBlockhash       string   // base58
	Instructions          []SolanaInstruction
}

// solCursor is a bounds-checked forward reader over the transaction bytes.
type solCursor struct {
	b   []byte
	pos int
}

func (c *solCursor) remaining() int { return len(c.b) - c.pos }

func (c *solCursor) readByte() (byte, error) {
	if c.remaining() < 1 {
		return 0, fmt.Errorf("%w: solana: truncated (want 1 byte)", ErrTxDecode)
	}
	v := c.b[c.pos]
	c.pos++
	return v, nil
}

func (c *solCursor) readBytes(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, fmt.Errorf("%w: solana: truncated (want %d bytes, have %d)", ErrTxDecode, n, c.remaining())
	}
	out := c.b[c.pos : c.pos+n]
	c.pos += n
	return out, nil
}

// readCompactU16 decodes Solana's compact-u16 (ShortVec) length: up to three
// 7-bit groups, little-endian, high bit as the continuation flag. It is the
// inverse of solanaCompactU16.
func (c *solCursor) readCompactU16() (int, error) {
	var val int
	for i := 0; i < 3; i++ {
		b, err := c.readByte()
		if err != nil {
			return 0, err
		}
		val |= int(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			if val > 0xffff {
				return 0, fmt.Errorf("%w: solana: compact-u16 out of range", ErrTxDecode)
			}
			return val, nil
		}
	}
	return 0, fmt.Errorf("%w: solana: compact-u16 too long", ErrTxDecode)
}

// DecodeSolanaTx decodes a raw signed Solana (legacy) transaction into its display
// fields. Malformed or truncated input returns ErrTxDecode; the function never
// panics and never reads past `raw`.
func DecodeSolanaTx(raw []byte) (*SolanaTxFields, error) {
	c := &solCursor{b: raw}

	sigCount, err := c.readCompactU16()
	if err != nil {
		return nil, err
	}
	f := &SolanaTxFields{}
	f.Signatures = make([][]byte, 0, sigCount)
	for i := 0; i < sigCount; i++ {
		sig, err := c.readBytes(64)
		if err != nil {
			return nil, err
		}
		f.Signatures = append(f.Signatures, append([]byte(nil), sig...))
	}

	// Message header.
	header, err := c.readBytes(3)
	if err != nil {
		return nil, err
	}
	f.NumRequiredSignatures = header[0]
	f.NumReadonlySigned = header[1]
	f.NumReadonlyUnsigned = header[2]

	// Account keys.
	keyCount, err := c.readCompactU16()
	if err != nil {
		return nil, err
	}
	keys := make([][]byte, 0, keyCount)
	f.AccountKeys = make([]string, 0, keyCount)
	for i := 0; i < keyCount; i++ {
		k, err := c.readBytes(32)
		if err != nil {
			return nil, err
		}
		kc := append([]byte(nil), k...)
		keys = append(keys, kc)
		f.AccountKeys = append(f.AccountKeys, base58Encode(base58BTC, kc))
	}

	// Recent blockhash.
	blockhash, err := c.readBytes(32)
	if err != nil {
		return nil, err
	}
	f.RecentBlockhash = base58Encode(base58BTC, blockhash)

	// Instructions.
	instrCount, err := c.readCompactU16()
	if err != nil {
		return nil, err
	}
	f.Instructions = make([]SolanaInstruction, 0, instrCount)
	for i := 0; i < instrCount; i++ {
		ins, err := decodeSolanaInstruction(c, keys)
		if err != nil {
			return nil, err
		}
		f.Instructions = append(f.Instructions, ins)
	}

	if c.remaining() != 0 {
		return nil, fmt.Errorf("%w: solana: %d trailing bytes", ErrTxDecode, c.remaining())
	}
	return f, nil
}

// decodeSolanaInstruction reads one instruction and decodes it against the
// (already parsed) account-key list to recognise known program calls.
func decodeSolanaInstruction(c *solCursor, keys [][]byte) (SolanaInstruction, error) {
	programIdx, err := c.readByte()
	if err != nil {
		return SolanaInstruction{}, err
	}
	accCount, err := c.readCompactU16()
	if err != nil {
		return SolanaInstruction{}, err
	}
	accounts, err := c.readBytes(accCount)
	if err != nil {
		return SolanaInstruction{}, err
	}
	dataLen, err := c.readCompactU16()
	if err != nil {
		return SolanaInstruction{}, err
	}
	data, err := c.readBytes(dataLen)
	if err != nil {
		return SolanaInstruction{}, err
	}

	ins := SolanaInstruction{
		ProgramIDIndex: programIdx,
		Accounts:       append([]byte(nil), accounts...),
		Data:           append([]byte(nil), data...),
	}
	var programKey []byte
	if int(programIdx) < len(keys) {
		programKey = keys[programIdx]
		ins.ProgramID = base58Encode(base58BTC, programKey)
	}
	decodeSolanaKnownInstruction(&ins, programKey)
	return ins, nil
}

// decodeSolanaKnownInstruction recognises the System-Program native transfer and
// SPL Token TransferChecked instructions and fills the decoded fields. Anything
// else leaves Type empty.
func decodeSolanaKnownInstruction(ins *SolanaInstruction, programKey []byte) {
	switch {
	case bytesEqual(programKey, solanaSystemProgramID) && len(ins.Data) == 12 &&
		binary.LittleEndian.Uint32(ins.Data[0:4]) == solanaTransferInstruction:
		ins.Type = "systemTransfer"
		ins.Lamports = binary.LittleEndian.Uint64(ins.Data[4:12])
	case len(ins.Data) == 10 && ins.Data[0] == solanaTokenTransferCheckedInstruction &&
		bytesEqual(programKey, solanaTokenProgramBytes()):
		ins.Type = "tokenTransferChecked"
		ins.Amount = binary.LittleEndian.Uint64(ins.Data[1:9])
		ins.Decimals = ins.Data[9]
	}
}

// solanaTokenProgramBytes decodes the well-known SPL Token program id once for
// comparison.
func solanaTokenProgramBytes() []byte {
	b, _ := base58Decode(base58BTC, solanaTokenProgramID)
	return b
}
