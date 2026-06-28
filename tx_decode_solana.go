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
// It reuses the base58 helpers (codec.go / address_validate.go) to render
// account keys, the blockhash and program ids, and recognises the System Program
// transfer, SPL Token Transfer/TransferChecked, and Compute Budget instructions.
//
// This file adds no signer/registry/proto changes; it is display-only. Every
// read is bounds-checked: malformed/truncated input returns ErrTxDecode and the
// decoder never panics or reads past `raw`.

import (
	"encoding/binary"
	"fmt"
)

// SolanaInstructionKind identifies a decoded instruction type.
type SolanaInstructionKind int

// SolanaInstructionUnknown is the zero value returned for instructions that
// are not one of the recognised/decoded types.
const (
	SolanaInstructionUnknown               SolanaInstructionKind = iota
	SolanaInstructionSystemTransfer                              // system: Transfer
	SolanaInstructionSPLTransfer                                 // spl-token: Transfer
	SolanaInstructionSPLTransferChecked                          // spl-token: TransferChecked
	SolanaInstructionComputeBudgetSetLimit                       // compute-budget: SetComputeUnitLimit
	SolanaInstructionComputeBudgetSetPrice                       // compute-budget: SetComputeUnitPrice
)

// SolanaDecodedInstruction is a decoded Solana instruction with typed fields.
// Only the fields relevant to the instruction Kind are populated; all others
// are zero. RawData/RawAccounts are always populated for Unknown instructions
// and as supplemental raw access for known ones.
type SolanaDecodedInstruction struct {
	Kind      SolanaInstructionKind
	ProgramID string // base58 program address

	// SystemTransfer fields:
	FromAccount   string // base58 sender account
	ToAccount     string // base58 recipient account
	LamportAmount uint64

	// SPLTransfer / SPLTransferChecked fields:
	SourceToken string // source token account (base58)
	DestToken   string // destination token account (base58)
	TokenMint   string // mint address (TransferChecked only, base58)
	TokenAmount uint64
	Decimals    uint8 // TransferChecked only

	// ComputeBudget fields:
	ComputeUnits  uint32 // SetComputeUnitLimit
	MicroLamports uint64 // SetComputeUnitPrice

	// Raw fallback — always set, useful for Unknown instructions:
	RawData     []byte
	RawAccounts []string // base58 account keys referenced by this instruction
}

// SolanaTxFields holds the decoded, display-ready fields of a Solana transaction.
type SolanaTxFields struct {
	Signatures            [][]byte
	NumRequiredSignatures byte
	NumReadonlySigned     byte
	NumReadonlyUnsigned   byte
	AccountKeys           []string // base58
	RecentBlockhash       string   // base58
	Instructions          []SolanaDecodedInstruction
}

// solanaComputeBudgetProgramID is the well-known Compute Budget program address.
const solanaComputeBudgetProgramID = "ComputeBudget111111111111111111111111111111" // #nosec G101 -- public program id, not a credential

// solanaTokenTransferInstruction is the SPL Token program instruction index for
// Transfer (non-checked).
const solanaTokenTransferInstruction byte = 3

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

// DecodeSolanaTx decodes a raw signed Solana (legacy) transaction into its
// display fields. Malformed or truncated input returns ErrTxDecode; the
// function never panics and never reads past `raw`.
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
	f.Instructions = make([]SolanaDecodedInstruction, 0, instrCount)
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

// decodeSolanaInstruction reads one instruction, resolves account indices to
// base58 addresses, and delegates to decodeSolanaKnownInstruction.
func decodeSolanaInstruction(c *solCursor, keys [][]byte) (SolanaDecodedInstruction, error) {
	programIdx, err := c.readByte()
	if err != nil {
		return SolanaDecodedInstruction{}, err
	}
	accCount, err := c.readCompactU16()
	if err != nil {
		return SolanaDecodedInstruction{}, err
	}
	accountIndices, err := c.readBytes(accCount)
	if err != nil {
		return SolanaDecodedInstruction{}, err
	}
	dataLen, err := c.readCompactU16()
	if err != nil {
		return SolanaDecodedInstruction{}, err
	}
	data, err := c.readBytes(dataLen)
	if err != nil {
		return SolanaDecodedInstruction{}, err
	}

	ins := SolanaDecodedInstruction{
		RawData: append([]byte(nil), data...),
	}

	var programKey []byte
	if int(programIdx) < len(keys) {
		programKey = keys[programIdx]
		ins.ProgramID = base58Encode(base58BTC, programKey)
	}

	// Resolve account indices → base58 addresses.
	ins.RawAccounts = make([]string, 0, len(accountIndices))
	for _, idx := range accountIndices {
		if int(idx) < len(keys) {
			ins.RawAccounts = append(ins.RawAccounts, base58Encode(base58BTC, keys[idx]))
		} else {
			ins.RawAccounts = append(ins.RawAccounts, "")
		}
	}

	decodeSolanaKnownInstruction(&ins, programKey)
	return ins, nil
}

// decodeSolanaKnownInstruction recognises System Program Transfer, SPL Token
// Transfer/TransferChecked, and Compute Budget instructions and fills the typed
// fields. Unknown instructions leave Kind == SolanaInstructionUnknown.
func decodeSolanaKnownInstruction(ins *SolanaDecodedInstruction, programKey []byte) {
	acc := func(n int) string {
		if n < len(ins.RawAccounts) {
			return ins.RawAccounts[n]
		}
		return ""
	}
	switch {
	// System Program: Transfer (discriminator u32=2, 12 bytes total)
	case bytesEqual(programKey, solanaSystemProgramID) && len(ins.RawData) == 12 &&
		binary.LittleEndian.Uint32(ins.RawData[0:4]) == solanaTransferInstruction:
		ins.Kind = SolanaInstructionSystemTransfer
		ins.LamportAmount = binary.LittleEndian.Uint64(ins.RawData[4:12])
		ins.FromAccount = acc(0)
		ins.ToAccount = acc(1)

	// SPL Token: Transfer (discriminator 3, 9 bytes: [3][u64 amount])
	case bytesEqual(programKey, solanaTokenProgramBytes()) && len(ins.RawData) == 9 &&
		ins.RawData[0] == solanaTokenTransferInstruction:
		ins.Kind = SolanaInstructionSPLTransfer
		ins.TokenAmount = binary.LittleEndian.Uint64(ins.RawData[1:9])
		ins.SourceToken = acc(0)
		ins.DestToken = acc(1)

	// SPL Token: TransferChecked (discriminator 12, 10 bytes: [12][u64 amount][u8 decimals])
	case bytesEqual(programKey, solanaTokenProgramBytes()) && len(ins.RawData) == 10 &&
		ins.RawData[0] == solanaTokenTransferCheckedInstruction:
		ins.Kind = SolanaInstructionSPLTransferChecked
		ins.TokenAmount = binary.LittleEndian.Uint64(ins.RawData[1:9])
		ins.Decimals = ins.RawData[9]
		ins.SourceToken = acc(0)
		ins.TokenMint = acc(1)
		ins.DestToken = acc(2)

	// Compute Budget: SetComputeUnitLimit (discriminator 2, 5 bytes: [2][u32 units])
	case bytesEqual(programKey, solanaComputeBudgetProgramBytes()) && len(ins.RawData) == 5 &&
		ins.RawData[0] == 2:
		ins.Kind = SolanaInstructionComputeBudgetSetLimit
		ins.ComputeUnits = binary.LittleEndian.Uint32(ins.RawData[1:5])

	// Compute Budget: SetComputeUnitPrice (discriminator 3, 9 bytes: [3][u64 microLamports])
	case bytesEqual(programKey, solanaComputeBudgetProgramBytes()) && len(ins.RawData) == 9 &&
		ins.RawData[0] == 3:
		ins.Kind = SolanaInstructionComputeBudgetSetPrice
		ins.MicroLamports = binary.LittleEndian.Uint64(ins.RawData[1:9])
	}
}

// solanaTokenProgramBytes decodes the well-known SPL Token program id once for
// comparison.
func solanaTokenProgramBytes() []byte {
	b, _ := base58Decode(base58BTC, solanaTokenProgramID)
	return b
}

// solanaComputeBudgetProgramBytes decodes the well-known Compute Budget program
// id once for comparison.
func solanaComputeBudgetProgramBytes() []byte {
	b, _ := base58Decode(base58BTC, solanaComputeBudgetProgramID)
	return b
}
