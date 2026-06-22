package hdwallet

import (
	"encoding/binary"
	"fmt"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// Solana transaction signing (System Program native transfer).
//
// A Solana (legacy) transaction is:
//
//	[compact-u16 signature count][64-byte signatures...][message]
//
// where the message is:
//
//	[header: numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned]
//	[compact-u16 account-key count][32-byte account keys...]
//	[32-byte recent blockhash]
//	[compact-u16 instruction count][instructions...]
//
// Each instruction is:
//
//	[programIdIndex u8][compact-array of account indices][compact-array of data]
//
// For a native transfer the accounts, in canonical order, are:
//
//	0: from   (writable signer)
//	1: to     (writable, not signer)
//	2: system program 11111111111111111111111111111111 (readonly, not signer)
//
// so the header is (1, 0, 1). The instruction targets the system program with
// accounts [0, 1] and data = LE-uint32(2 = Transfer) || LE-uint64(lamports).
//
// ed25519 signs the serialized MESSAGE directly (no pre-hash). The fully signed
// transaction is base58-encoded. Verified byte-for-byte against Trust Wallet
// Core's Solana AnySigner transfer vector (tx_solana_test.go).

// solanaSystemProgramID is the System Program account "111...1" (32 zero bytes).
var solanaSystemProgramID = make([]byte, 32)

// solanaTransferInstruction is the System Program instruction index for Transfer.
const solanaTransferInstruction uint32 = 2

// signSolanaTx builds, signs and base58-encodes a Solana system transfer.
func (w *HDWallet) signSolanaTx(symbol Symbol, index uint32, in *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	transfer := in.GetTransferTransaction()
	if transfer == nil {
		return nil, fmt.Errorf("%w: solana: only a native system transfer is supported", ErrTxInput)
	}

	from, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(from) != 32 {
		return nil, fmt.Errorf("%w: solana: expected 32-byte ed25519 key", ErrTxInput)
	}
	to, err := base58DecodeFixed(transfer.GetRecipient(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recipient: %v", ErrTxInput, err)
	}
	blockhash, err := base58DecodeFixed(in.GetRecentBlockhash(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent_blockhash: %v", ErrTxInput, err)
	}

	message := solanaTransferMessage(from, to, blockhash, transfer.GetValue())

	// ed25519 signs the raw serialized message.
	sig, err := w.SignIndex(symbol, index, message)
	if err != nil {
		return nil, err
	}
	sigBytes := sig.Bytes()
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("%w: solana: expected 64-byte signature", ErrTxInput)
	}

	// [compact-u16 sig count = 1][signature][message].
	tx := make([]byte, 0, 1+len(sigBytes)+len(message))
	tx = append(tx, solanaCompactU16(1)...)
	tx = append(tx, sigBytes...)
	tx = append(tx, message...)

	encoded := base58Encode(base58BTC, tx)
	return &txsolana.SigningOutput{
		Encoded: encoded,
		Raw:     tx,
	}, nil
}

// solanaTransferMessage serializes the (legacy) transaction message for a system
// transfer of value lamports from -> to.
func solanaTransferMessage(from, to, blockhash []byte, value uint64) []byte {
	// Account keys in canonical order: from(signer,writable), to(writable),
	// system program(readonly). Indices: from=0, to=1, system=2.
	keys := [][]byte{from, to, solanaSystemProgramID}

	var msg []byte
	// Header: numRequiredSignatures, numReadonlySignedAccounts,
	// numReadonlyUnsignedAccounts.
	msg = append(msg, 1, 0, 1)

	// Account keys.
	msg = append(msg, solanaCompactU16(len(keys))...)
	for _, k := range keys {
		msg = append(msg, k...)
	}

	// Recent blockhash.
	msg = append(msg, blockhash...)

	// Instruction data: LE-u32(Transfer) || LE-u64(lamports).
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], solanaTransferInstruction)
	binary.LittleEndian.PutUint64(data[4:12], value)

	// One instruction: program=system(idx 2), accounts=[from(0), to(1)].
	msg = append(msg, solanaCompactU16(1)...) // instruction count
	msg = append(msg, 2)                      // programIdIndex (system program)
	msg = append(msg, solanaCompactU16(2)...) // account index count
	msg = append(msg, 0, 1)                   // [from, to]
	msg = append(msg, solanaCompactU16(len(data))...)
	msg = append(msg, data...)

	return msg
}

// solanaCompactU16 encodes a length as Solana's compact-u16 (ShortVec) varint:
// 7 bits per byte, little-endian, high bit as the continuation flag.
func solanaCompactU16(n int) []byte {
	v := uint32(n) & 0xffff // #nosec G115 -- ShortVec is at most 16 bits; counts here are tiny
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			out = append(out, b)
			return out
		}
		out = append(out, b|0x80)
	}
}

// base58DecodeFixed decodes a Bitcoin-alphabet base58 string and requires the
// result to be exactly size bytes.
func base58DecodeFixed(s string, size int) ([]byte, error) {
	b, err := base58Decode(base58BTC, s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("decoded length %d, want %d", len(b), size)
	}
	return b, nil
}
