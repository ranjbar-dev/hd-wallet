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

// solanaTokenProgramID is the SPL Token program account, base58. It is a public
// well-known program address, not a secret.
const solanaTokenProgramID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" // #nosec G101 -- public SPL Token program id, not a credential

// solanaTransferInstruction is the System Program instruction index for Transfer.
const solanaTransferInstruction uint32 = 2

// solanaTokenTransferCheckedInstruction is the SPL Token program instruction
// index for TransferChecked.
const solanaTokenTransferCheckedInstruction byte = 12

// signSolanaTx dispatches on the SigningInput's transaction type.
func (w *HDWallet) signSolanaTx(symbol Symbol, index uint32, in *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	switch {
	case in.GetTransferTransaction() != nil:
		return w.signSolanaSystemTransfer(symbol, index, in)
	case in.GetTokenTransferTransaction() != nil:
		return w.signSolanaTokenTransfer(symbol, index, in)
	case in.GetCreateTokenAccountTransaction() != nil:
		return w.signSolanaCreateTokenAccount(symbol, index, in)
	case in.GetCreateAndTransferTokenTransaction() != nil:
		return w.signSolanaCreateAndTransferToken(symbol, index, in)
	default:
		return nil, fmt.Errorf("%w: solana: no supported transaction set", ErrTxInput)
	}
}

// solanaNonceParams resolves the optional durable-nonce inputs: the nonce
// account and the RecentBlockhashes sysvar it references. Both nil when
// nonce_account is unset. When set, the SigningInput's recent_blockhash field
// carries the durable nonce VALUE, which lands in the message blockhash slot.
func solanaNonceParams(in *txsolana.SigningInput) (nonce, sysvarRBH []byte, err error) {
	if in.GetNonceAccount() == "" {
		return nil, nil, nil
	}
	nonce, err = base58DecodeFixed(in.GetNonceAccount(), 32)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: solana: nonce_account: %v", ErrTxInput, err)
	}
	sysvarRBH, err = base58DecodeFixed(solanaSysvarRecentBlockhashesID, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: solana: recent-blockhashes sysvar: %v", ErrTxInput, err)
	}
	return nonce, sysvarRBH, nil
}

// solanaFinishTx signs message with the wallet key (single required signature)
// and assembles [compact-u16 1][signature][message].
func (w *HDWallet) solanaFinishTx(symbol Symbol, index uint32, message []byte) (*txsolana.SigningOutput, error) {
	sig, err := w.SignIndex(symbol, index, message)
	if err != nil {
		return nil, err
	}
	sigBytes := sig.Bytes()
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("%w: solana: expected 64-byte signature", ErrTxInput)
	}
	tx := make([]byte, 0, 1+len(sigBytes)+len(message))
	tx = append(tx, solanaCompactU16(1)...)
	tx = append(tx, sigBytes...)
	tx = append(tx, message...)
	return &txsolana.SigningOutput{
		Encoded: base58Encode(base58BTC, tx),
		Raw:     tx,
		// On Solana the fee-payer's signature IS the transaction id.
		TxId: base58Encode(base58BTC, sigBytes),
	}, nil
}

// signSolanaSystemTransfer builds, signs and base58-encodes a Solana system
// (native SOL) transfer.
func (w *HDWallet) signSolanaSystemTransfer(symbol Symbol, index uint32, in *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	transfer := in.GetTransferTransaction()

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

	nonce, sysvarRBH, err := solanaNonceParams(in)
	if err != nil {
		return nil, err
	}
	var message []byte
	if nonce != nil {
		message = solanaCompileMessage(from, []solanaInstruction{
			solanaInstrAdvanceNonce(nonce, from, sysvarRBH),
			solanaInstrSystemTransfer(from, to, transfer.GetValue()),
		}, blockhash)
	} else {
		message = solanaTransferMessage(from, to, blockhash, transfer.GetValue())
	}
	return w.solanaFinishTx(symbol, index, message)
}

// signSolanaTokenTransfer builds, signs and base58-encodes an SPL token
// TransferChecked between two existing token accounts. The proto supplies the
// source/destination token accounts and the mint directly (no associated-token-
// account derivation). The signer (owner of the source account) is also the fee
// payer.
func (w *HDWallet) signSolanaTokenTransfer(symbol Symbol, index uint32, in *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	tt := in.GetTokenTransferTransaction()

	owner, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(owner) != 32 {
		return nil, fmt.Errorf("%w: solana: expected 32-byte ed25519 key", ErrTxInput)
	}
	if tt.GetDecimals() > 255 {
		return nil, fmt.Errorf("%w: solana: decimals %d out of range", ErrTxInput, tt.GetDecimals())
	}

	source, err := base58DecodeFixed(tt.GetSenderTokenAddress(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: sender_token_address: %v", ErrTxInput, err)
	}
	dest, err := base58DecodeFixed(tt.GetRecipientTokenAddress(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recipient_token_address: %v", ErrTxInput, err)
	}
	mint, err := base58DecodeFixed(tt.GetTokenMintAddress(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: token_mint_address: %v", ErrTxInput, err)
	}
	blockhash, err := base58DecodeFixed(in.GetRecentBlockhash(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent_blockhash: %v", ErrTxInput, err)
	}
	tokenProgram, err := base58DecodeFixed(solanaTokenProgramID, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: token program id: %v", ErrTxInput, err)
	}

	nonce, sysvarRBH, err := solanaNonceParams(in)
	if err != nil {
		return nil, err
	}
	decimals := byte(tt.GetDecimals()) // #nosec G115 -- range-checked (<= 255) above
	var message []byte
	if nonce != nil {
		message = solanaCompileMessage(owner, []solanaInstruction{
			solanaInstrAdvanceNonce(nonce, owner, sysvarRBH),
			solanaInstrTransferChecked(source, mint, dest, owner, tokenProgram, tt.GetAmount(), decimals),
		}, blockhash)
	} else {
		message = solanaTokenTransferMessage(owner, source, dest, mint, tokenProgram, blockhash, tt.GetAmount(), decimals)
	}
	return w.solanaFinishTx(symbol, index, message)
}

// solanaTokenTransferMessage serializes the legacy message for an SPL
// TransferChecked. Account keys, in canonical Solana order (writable signer,
// then writable non-signers, then readonly non-signers), are:
//
//	0: owner   (signer, writable — fee payer + source-account authority)
//	1: source  (writable)
//	2: dest    (writable)
//	3: mint    (readonly)
//	4: token program (readonly)
//
// so the header is (1, 0, 2). The TransferChecked instruction (tag 12) targets
// the token program with accounts [source, mint, dest, owner] and data
// 12 || LE-u64(amount) || u8(decimals).
func solanaTokenTransferMessage(owner, source, dest, mint, tokenProgram, blockhash []byte, amount uint64, decimals byte) []byte {
	keys := [][]byte{owner, source, dest, mint, tokenProgram}

	var msg []byte
	// Header: numRequiredSignatures, numReadonlySignedAccounts,
	// numReadonlyUnsignedAccounts.
	msg = append(msg, 1, 0, 2)

	// Account keys.
	msg = append(msg, solanaCompactU16(len(keys))...)
	for _, k := range keys {
		msg = append(msg, k...)
	}

	// Recent blockhash.
	msg = append(msg, blockhash...)

	// Instruction data: 12 (TransferChecked) || LE-u64(amount) || u8(decimals).
	data := make([]byte, 0, 10)
	data = append(data, solanaTokenTransferCheckedInstruction)
	amt := make([]byte, 8)
	binary.LittleEndian.PutUint64(amt, amount)
	data = append(data, amt...)
	data = append(data, decimals)

	// One instruction: program = token program (idx 4), accounts in
	// TransferChecked order [source(1), mint(3), dest(2), owner(0)].
	msg = append(msg, solanaCompactU16(1)...) // instruction count
	msg = append(msg, 4)                      // programIdIndex (token program)
	msg = append(msg, solanaCompactU16(4)...) // account index count
	msg = append(msg, 1, 3, 2, 0)             // [source, mint, dest, owner]
	msg = append(msg, solanaCompactU16(len(data))...)
	msg = append(msg, data...)

	return msg
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
