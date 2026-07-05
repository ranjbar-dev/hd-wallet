package hdwallet

import (
	"encoding/binary"
	"fmt"

	"google.golang.org/protobuf/proto"

	txaptos "github.com/ranjbar-dev/hd-wallet/txproto/aptos"
)

// Aptos transaction signing.
//
// Wire format: BCS (Binary Canonical Serialization).
//   - Integers: little-endian (u8, u32, u64, u128)
//   - Sequences: ULEB128 length + elements
//   - Byte arrays: ULEB128 length + raw bytes
//   - Strings: ULEB128 length + UTF-8 bytes
//
// Signing preimage:
//  1. domain    = SHA3-256("APTOS::RawTransaction")  — 32-byte domain separator
//  2. rawTxBCS  = BCS(RawTransaction)
//  3. message   = domain || rawTxBCS
//  4. sig       = ed25519.Sign(key, message)          — ed25519 receives the full message
//     (Aptos does NOT pre-hash to a 32-byte digest before ed25519; the full domain-
//     separated message is passed to ed25519.Sign which hashes it internally with SHA-512)
//
// SignedTransaction output:
//
//	BCS(RawTransaction) || authenticator_variant(0) || ULEB128(32) || pubkey(32) || ULEB128(64) || sig(64)
//
// The sender address is SHA3-256(pubkey || 0x00), where 0x00 is the single-signer
// ed25519 authentication-key scheme byte (Aptos AIP-55 / authentication key spec).
//
// Verified byte-for-byte against Trust Wallet Core AptosTests.cpp
// test "TxSign" (private key 5d996aa7..., seq=99, maxGas=3296766, gasPrice=100,
// expiry=3664390082, chainId=33, module="aptos_account", fn="transfer",
// recipient=sender, amount=1000).
//
// Source: https://github.com/trustwallet/wallet-core/blob/master/tests/chains/Aptos/TWAnySignerTests.cpp

// aptosDomainPrefix is SHA3-256("APTOS::RawTransaction") — the fixed 32-byte
// domain separator for Aptos transaction signing.
var aptosDomainPrefix = sha3Sum256([]byte("APTOS::RawTransaction"))

// aptosEntryFunctionVariant is the BCS TransactionPayload variant index for
// EntryFunction (= 2).
const aptosEntryFunctionVariant = 2

// aptosEd25519AuthVariant is the BCS TransactionAuthenticator variant index for
// Ed25519 (= 0).
const aptosEd25519AuthVariant = 0

// aptosFrameworkAddr is the 32-byte Aptos framework address 0x0…01, used as
// the module address for built-in modules such as aptos_account.
var aptosFrameworkAddr = func() []byte {
	addr := make([]byte, 32)
	addr[31] = 0x01
	return addr
}()

// aptosEntryFunctionFromTransfer synthesizes the EntryFunction equivalent to
// 0x1::aptos_account::transfer(to, amount) from a structured TransferMessage.
// The resulting EntryFunction is fed through the exact same BCS-encoding /
// signing path as an explicit entry_function input, so the two are
// byte-identical for the same recipient/amount.
func aptosEntryFunctionFromTransfer(tm *txaptos.TransferMessage) (*txaptos.EntryFunction, error) {
	toBytes, err := hexToBytes(tm.GetTo())
	if err != nil {
		return nil, fmt.Errorf("%w: Aptos: transfer.to: %v", ErrTxInput, err)
	}
	if len(toBytes) != 32 {
		return nil, fmt.Errorf("%w: Aptos: transfer.to must be a 32-byte address, got %d bytes", ErrTxInput, len(toBytes))
	}

	return &txaptos.EntryFunction{
		ModuleAddress: aptosFrameworkAddr,
		ModuleName:    "aptos_account",
		FunctionName:  "transfer",
		TypeArgs:      nil,
		Args:          [][]byte{toBytes, aptosAppendU64LE(nil, tm.GetAmount())},
	}, nil
}

// signAptosTx builds and signs an Aptos SignedTransaction.
func (w *HDWallet) signAptosTx(_ Chain, index uint32, in *txaptos.SigningInput) (proto.Message, error) {
	if in.GetEntryFunction() != nil && in.GetTransfer() != nil {
		return nil, fmt.Errorf("%w: Aptos: entry_function and transfer are mutually exclusive", ErrTxInput)
	}

	ef := in.GetEntryFunction()
	if ef == nil && in.GetTransfer() != nil {
		var err error
		ef, err = aptosEntryFunctionFromTransfer(in.GetTransfer())
		if err != nil {
			return nil, err
		}
	}
	if ef == nil {
		return nil, fmt.Errorf("%w: Aptos: entry_function or transfer is required", ErrTxInput)
	}
	if len(ef.ModuleAddress) != 32 {
		return nil, fmt.Errorf("%w: Aptos: module_address must be 32 bytes", ErrTxInput)
	}

	// Derive the sender's 32-byte ed25519 public key.
	pubKey, err := w.PublicKeyIndex(APTOS, index)
	if err != nil {
		return nil, fmt.Errorf("aptos: derive public key: %w", err)
	}
	if len(pubKey) != 32 {
		return nil, fmt.Errorf("aptos: expected 32-byte ed25519 public key, got %d", len(pubKey))
	}

	// Compute the sender address = SHA3-256(pubkey || 0x00).
	// Aptos addresses are derived as sha3_256(pubkey || auth_key_scheme), where
	// 0x00 is the single-signer ed25519 scheme byte. This matches encodeAPTOS.
	addrInput := make([]byte, 0, 33)
	addrInput = append(addrInput, pubKey...)
	addrInput = append(addrInput, 0x00) // single-signer ed25519 scheme
	senderAddr := sha3Sum256(addrInput)

	// Build the BCS-encoded RawTransaction.
	rawTx := aptosBuildRawTransaction(senderAddr, in, ef)

	// Signing message = domain_prefix || BCS(RawTransaction).
	message := make([]byte, 0, 32+len(rawTx))
	message = append(message, aptosDomainPrefix...)
	message = append(message, rawTx...)

	// Sign the message with ed25519. Key is derived and wiped inside SignIndex.
	sig, err := w.SignIndex(APTOS, index, message)
	if err != nil {
		return nil, fmt.Errorf("aptos: sign: %w", err)
	}
	sigBytes := sig.Bytes() // 64-byte ed25519 signature

	// Assemble SignedTransaction = RawTransaction || authenticator.
	signed := make([]byte, 0, len(rawTx)+1+1+32+1+64)
	signed = append(signed, rawTx...)
	// Ed25519 authenticator variant = 0 (ULEB128; single byte).
	signed = append(signed, aptosEd25519AuthVariant)
	// Public key: ULEB128(32) + 32 bytes.
	signed = aptosBCSAppendBytes(signed, pubKey)
	// Signature: ULEB128(64) + 64 bytes.
	signed = aptosBCSAppendBytes(signed, sigBytes)

	return &txaptos.SigningOutput{
		RawTxn:  signed,
		Encoded: bytesToHex(signed),
	}, nil
}

// aptosBuildRawTransaction BCS-encodes an Aptos RawTransaction.
func aptosBuildRawTransaction(sender []byte, in *txaptos.SigningInput, ef *txaptos.EntryFunction) []byte {
	var b []byte

	// sender: AccountAddress (32 bytes, no ULEB128 prefix — fixed-size field).
	b = append(b, sender...)

	// sequence_number: u64 LE.
	b = aptosAppendU64LE(b, in.SequenceNumber)

	// payload: TransactionPayload — EntryFunction variant = 2.
	b = aptosBCSAppendULEB128(b, aptosEntryFunctionVariant)

	// ModuleId = { address: [32]byte, name: BCS string }.
	b = append(b, ef.ModuleAddress...) // 32 bytes, no length prefix (fixed-size field in BCS)
	b = aptosBCSAppendString(b, ef.ModuleName)

	// function_name: BCS string.
	b = aptosBCSAppendString(b, ef.FunctionName)

	// type_args: ULEB128(count) + each TypeTag.
	b = aptosBCSAppendULEB128(b, uint64(len(ef.TypeArgs)))
	for _, ta := range ef.TypeArgs {
		b = append(b, ta...)
	}

	// args: ULEB128(count) + each arg as ULEB128(len) + bytes.
	b = aptosBCSAppendULEB128(b, uint64(len(ef.Args)))
	for _, arg := range ef.Args {
		b = aptosBCSAppendBytes(b, arg)
	}

	// max_gas_amount: u64 LE.
	b = aptosAppendU64LE(b, in.MaxGasAmount)

	// gas_unit_price: u64 LE.
	b = aptosAppendU64LE(b, in.GasUnitPrice)

	// expiration_timestamp_secs: u64 LE.
	b = aptosAppendU64LE(b, in.ExpirationTimestampSecs)

	// chain_id: u8.
	b = append(b, byte(in.ChainId)) // #nosec G115 -- chain_id is a protocol-defined u8 field

	return b
}

// aptosBCSAppendBytes appends a BCS-encoded byte sequence: ULEB128(len) + bytes.
func aptosBCSAppendBytes(buf, data []byte) []byte {
	buf = aptosBCSAppendULEB128(buf, uint64(len(data)))
	return append(buf, data...)
}

// aptosBCSAppendString appends a BCS-encoded string: ULEB128(len_utf8) + utf8 bytes.
func aptosBCSAppendString(buf []byte, s string) []byte {
	return aptosBCSAppendBytes(buf, []byte(s))
}

// aptosBCSAppendULEB128 appends a ULEB128-encoded uint64.
func aptosBCSAppendULEB128(buf []byte, v uint64) []byte {
	for {
		b := byte(v & 0x7f) //nolint:gosec // explicit 7-bit mask
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			break
		}
	}
	return buf
}

// aptosAppendU64LE appends a uint64 in 8-byte little-endian form.
func aptosAppendU64LE(buf []byte, v uint64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(buf, tmp[:]...)
}
