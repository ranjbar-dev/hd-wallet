package hdwallet

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"google.golang.org/protobuf/proto"

	txton "github.com/ranjbar-dev/hd-wallet/txproto/ton"
)

// TON (The Open Network) native transfer signing — wallet v4r2.
//
// A signed TON transfer is a three-cell tree (plus a body-payload leaf) wrapped
// in an external message:
//
//	external message ── ref ─▶ signed body ── ref ─▶ internal message ── ref ─▶ payload
//
//  1. Internal message cell (int_msg_info): the value transfer to `dest`
//     (addr_std with the destination workchain + hash), `amount` nanotons as
//     grams, all fees zeroed, no state-init, and a body Either-ref to a payload
//     cell (empty when there is no comment).
//  2. Unsigned body cell (wallet v4): subwallet_id ‖ expire_at ‖ seqno ‖ op=0 ‖
//     per message (mode ‖ ref(internal message)). Its representation hash is the
//     message signed with the account's ed25519 key (raw message — the repr hash
//     IS the signed message; ed25519 hashes it internally).
//  3. Signed body cell: signature(512 bits) ‖ <unsigned body bits/refs>.
//  4. External message cell (ext_in_msg_info): src=addr_none, dest=the wallet's
//     own addr_std, import_fee=0, a StateInit ref only for a deploy (seqno==0),
//     and a body Either-ref to the signed body cell.
//
// Output: `encoded` = base64(BoC(external cell)), `raw` = the BoC bytes,
// `hash` = hex(reprHash(external cell)) — the poll key toncenter returns from
// sendBocReturnHash. Verified byte-for-byte against the Trust Wallet Core vector
// "test_ton_sign_transfer_ordinary" (see tx_ton_test.go).

// TON send-mode flags (the `mode` byte on each wallet message). The default
// transfer mode is 3 = PAY_FEES_SEPARATELY | IGNORE_ACTION_PHASE_ERRORS.
const (
	// TONModePayFeesSeparately pays transfer fees separately from the message
	// value (send-mode bit 0).
	TONModePayFeesSeparately uint32 = 1
	// TONModeIgnoreActionPhaseErrors ignores errors during the action phase
	// (send-mode bit 1).
	TONModeIgnoreActionPhaseErrors uint32 = 2
)

// signTONTx signs a wallet-v4r2 native transfer and returns a base64 BoC of the
// signed external message plus its repr hash.
func (w *HDWallet) signTONTx(chain Chain, index uint32, in *txton.SigningInput) (proto.Message, error) {
	if in == nil {
		return nil, fmt.Errorf("%w: TON: nil signing input", ErrTxInput)
	}
	transfer := in.GetTransfer()
	if transfer == nil {
		return nil, fmt.Errorf("%w: TON: transfer is required", ErrTxInput)
	}
	if transfer.Comment != "" {
		// Comments (op=0 text payload) are Task 13; ordinary transfers only here.
		return nil, fmt.Errorf("%w: TON: comment payload not supported", ErrTxInput)
	}

	// Destination workchain + 32-byte account hash.
	destWC, destHash, err := tonParseAddressFull(transfer.Dest)
	if err != nil {
		return nil, fmt.Errorf("%w: TON: invalid dest %q: %v", ErrTxInput, transfer.Dest, err)
	}

	// The account's ed25519 public key gives the wallet's own address (external
	// dest) and, for a deploy, its StateInit cell.
	pub, err := w.PublicKeyIndex(chain, index)
	if err != nil {
		return nil, fmt.Errorf("TON: derive public key: %w", err)
	}
	walletHash, err := tonStateInitHash(pub)
	if err != nil {
		return nil, fmt.Errorf("TON: wallet address: %w", err)
	}

	// (1) Internal message cell.
	internal := tonBuildInternalMessage(destWC, destHash, transfer.Amount, transfer.Bounceable)

	// (2) Unsigned body cell → repr hash → ed25519 signature.
	mode := transfer.Mode
	unsigned := &tonCell{}
	tonWriteWalletV4Body(unsigned, in.SequenceNumber, in.ExpireAt, mode, internal)
	signHash := unsigned.reprHash()

	sig, err := w.SignIndex(chain, index, signHash)
	if err != nil {
		return nil, fmt.Errorf("TON: sign: %w", err)
	}
	sigBytes := sig.Bytes() // 64-byte ed25519 signature

	// (3) Signed body cell = signature ‖ <unsigned body>.
	signed := &tonCell{}
	signed.appendBytes(sigBytes)
	tonWriteWalletV4Body(signed, in.SequenceNumber, in.ExpireAt, mode, internal)

	// (4) External message cell (attach StateInit only for a deploy, seqno==0).
	var stateInit *tonCell
	if in.SequenceNumber == 0 {
		stateInit, err = tonStateInitCell(pub)
		if err != nil {
			return nil, fmt.Errorf("TON: state init: %w", err)
		}
	}
	external := tonBuildExternalMessage(walletHash, stateInit, signed)

	boc := tonCellToBoC(external)
	return &txton.SigningOutput{
		Encoded: base64.StdEncoding.EncodeToString(boc),
		Raw:     boc,
		Hash:    hex.EncodeToString(external.reprHash()),
	}, nil
}

// tonBuildInternalMessage builds the int_msg_info cell carrying a plain value
// transfer to (destWC, destHash) of `amount` nanotons. The body is an
// Either-ref to an empty payload cell (no comment).
func tonBuildInternalMessage(destWC int32, destHash []byte, amount uint64, bounce bool) *tonCell {
	c := &tonCell{}
	c.appendBit(0) // int_msg_info$0
	c.appendBit(1) // ihr_disabled = 1
	if bounce {
		c.appendBit(1)
	} else {
		c.appendBit(0)
	}
	c.appendBit(0)     // bounced = 0
	c.appendUint(0, 2) // src = addr_none$00

	// dest = addr_std$10, anycast=nothing, workchain int8, hash 256.
	c.appendBit(1)
	c.appendBit(0)
	c.appendBit(0) // anycast = nothing
	// workchain int8: low 8 bits (0x00 basechain / 0xff masterchain).
	c.appendUint(uint64(byte(int8(destWC))), 8) // #nosec G115 -- workchain is 0 or -1; encoding its 8-bit two's-complement form
	c.appendBytes(destHash)

	tonAppendGrams(c, amount) // value: grams
	c.appendBit(0)            // other (extra-currency dict) = empty
	tonAppendGrams(c, 0)      // ihr_fee = 0
	tonAppendGrams(c, 0)      // fwd_fee = 0
	c.appendUint(0, 64)       // created_lt
	c.appendUint(0, 32)       // created_at
	c.appendBit(0)            // init: Maybe = nothing

	// body: Either — stored in a ref to an (empty) payload cell.
	c.appendBit(1)
	c.appendRef(&tonCell{})
	return c
}

// tonWriteWalletV4Body writes the wallet-v4 signing body (without the leading
// signature) into c: subwallet_id ‖ expire_at ‖ seqno ‖ op=0 ‖ mode ‖
// ref(internal message).
func tonWriteWalletV4Body(c *tonCell, seqno, expireAt, mode uint32, internal *tonCell) {
	c.appendUint(tonSubwalletID, 32)
	c.appendUint(uint64(expireAt), 32)
	c.appendUint(uint64(seqno), 32)
	c.appendUint(0, 8)            // op = 0 (simple transfer)
	c.appendUint(uint64(mode), 8) // send mode
	c.appendRef(internal)
}

// tonBuildExternalMessage builds the ext_in_msg_info cell addressed to the
// wallet's own account (walletHash, workchain 0). stateInit is attached as a ref
// only for a deploy (seqno==0); body is an Either-ref to the signed body cell.
func tonBuildExternalMessage(walletHash []byte, stateInit, signedBody *tonCell) *tonCell {
	c := &tonCell{}
	c.appendUint(2, 2) // ext_in_msg_info$10
	c.appendUint(0, 2) // src = addr_none$00

	// dest = addr_std$10, anycast=nothing, workchain 0 (int8), hash 256.
	c.appendBit(1)
	c.appendBit(0)
	c.appendBit(0)     // anycast = nothing
	c.appendUint(0, 8) // workchain 0
	c.appendBytes(walletHash)

	tonAppendGrams(c, 0) // import_fee = 0

	// state_init: Maybe(Either StateInit ^StateInit). Present + in-ref for deploy.
	if stateInit != nil {
		c.appendBit(1) // Maybe = present
		c.appendBit(1) // Either = ref
		c.appendRef(stateInit)
	} else {
		c.appendBit(0) // Maybe = nothing
	}

	// body: Either — stored in a ref to the signed body cell.
	c.appendBit(1)
	c.appendRef(signedBody)
	return c
}

// tonAppendGrams appends a TON grams (VarUInteger 16) value: a 4-bit byte-length
// prefix followed by that many bytes of big-endian value. Zero is encoded as a
// length nibble of 0 with no value bytes.
func tonAppendGrams(c *tonCell, amount uint64) {
	if amount == 0 {
		c.appendUint(0, 4)
		return
	}
	// Number of bytes needed to represent amount (1..8).
	nbytes := 0
	for v := amount; v > 0; v >>= 8 {
		nbytes++
	}
	c.appendUint(uint64(nbytes), 4)
	c.appendUint(amount, nbytes*8)
}
