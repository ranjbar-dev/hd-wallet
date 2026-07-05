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

	// Destination workchain + 32-byte account hash. For a jetton transfer this is
	// the SENDER's jetton wallet contract (where the TEP-74 transfer body is sent).
	destWC, destHash, err := tonParseAddressFull(transfer.Dest)
	if err != nil {
		return nil, fmt.Errorf("%w: TON: invalid dest %q: %v", ErrTxInput, transfer.Dest, err)
	}

	// Internal-message body: a jetton TEP-74 transfer body, a plain text-comment
	// payload (op=0), or an empty cell for a bare value transfer.
	body, err := tonBuildTransferBody(transfer)
	if err != nil {
		return nil, err
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
	internal := tonBuildInternalMessage(destWC, destHash, transfer.Amount, transfer.Bounceable, body)

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

// tonBuildInternalMessage builds the int_msg_info cell carrying a value transfer
// to (destWC, destHash) of `amount` nanotons. `body` is stored as the message
// body via an Either-ref (an empty cell for a bare transfer, the op=0 comment
// payload for a text comment, or the TEP-74 body for a jetton transfer).
func tonBuildInternalMessage(destWC int32, destHash []byte, amount uint64, bounce bool, body *tonCell) *tonCell {
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

	tonAppendAddrStd(c, destWC, destHash) // dest = addr_std

	tonAppendGrams(c, amount) // value: grams
	c.appendBit(0)            // other (extra-currency dict) = empty
	tonAppendGrams(c, 0)      // ihr_fee = 0
	tonAppendGrams(c, 0)      // fwd_fee = 0
	c.appendUint(0, 64)       // created_lt
	c.appendUint(0, 32)       // created_at
	c.appendBit(0)            // init: Maybe = nothing

	// body: Either — stored in a ref to the body cell.
	c.appendBit(1)
	c.appendRef(body)
	return c
}

// tonAppendAddrStd appends a MsgAddressInt addr_std$10 (no anycast) with the
// given signed workchain and 32-byte account hash.
func tonAppendAddrStd(c *tonCell, wc int32, hash []byte) {
	c.appendBit(1)
	c.appendBit(0)
	c.appendBit(0)                          // anycast = nothing
	c.appendUint(uint64(byte(int8(wc))), 8) // #nosec G115 -- workchain is 0 or -1; encoding its 8-bit two's-complement form
	c.appendBytes(hash)
}

// tonJettonTransferOp is the TEP-74 jetton `transfer` op code.
const tonJettonTransferOp = 0x0f8a7ea5

// tonBuildTransferBody selects and builds the internal-message body cell for a
// transfer: a TEP-74 jetton transfer body when JettonTransfer is set, an op=0
// text-comment payload when only a comment is present, or an empty cell for a
// bare value transfer.
func tonBuildTransferBody(transfer *txton.Transfer) (*tonCell, error) {
	if jt := transfer.GetJettonTransfer(); jt != nil {
		return tonBuildJettonBody(jt, transfer.Comment)
	}
	if transfer.Comment != "" {
		return tonCommentCell(transfer.Comment), nil
	}
	return &tonCell{}, nil
}

// tonCommentCell builds an op=0 text-comment payload cell: a 32-bit zero op
// followed by the UTF-8 comment bytes, snake-chained across ref cells when the
// comment exceeds one cell (127 bytes including the 4-byte op prefix).
func tonCommentCell(comment string) *tonCell {
	data := append([]byte{0, 0, 0, 0}, []byte(comment)...)
	return tonSnakeCell(data)
}

// tonSnakeCell stores data as a TON "snake": up to 127 bytes in this cell, the
// remainder in a single ref child, recursively.
func tonSnakeCell(data []byte) *tonCell {
	const maxBytes = 127 // 1023-bit cell capacity, byte-aligned
	c := &tonCell{}
	n := len(data)
	if n > maxBytes {
		n = maxBytes
	}
	c.appendBytes(data[:n])
	if len(data) > maxBytes {
		c.appendRef(tonSnakeCell(data[maxBytes:]))
	}
	return c
}

// tonBuildJettonBody builds a TEP-74 jetton `transfer` message body:
//
//	op=0x0f8a7ea5 u32 ‖ query_id u64 ‖ amount (grams) ‖ destination addr_std ‖
//	response_destination addr_std ‖ custom_payload=Maybe(nothing) ‖
//	forward_ton_amount (grams) ‖ forward_payload (Either inline/ref)
//
// A non-empty comment becomes an op=0 text forward payload — stored inline when
// it fits in the current cell, otherwise in a ref (snake) cell.
func tonBuildJettonBody(jt *txton.JettonTransfer, comment string) (*tonCell, error) {
	toWC, toHash, err := tonParseAddressFull(jt.ToOwner)
	if err != nil {
		return nil, fmt.Errorf("%w: TON jetton: invalid to_owner %q: %v", ErrTxInput, jt.ToOwner, err)
	}
	respWC, respHash, err := tonParseAddressFull(jt.ResponseAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: TON jetton: invalid response_address %q: %v", ErrTxInput, jt.ResponseAddress, err)
	}

	c := &tonCell{}
	c.appendUint(tonJettonTransferOp, 32)
	c.appendUint(jt.QueryId, 64)
	tonAppendGrams(c, jt.JettonAmount)
	tonAppendAddrStd(c, toWC, toHash)     // destination (recipient owner)
	tonAppendAddrStd(c, respWC, respHash) // response_destination
	c.appendBit(0)                        // custom_payload: Maybe = nothing
	tonAppendGrams(c, jt.ForwardAmount)   // forward_ton_amount

	// forward_payload: Either Cell ^Cell. Empty (inline) when no comment; a text
	// op=0 comment inline if it fits in the remaining cell bits, else a ref.
	if comment == "" {
		c.appendBit(0) // Either = inline, empty
		return c, nil
	}
	payload := append([]byte{0, 0, 0, 0}, []byte(comment)...)
	// 1 Either bit + payload bits must fit the 1023-bit cell for inline storage.
	if c.bitLen+1+len(payload)*8 <= 1023 {
		c.appendBit(0) // Either = inline
		c.appendBytes(payload)
	} else {
		c.appendBit(1) // Either = ref
		c.appendRef(tonSnakeCell(payload))
	}
	return c, nil
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
