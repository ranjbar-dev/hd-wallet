package hdwallet

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"google.golang.org/protobuf/proto"

	txstellar "github.com/ranjbar-dev/hd-wallet/txproto/stellar"
)

// Stellar (XLM) transaction signing.
//
// Wire format: XDR (External Data Representation), TransactionV0 envelope.
// All integers are big-endian; fixed-size arrays have no length prefix.
//
// Output envelope format (TransactionV0, ENVELOPE_TYPE_TX_V0 = 0):
//   [00000000]                         ← outer envelope discriminant
//   [sourcePub(32)]                    ← raw uint256, NO MuxedAccount discriminant
//   [fee][seqNum][timeBounds*=0][memo][ops][ext]
//   [sigs]
//
// Signing preimage layout (empirically matched to TWC vector):
//   networkId(32) || ENVELOPE_TYPE_TX(4=2) || KEY_TYPE_ED25519(4=0) || txV0Body
//
// The KEY_TYPE_ED25519 discriminant (00000000) is inserted between the type tag
// and the V0 body in the preimage. This causes the preimage to look like a V1
// transaction body (MuxedAccount source), while the output envelope remains V0
// format (raw source key). Trust Wallet Core's Stellar signer produces this exact
// layout, confirmed byte-for-byte against the test vector below.
//
// Signing preimage steps:
//  1. networkId  = SHA256(networkPassphrase)                     — 32 bytes
//  2. preimage   = networkId || uint32(2) || uint32(0) || txV0Body
//  3. sigHash    = SHA256(preimage)
//  4. sig        = ed25519.Sign(key, sigHash[:])                 — raw sigHash as message
//
// Verified byte-for-byte against Trust Wallet Core TransactionTests.cpp
// test "sign" (TWCoinTypeStellar, mnemonic "indicate rival expand cave giant same
// grocery burden ugly rose tuna blood", fee=1000, seq=2, amount=10000000).
//
// Source: https://github.com/trustwallet/wallet-core/blob/master/tests/chains/Stellar/TransactionTests.cpp

// xlmMainnetPassphrase is the standard Stellar mainnet network passphrase.
const xlmMainnetPassphrase = "Public Global Stellar Network ; September 2015"

// xlmEnvelopeTypeV0 is the XDR discriminant for ENVELOPE_TYPE_TX_V0 = 0.
// All major wallets (Trust Wallet Core, Stellar SDK) emit V0 envelopes.
const xlmEnvelopeTypeV0 uint32 = 0

// xlmEnvelopeTypeTX is the XDR discriminant for ENVELOPE_TYPE_TX = 2.
// Used ONLY in the signing preimage type tag (both V0 and V1 transactions
// use this tag in their hash preimage per Stellar protocol spec).
const xlmEnvelopeTypeTX uint32 = 2

// xlmKeyTypeED25519 is the MuxedAccount discriminant KEY_TYPE_ED25519 = 0.
// Used for PaymentOp.destination (always MuxedAccount in both V0 and V1).
// NOT used for the V0 source account (raw uint256 there).
const xlmKeyTypeED25519 uint32 = 0

// xlmMemoNone is the Memo discriminant MEMO_NONE = 0.
const xlmMemoNone uint32 = 0

// xlmMemoText is the Memo discriminant MEMO_TEXT = 1.
const xlmMemoText uint32 = 1

// xlmMemoID is the Memo discriminant MEMO_ID = 2.
const xlmMemoID uint32 = 2

// xlmMemoHash is the Memo discriminant MEMO_HASH = 3.
const xlmMemoHash uint32 = 3

// xlmMemoTextMaxLen is the maximum length in bytes of a MEMO_TEXT value.
const xlmMemoTextMaxLen = 28

// xlmMemoHashLen is the required length in bytes of a MEMO_HASH value.
const xlmMemoHashLen = 32

// xlmTimeBoundsAbsent is the XDR optional pointer for absent TimeBounds in V0 = 0.
const xlmTimeBoundsAbsent uint32 = 0

// xlmOpCreateAccount is the OperationBody discriminant CREATE_ACCOUNT = 0.
const xlmOpCreateAccount uint32 = 0

// xlmOpPayment is the OperationBody discriminant PAYMENT = 1.
const xlmOpPayment uint32 = 1

// xlmAssetTypeNative is the Asset discriminant ASSET_TYPE_NATIVE = 0.
const xlmAssetTypeNative uint32 = 0

// signXLMTx signs a Stellar payment transaction and returns base64(XDR(TransactionEnvelope)).
// The XLM key is ed25519; the preimage is SHA256(preimage) which is passed as the
// raw message to ed25519.Sign (ed25519 hashes it internally with SHA-512).
func (w *HDWallet) signXLMTx(_ Chain, index uint32, in *txstellar.SigningInput) (proto.Message, error) {
	// Decode source account G-address → 32-byte ed25519 public key.
	sourcePub, err := validators[XLM](in.Account)
	if err != nil {
		return nil, fmt.Errorf("%w: XLM: invalid source account %q: %v", ErrTxInput, in.Account, err)
	}

	// Validate fee before narrowing to uint32.
	if in.Fee <= 0 {
		return nil, fmt.Errorf("%w: XLM: fee must be positive (got %d)", ErrTxInput, in.Fee)
	}

	// Validate and encode the operation (Payment or CreateAccount).
	opXDR, err := xlmBuildOperationXDR(in)
	if err != nil {
		return nil, err
	}

	// Build the XDR-encoded memo (defaults to MEMO_NONE if no memo oneof case is set).
	memoXDR, err := xlmBuildMemoXDR(in)
	if err != nil {
		return nil, err
	}

	// Build the XDR-encoded Transaction body.
	txXDR := xlmBuildTransactionXDR(sourcePub, uint32(in.Fee), in.Sequence, opXDR, memoXDR) // #nosec G115 -- fee is int32, validated positive above; safe narrowing to uint32

	// Determine the network passphrase.
	passphrase := in.Passphrase
	if passphrase == "" {
		passphrase = xlmMainnetPassphrase
	}

	// Compute the network ID = SHA256(passphrase).
	networkID := sha256.Sum256([]byte(passphrase))

	// Signing preimage: networkID(32) || ENVELOPE_TYPE_TX(4) || KEY_TYPE_ED25519(4) || txXDR.
	// The KEY_TYPE_ED25519 discriminant is inserted between the type tag and the V0 body
	// so the preimage matches a V1-style MuxedAccount source encoding, as TWC produces.
	preimage := make([]byte, 0, 32+4+4+len(txXDR))
	preimage = append(preimage, networkID[:]...)
	preimage = xlmAppendUint32(preimage, xlmEnvelopeTypeTX)
	preimage = xlmAppendUint32(preimage, xlmKeyTypeED25519)
	preimage = append(preimage, txXDR...)

	// sigHash = SHA256(preimage) — 32-byte digest.
	sigHash := sha256.Sum256(preimage)

	// Derive the ed25519 public key to compute the signature hint.
	pubKey, err := w.PublicKeyIndex(XLM, index)
	if err != nil {
		return nil, fmt.Errorf("XLM: derive public key: %w", err)
	}

	// Sign the sigHash with ed25519. The key is derived and wiped inside SignIndex.
	sig, err := w.SignIndex(XLM, index, sigHash[:])
	if err != nil {
		return nil, fmt.Errorf("XLM: sign: %w", err)
	}
	sigBytes := sig.Bytes() // 64-byte ed25519 signature

	// Signature hint = last 4 bytes of the signing public key.
	hint := pubKey[28:32]

	// Assemble the TransactionEnvelope XDR.
	envXDR := xlmBuildEnvelopeXDR(txXDR, hint, sigBytes)

	return &txstellar.SigningOutput{
		Encoded: base64.StdEncoding.EncodeToString(envXDR),
		Raw:     envXDR,
	}, nil
}

// xlmBuildMemoXDR encodes the Stellar Memo union as XDR bytes, selected from
// the SigningInput memo oneof. MEMO_NONE(0) is the default when no memo case
// is set. Validates memo_text <=28 bytes and memo_hash ==32 bytes.
func xlmBuildMemoXDR(in *txstellar.SigningInput) ([]byte, error) {
	switch memo := in.GetMemo().(type) {
	case *txstellar.SigningInput_MemoText:
		text := memo.MemoText.GetText()
		if len(text) > xlmMemoTextMaxLen {
			return nil, fmt.Errorf("%w: XLM: memo_text must be <=%d bytes (got %d)", ErrTxInput, xlmMemoTextMaxLen, len(text))
		}
		var b []byte
		b = xlmAppendUint32(b, xlmMemoText)
		b = xlmAppendOpaqueString(b, text)
		return b, nil

	case *txstellar.SigningInput_MemoId:
		var b []byte
		b = xlmAppendUint32(b, xlmMemoID)
		b = xlmAppendUint64(b, memo.MemoId.GetId())
		return b, nil

	case *txstellar.SigningInput_MemoHash:
		hash := memo.MemoHash.GetHash()
		if len(hash) != xlmMemoHashLen {
			return nil, fmt.Errorf("%w: XLM: memo_hash must be exactly %d bytes (got %d)", ErrTxInput, xlmMemoHashLen, len(hash))
		}
		var b []byte
		b = xlmAppendUint32(b, xlmMemoHash)
		b = append(b, hash...) // opaque[32] — fixed size, no length prefix
		return b, nil

	default:
		// MEMO_NONE(0): no payload.
		return xlmAppendUint32(nil, xlmMemoNone), nil
	}
}

// xlmBuildOperationXDR encodes the Operation.body (OperationBody discriminant
// plus the operation-specific fields) selected from the SigningInput operation
// oneof — either Payment (PAYMENT=1) or CreateAccount (CREATE_ACCOUNT=0).
// CreateAccount funds a not-yet-existing account (Stellar rejects Payment to
// unfunded accounts); unlike Payment it has no asset field, since it always
// funds with native XLM.
func xlmBuildOperationXDR(in *txstellar.SigningInput) ([]byte, error) {
	switch {
	case in.GetPayment() != nil:
		payment := in.GetPayment()
		if payment.Amount <= 0 {
			return nil, fmt.Errorf("%w: XLM: payment amount must be positive (got %d stroops)", ErrTxInput, payment.Amount)
		}
		destPub, err := validators[XLM](payment.Destination)
		if err != nil {
			return nil, fmt.Errorf("%w: XLM: invalid destination %q: %v", ErrTxInput, payment.Destination, err)
		}
		var b []byte
		// body: OperationBody { type=PAYMENT(1), PaymentOp }
		b = xlmAppendUint32(b, xlmOpPayment)
		// PaymentOp.destination: MuxedAccount
		b = xlmAppendUint32(b, xlmKeyTypeED25519)
		b = append(b, destPub...) // opaque[32]
		// PaymentOp.asset: Asset { type=ASSET_TYPE_NATIVE(0) }
		b = xlmAppendUint32(b, xlmAssetTypeNative)
		// PaymentOp.amount: int64
		b = xlmAppendInt64(b, payment.Amount)
		return b, nil

	case in.GetCreateAccount() != nil:
		createAccount := in.GetCreateAccount()
		if createAccount.StartingBalance <= 0 {
			return nil, fmt.Errorf("%w: XLM: starting_balance must be positive (got %d stroops)", ErrTxInput, createAccount.StartingBalance)
		}
		destPub, err := validators[XLM](createAccount.Destination)
		if err != nil {
			return nil, fmt.Errorf("%w: XLM: invalid destination %q: %v", ErrTxInput, createAccount.Destination, err)
		}
		var b []byte
		// body: OperationBody { type=CREATE_ACCOUNT(0), CreateAccountOp }
		b = xlmAppendUint32(b, xlmOpCreateAccount)
		// CreateAccountOp.destination: AccountID (MuxedAccount-style encoding, as used
		// throughout this V0 preimage layout — see the file-level comment).
		b = xlmAppendUint32(b, xlmKeyTypeED25519)
		b = append(b, destPub...) // opaque[32]
		// CreateAccountOp.startingBalance: int64 — no asset field (always native XLM).
		b = xlmAppendInt64(b, createAccount.StartingBalance)
		return b, nil

	default:
		return nil, fmt.Errorf("%w: XLM: no operation provided (payment or create_account)", ErrTxInput)
	}
}

// xlmBuildTransactionXDR encodes a Stellar TransactionV0 body (without the
// envelope wrapper) as XDR bytes. This is the V0 format: source account is a
// raw uint256 (32 bytes) with no MuxedAccount discriminant prefix. opXDR is
// the pre-encoded Operation.body (see xlmBuildOperationXDR) and memoXDR is the
// pre-encoded Memo union (see xlmBuildMemoXDR).
func xlmBuildTransactionXDR(sourcePub []byte, fee uint32, seqNum int64, opXDR []byte, memoXDR []byte) []byte {
	var b []byte

	// sourceAccountEd25519: uint256 — V0 raw 32-byte key, NO MuxedAccount discriminant.
	b = append(b, sourcePub...)

	// fee: uint32
	b = xlmAppendUint32(b, fee)

	// seqNum: int64
	b = xlmAppendInt64(b, seqNum)

	// timeBounds*: XDR optional — 0 = absent (no time bounds).
	b = xlmAppendUint32(b, xlmTimeBoundsAbsent)

	// memo: Memo union (MEMO_NONE/MEMO_TEXT/MEMO_ID/MEMO_HASH)
	b = append(b, memoXDR...)

	// operations: array[1]
	b = xlmAppendUint32(b, 1) // count
	// Operation {
	//   sourceAccount: absent (optional presence flag = 0)
	b = xlmAppendUint32(b, 0) // present=0 (absent)
	//   body: OperationBody (pre-encoded — Payment or CreateAccount)
	b = append(b, opXDR...)
	// }

	// ext: TransactionExt { v=0 }
	b = xlmAppendUint32(b, 0)

	return b
}

// xlmBuildEnvelopeXDR wraps a TransactionV0 body in a TransactionEnvelope with
// one DecoratedSignature. Outer discriminant is ENVELOPE_TYPE_TX_V0 = 0.
func xlmBuildEnvelopeXDR(txXDR, hint, sig []byte) []byte {
	var b []byte

	// type: ENVELOPE_TYPE_TX_V0 = 0
	b = xlmAppendUint32(b, xlmEnvelopeTypeV0)

	// tx: Transaction (raw XDR, already built)
	b = append(b, txXDR...)

	// signatures: array[1]
	b = xlmAppendUint32(b, 1) // count = 1
	// DecoratedSignature {
	//   hint:      opaque[4] — fixed size
	b = append(b, hint...)
	//   signature: opaque<> — variable, uint32(len) + bytes
	b = xlmAppendUint32(b, uint32(len(sig))) // #nosec G115 -- ed25519 sig is always 64 bytes
	b = append(b, sig...)
	// }

	return b
}

// xlmAppendUint32 appends a big-endian uint32 to buf and returns the result.
func xlmAppendUint32(buf []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(buf, tmp[:]...)
}

// xlmAppendInt64 appends a big-endian int64 to buf and returns the result.
func xlmAppendInt64(buf []byte, v int64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(v)) // #nosec G115 -- exact int64→uint64 bit reinterpretation for big-endian XDR encoding
	return append(buf, tmp[:]...)
}

// xlmAppendUint64 appends a big-endian uint64 to buf and returns the result.
func xlmAppendUint64(buf []byte, v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	return append(buf, tmp[:]...)
}

// xlmAppendOpaqueString appends an XDR variable-length opaque/string value:
// uint32(len) || bytes, zero-padded to the next 4-byte boundary.
func xlmAppendOpaqueString(buf []byte, s string) []byte {
	buf = xlmAppendUint32(buf, uint32(len(s))) // #nosec G115 -- len(s) is bounded by xlmMemoTextMaxLen (28) at the only call site
	buf = append(buf, s...)
	if pad := (4 - len(s)%4) % 4; pad > 0 {
		buf = append(buf, make([]byte, pad)...)
	}
	return buf
}
