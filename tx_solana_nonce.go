package hdwallet

import (
	"crypto/ed25519"
	"fmt"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// Durable-nonce account lifecycle: CreateNonceAccount (fund + initialize, the
// new account co-signs its own creation), WithdrawNonceAccount, and a
// standalone AdvanceNonceAccount. All pinned byte-for-byte to TWC AnySigner
// vectors (tx_solana_nonce_test.go).
//
// CreateNonceAccount is the one place a second, caller-supplied private key
// (the new nonce account's 32-byte ed25519 seed) enters a signer. It is used
// only inside this function; the expanded key is wiped before return, and the
// caller owns (and should wipe) the proto field's buffer. This mirrors the
// FromPrivateKeyBytes trust boundary — no key material is ever returned.

// solanaNonceAccountSpace is the on-chain size of a nonce account (bytes).
const solanaNonceAccountSpace = 80

// signSolanaCreateNonceAccount funds and initializes a new durable-nonce
// account. The signing wallet pays rent and becomes the nonce authority.
func (w *HDWallet) signSolanaCreateNonceAccount(symbol Symbol, index uint32, in *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	cn := in.GetCreateNonceAccount()
	seed := cn.GetNonceAccountPrivateKey()
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: solana: nonce_account_private_key must be 32 bytes", ErrTxInput)
	}
	payer, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(payer) != 32 {
		return nil, fmt.Errorf("%w: solana: expected 32-byte ed25519 key", ErrTxInput)
	}
	blockhash, err := base58DecodeFixed(in.GetRecentBlockhash(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent_blockhash: %v", ErrTxInput, err)
	}
	sysvarRBH, err := base58DecodeFixed(solanaSysvarRecentBlockhashesID, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent-blockhashes sysvar: %v", ErrTxInput, err)
	}
	rentSysvar, err := base58DecodeFixed(solanaSysvarRentID, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: rent sysvar: %v", ErrTxInput, err)
	}
	nonce, advSysvar, err := solanaNonceParams(in) // optional durable nonce on top
	if err != nil {
		return nil, err
	}

	// The new nonce account must co-sign; expand its seed, wipe before return.
	noncePriv := ed25519.NewKeyFromSeed(seed)
	defer wipe(noncePriv)
	noncePub := []byte(noncePriv.Public().(ed25519.PublicKey))

	var instrs []solanaInstruction
	if nonce != nil {
		instrs = append(instrs, solanaInstrAdvanceNonce(nonce, payer, advSysvar))
	}
	instrs = append(instrs,
		solanaInstrCreateAccount(payer, noncePub, cn.GetRent(), solanaNonceAccountSpace, solanaSystemProgramID),
		solanaInstrInitNonce(noncePub, sysvarRBH, rentSysvar, payer),
	)
	message := solanaCompileMessage(payer, instrs, blockhash)

	// Two required signatures, in key order: payer (wallet), then nonce account.
	sig, err := w.SignIndex(symbol, index, message)
	if err != nil {
		return nil, err
	}
	payerSig := sig.Bytes()
	if len(payerSig) != 64 {
		return nil, fmt.Errorf("%w: solana: expected 64-byte signature", ErrTxInput)
	}
	nonceSig := ed25519.Sign(noncePriv, message)

	tx := make([]byte, 0, 1+2*64+len(message))
	tx = append(tx, solanaCompactU16(2)...)
	tx = append(tx, payerSig...)
	tx = append(tx, nonceSig...)
	tx = append(tx, message...)
	return &txsolana.SigningOutput{
		Encoded: base58Encode(base58BTC, tx),
		Raw:     tx,
		// The fee-payer's signature IS the transaction id.
		TxId: base58Encode(base58BTC, payerSig),
	}, nil
}

// signSolanaWithdrawNonceAccount withdraws lamports from a nonce account the
// wallet key is authority over; supports an optional durable nonce.
func (w *HDWallet) signSolanaWithdrawNonceAccount(symbol Symbol, index uint32, in *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	wn := in.GetWithdrawNonceAccount()
	authority, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(authority) != 32 {
		return nil, fmt.Errorf("%w: solana: expected 32-byte ed25519 key", ErrTxInput)
	}
	withdrawFrom, err := base58DecodeFixed(wn.GetNonceAccount(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: nonce_account: %v", ErrTxInput, err)
	}
	recipient, err := base58DecodeFixed(wn.GetRecipient(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recipient: %v", ErrTxInput, err)
	}
	blockhash, err := base58DecodeFixed(in.GetRecentBlockhash(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent_blockhash: %v", ErrTxInput, err)
	}
	sysvarRBH, err := base58DecodeFixed(solanaSysvarRecentBlockhashesID, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent-blockhashes sysvar: %v", ErrTxInput, err)
	}
	rentSysvar, err := base58DecodeFixed(solanaSysvarRentID, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: rent sysvar: %v", ErrTxInput, err)
	}
	nonce, advSysvar, err := solanaNonceParams(in)
	if err != nil {
		return nil, err
	}

	var instrs []solanaInstruction
	if nonce != nil {
		instrs = append(instrs, solanaInstrAdvanceNonce(nonce, authority, advSysvar))
	}
	instrs = append(instrs, solanaInstrWithdrawNonce(withdrawFrom, recipient, sysvarRBH, rentSysvar, authority, wn.GetValue()))
	message := solanaCompileMessage(authority, instrs, blockhash)
	return w.solanaFinishTx(symbol, index, message)
}

// signSolanaAdvanceNonceAccount advances a durable nonce with no other
// operation (periodic refresh / invalidating a previously signed tx).
func (w *HDWallet) signSolanaAdvanceNonceAccount(symbol Symbol, index uint32, in *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	an := in.GetAdvanceNonceAccount()
	if in.GetNonceAccount() != "" {
		return nil, fmt.Errorf("%w: solana: nonce_account input is not supported for a standalone AdvanceNonceAccount", ErrTxInput)
	}
	authority, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(authority) != 32 {
		return nil, fmt.Errorf("%w: solana: expected 32-byte ed25519 key", ErrTxInput)
	}
	nonceAcct, err := base58DecodeFixed(an.GetNonceAccount(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: nonce_account: %v", ErrTxInput, err)
	}
	blockhash, err := base58DecodeFixed(in.GetRecentBlockhash(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent_blockhash: %v", ErrTxInput, err)
	}
	sysvarRBH, err := base58DecodeFixed(solanaSysvarRecentBlockhashesID, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent-blockhashes sysvar: %v", ErrTxInput, err)
	}
	message := solanaCompileMessage(authority, []solanaInstruction{
		solanaInstrAdvanceNonce(nonceAcct, authority, sysvarRBH),
	}, blockhash)
	return w.solanaFinishTx(symbol, index, message)
}
