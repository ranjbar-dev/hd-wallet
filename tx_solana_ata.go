package hdwallet

import (
	"fmt"

	txsolana "github.com/ranjbar-dev/hd-wallet/txproto/solana"
)

// Associated-token-account transaction shapes: CreateTokenAccount (fund the
// canonical ATA for a wallet+mint) and CreateAndTransferToken (create the
// recipient's ATA and TransferChecked into it — the standard token-withdrawal
// op for a recipient that may not have a token account yet). Both pinned
// byte-for-byte to TWC AnySigner vectors (tx_solana_ata_test.go).
//
// Fund-critical guard: the ATA is always derived internally via
// SolanaTokenAccountAddress; a caller-supplied token address must match it
// exactly, otherwise rent/tokens could fund an account nobody controls.

// solanaATAAccounts decodes the fixed program/sysvar accounts every ATA
// instruction references.
func solanaATAAccounts() (tokenProgram, rent, ataProgram []byte, err error) {
	if tokenProgram, err = base58DecodeFixed(solanaTokenProgramID, 32); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: solana: token program id: %v", ErrTxInput, err)
	}
	if rent, err = base58DecodeFixed(solanaSysvarRentID, 32); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: solana: rent sysvar: %v", ErrTxInput, err)
	}
	if ataProgram, err = base58DecodeFixed(solanaATAProgramID, 32); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: solana: ata program id: %v", ErrTxInput, err)
	}
	return tokenProgram, rent, ataProgram, nil
}

// solanaDeriveATAGuarded derives the canonical ATA for (wallet, mint) and, if
// the caller supplied an expected address, requires an exact match.
func solanaDeriveATAGuarded(wallet, mint, supplied string) ([]byte, error) {
	derived, err := SolanaTokenAccountAddress(wallet, mint)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: derive ata: %v", ErrTxInput, err)
	}
	if supplied != "" && supplied != derived {
		return nil, fmt.Errorf("%w: solana: token address %s does not match derived ata %s for wallet %s",
			ErrTxInput, supplied, derived, wallet)
	}
	return base58DecodeFixed(derived, 32)
}

// signSolanaCreateTokenAccount builds and signs a CreateAssociatedTokenAccount
// transaction. The signing wallet funds the account; main_address owns it.
func (w *HDWallet) signSolanaCreateTokenAccount(symbol Symbol, index uint32, in *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	cta := in.GetCreateTokenAccountTransaction()
	if in.GetNonceAccount() != "" {
		return nil, fmt.Errorf("%w: solana: durable nonce is not supported for CreateTokenAccount (no authoritative vector)", ErrTxInput)
	}
	funder, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(funder) != 32 {
		return nil, fmt.Errorf("%w: solana: expected 32-byte ed25519 key", ErrTxInput)
	}
	wallet, err := base58DecodeFixed(cta.GetMainAddress(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: main_address: %v", ErrTxInput, err)
	}
	mint, err := base58DecodeFixed(cta.GetTokenMintAddress(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: token_mint_address: %v", ErrTxInput, err)
	}
	ata, err := solanaDeriveATAGuarded(cta.GetMainAddress(), cta.GetTokenMintAddress(), cta.GetTokenAddress())
	if err != nil {
		return nil, err
	}
	blockhash, err := base58DecodeFixed(in.GetRecentBlockhash(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent_blockhash: %v", ErrTxInput, err)
	}
	tokenProgram, rent, ataProgram, err := solanaATAAccounts()
	if err != nil {
		return nil, err
	}

	message := solanaCompileMessage(funder, []solanaInstruction{
		solanaInstrCreateATA(funder, ata, wallet, mint, solanaSystemProgramID, tokenProgram, rent, ataProgram),
	}, blockhash)
	return w.solanaFinishTx(symbol, index, message)
}

// signSolanaCreateAndTransferToken creates the recipient's ATA and transfers
// SPL tokens into it in one transaction; supports an optional durable nonce.
func (w *HDWallet) signSolanaCreateAndTransferToken(symbol Symbol, index uint32, in *txsolana.SigningInput) (*txsolana.SigningOutput, error) {
	ct := in.GetCreateAndTransferTokenTransaction()
	owner, err := w.PublicKeyIndex(symbol, index)
	if err != nil {
		return nil, err
	}
	if len(owner) != 32 {
		return nil, fmt.Errorf("%w: solana: expected 32-byte ed25519 key", ErrTxInput)
	}
	if ct.GetDecimals() > 255 {
		return nil, fmt.Errorf("%w: solana: decimals %d out of range", ErrTxInput, ct.GetDecimals())
	}
	recipientWallet, err := base58DecodeFixed(ct.GetRecipientMainAddress(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recipient_main_address: %v", ErrTxInput, err)
	}
	mint, err := base58DecodeFixed(ct.GetTokenMintAddress(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: token_mint_address: %v", ErrTxInput, err)
	}
	source, err := base58DecodeFixed(ct.GetSenderTokenAddress(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: sender_token_address: %v", ErrTxInput, err)
	}
	recipientATA, err := solanaDeriveATAGuarded(ct.GetRecipientMainAddress(), ct.GetTokenMintAddress(), ct.GetRecipientTokenAddress())
	if err != nil {
		return nil, err
	}
	blockhash, err := base58DecodeFixed(in.GetRecentBlockhash(), 32)
	if err != nil {
		return nil, fmt.Errorf("%w: solana: recent_blockhash: %v", ErrTxInput, err)
	}
	tokenProgram, rent, ataProgram, err := solanaATAAccounts()
	if err != nil {
		return nil, err
	}
	nonce, sysvarRBH, err := solanaNonceParams(in)
	if err != nil {
		return nil, err
	}

	decimals := byte(ct.GetDecimals()) // #nosec G115 -- range-checked (<= 255) above
	var instrs []solanaInstruction
	if nonce != nil {
		instrs = append(instrs, solanaInstrAdvanceNonce(nonce, owner, sysvarRBH))
	}
	instrs = append(instrs,
		solanaInstrCreateATA(owner, recipientATA, recipientWallet, mint, solanaSystemProgramID, tokenProgram, rent, ataProgram),
		solanaInstrTransferChecked(source, mint, recipientATA, owner, tokenProgram, ct.GetAmount(), decimals),
	)
	message := solanaCompileMessage(owner, instrs, blockhash)
	return w.solanaFinishTx(symbol, index, message)
}
