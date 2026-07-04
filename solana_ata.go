package hdwallet

import (
	"crypto/sha256"
	"fmt"

	"filippo.io/edwards25519"
)

// Solana associated token account (ATA) derivation — the SPL Associated Token
// Account program's program-derived address (PDA) scheme.
//
// The canonical token account for (wallet, mint) is
//
//    findProgramAddress(seeds = [wallet, TOKEN_PROGRAM_ID, mint],
//                       programID = ATA_PROGRAM_ID)
//
// where a PDA candidate for bump b is
//
//    sha256(seed1 ‖ … ‖ seedN ‖ [b] ‖ programID ‖ "ProgramDerivedAddress")
//
// and the first candidate (bump 255 down to 0) that is NOT a valid ed25519
// curve point is the address — PDAs must have no possible private key. The
// off-curve check uses filippo.io/edwards25519 (the implementation vendored
// inside Go's own crypto/ed25519), because the stdlib does not export point
// decompression. Derivation is pure and offline: no secrets, no network.
//
// Pinned against seven Trust Wallet Core (wallet, mint) → ATA triples, each
// tied to an on-chain-confirmed transaction (solana_ata_test.go).

// solanaATAProgramID is the SPL Associated Token Account program. It is a
// public well-known program address, not a secret.
const solanaATAProgramID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" // #nosec G101 -- public program id, not a credential

// Well-known sysvar accounts referenced by nonce/ATA instructions.
const (
	solanaSysvarRentID              = "SysvarRent111111111111111111111111111111111"
	solanaSysvarRecentBlockhashesID = "SysvarRecentB1ockHashes11111111111111111111"
)

// solanaPDAMarker terminates every PDA hash preimage (SPL convention).
var solanaPDAMarker = []byte("ProgramDerivedAddress")

// solanaIsOnCurve reports whether b is a valid ed25519 point encoding. A PDA
// must be OFF the curve; a candidate that decompresses is rejected.
func solanaIsOnCurve(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	_, err := new(edwards25519.Point).SetBytes(b)
	return err == nil
}

// solanaFindProgramAddress derives the program-derived address for seeds under
// programID, scanning bump 255 down to 0 and returning the first off-curve
// candidate (solana-sdk Pubkey::find_program_address).
func solanaFindProgramAddress(seeds [][]byte, programID []byte) ([]byte, error) {
	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		for _, s := range seeds {
			h.Write(s)
		}
		h.Write([]byte{byte(bump)}) // #nosec G115 -- loop bounded to [0,255]
		h.Write(programID)
		h.Write(solanaPDAMarker)
		candidate := h.Sum(nil)
		if !solanaIsOnCurve(candidate) {
			return candidate, nil
		}
	}
	// Unreachable in practice (probability ~2^-256), but never guess an address.
	return nil, fmt.Errorf("%w: no off-curve program-derived address", ErrInvalidAddress)
}

// SolanaTokenAccountAddress returns the SPL associated token account (ATA) —
// the canonical token account address — for a wallet address and token mint,
// both base58. It is a pure offline derivation: no wallet, no secrets, no
// network. Use it to compute deposit token accounts and withdrawal
// destinations for SPL tokens.
//
// This derives against the classic SPL Token program; for a Token-2022
// (Token Extensions) mint use SolanaTokenAccountAddressWithProgram.
func SolanaTokenAccountAddress(walletAddress, mintAddress string) (string, error) {
	return SolanaTokenAccountAddressWithProgram(walletAddress, mintAddress, solanaTokenProgramID)
}

// SolanaTokenAccountAddressWithProgram is SolanaTokenAccountAddress with an
// explicit token-program id (base58), so the ATA can be derived for the
// classic SPL Token program or the Token-2022 (Token Extensions) program —
// the seeds are [wallet, tokenProgramID, mint], and the token-program id enters
// the PDA derivation directly. Pure offline derivation: no wallet, no
// secrets, no network.
func SolanaTokenAccountAddressWithProgram(walletAddress, mintAddress, tokenProgramID string) (string, error) {
	wallet, err := base58DecodeFixed(walletAddress, 32)
	if err != nil {
		return "", fmt.Errorf("%w: solana wallet address: %v", ErrInvalidAddress, err)
	}
	mint, err := base58DecodeFixed(mintAddress, 32)
	if err != nil {
		return "", fmt.Errorf("%w: solana mint address: %v", ErrInvalidAddress, err)
	}
	tokenProgram, err := base58DecodeFixed(tokenProgramID, 32)
	if err != nil {
		return "", fmt.Errorf("%w: token program id: %v", ErrInvalidAddress, err)
	}
	ataProgram, err := base58DecodeFixed(solanaATAProgramID, 32)
	if err != nil {
		return "", fmt.Errorf("%w: ata program id: %v", ErrInvalidAddress, err)
	}
	pda, err := solanaFindProgramAddress([][]byte{wallet, tokenProgram, mint}, ataProgram)
	if err != nil {
		return "", err
	}
	return base58Encode(base58BTC, pda), nil
}
