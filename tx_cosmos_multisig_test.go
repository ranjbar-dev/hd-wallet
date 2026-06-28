package hdwallet

import "testing"

// TestCosmosMultisig_Roadmap is a placeholder for Cosmos LegacyAminoMultisig
// signing support.  It is skipped because:
//   - No byte-identical authoritative vector is available from Trust Wallet
//     Core, cosmjs, or Keplr for Cosmos threshold multisig.
//   - SIGN_MODE_LEGACY_AMINO_JSON (required for multisig) is not yet
//     implemented in tx_cosmos.go.
//
// See tx_cosmos_multisig.go for the full roadmap description.
func TestCosmosMultisig_Roadmap(t *testing.T) {
	t.Skip("Cosmos LegacyAminoMultisig signing is not yet implemented — " +
		"see tx_cosmos_multisig.go for the roadmap")
}
