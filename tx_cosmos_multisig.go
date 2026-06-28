package hdwallet

// Cosmos LegacyAminoMultisig — roadmap.
//
// Cosmos multisig uses LEGACY_AMINO_JSON sign mode (not DIRECT) with a
// ThresholdMultisigPubKey assembled from N compressed secp256k1 keys plus a
// bitarray tracking which signers contributed.  The current tx_cosmos.go
// implementation signs in DIRECT mode (SIGN_MODE_DIRECT = 1), which is
// incompatible with the multisig flow.
//
// Deferred because:
//  1. No byte-identical authoritative vector is publicly available from Trust
//     Wallet Core's AnySigner for Cosmos LegacyAminoMultisig — TWC does not
//     ship a Cosmos multisig test in its AnySigner test suite as of v4.x.
//  2. Implementing AMINO_JSON sign mode (cosmosAminoSignDoc, sort-keys JSON
//     canonicalization, the LEGACY_AMINO_JSON wire format) is a non-trivial
//     additive feature; shipping it without a byte-exact vector risks
//     producing an invalid on-chain signature.
//  3. The compact bitarray encoding (BitArray{ count, elems []uint64 }) and
//     the protobuf MultiSignature / CompactBitArray types need new txproto
//     definitions.
//
// When implemented this file should provide:
//   - BuildCosmosMultisigAuthInfo: assemble AuthInfo with a
//     ThresholdMultisigPubKey (pubKey type_url
//     "/cosmos.crypto.multisig.LegacyAminoPubKey"), ordered public keys, and
//     a threshold.
//   - SignCosmosMultisig: produce this signer's single-key partial signature
//     (sha256(AMINO-JSON sign doc)), returning a SignDoc-contribution that the
//     combiner can merge.
//   - CombineCosmosMultisig: assemble a MultiSignature proto from M partial
//     signatures, set the corresponding bits in the CompactBitArray, and
//     produce the final broadcast TxRaw.
//
// roadmap: implement when a byte-exact TWC or cosmjs/Keplr multisig vector
// becomes available to pin correctness.  Track in tx_cosmos_multisig_test.go.
