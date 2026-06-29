package hdwallet

// Babylon BTC-staking output builders.
//
// Reference: https://github.com/babylonlabs-io/babylon/blob/main/docs/staking-script.md
//
// A Babylon staking output is a P2TR (taproot) output whose tap-tree commits to
// three leaves:
//
//	leaf 0 – Timelock:    <staker_xonly> OP_CHECKSIGVERIFY <staking_time> OP_CSV OP_DROP OP_TRUE
//	leaf 1 – Unbonding:   <staker_xonly> OP_CHECKSIGVERIFY <cov_0> OP_CHECKSIG [<cov_i> OP_CHECKSIGADD...] <quorum> OP_NUMEQUAL
//	leaf 2 – Slashing:    same structure as Unbonding
//
// The taproot internal key is the BIP-341 NUMS (nothing-up-my-sleeve) point so
// the key-path spend is effectively disabled (the discrete log is unknown).
//
// An optional OP_RETURN output identifies the stake on-chain:
//
//	OP_RETURN "bbn\x01" <version(1)> <staker_xonly(32)> <fp_xonly(32)> <staking_time_LE(2)>
//
// All functions in this file are pure (no key material, no network I/O).
// None have authoritative TWC byte vectors yet; tests are skipped and marked
// for future pinning once an official vector is published.

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// babylonNUMSKeyBytes is the 33-byte compressed encoding of the BIP-341 NUMS
// (nothing-up-my-sleeve) unspendable internal key.  Its x-coordinate is the
// SHA-256 of the ASCII string "BIP0341" incremented until a valid point is
// found; the specific value is the one used by the Bitcoin ecosystem:
//
//	02 50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
//
// This is widely known to have no known discrete-log preimage.
var babylonNUMSKeyBytes = []byte{
	0x02,
	0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
	0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
	0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
	0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
}

// babylonNUMSKey parses and returns the unspendable internal key.
// The parse cannot fail for the hard-coded bytes; panics on programmer error.
func babylonNUMSKey() *btcec.PublicKey {
	k, err := btcec.ParsePubKey(babylonNUMSKeyBytes)
	if err != nil {
		panic("hdwallet: babylon: failed to parse hard-coded NUMS key: " + err.Error())
	}
	return k
}

// babylonXonly extracts the 32-byte x-only form of a public key.
// key may be 33-byte compressed (0x02/0x03 prefix) or 32-byte x-only.
// Returns an error for any other length.
func babylonXonly(key []byte) ([]byte, error) {
	switch len(key) {
	case 32:
		return key, nil
	case 33:
		// Parse and re-serialize so that the x-only form is always
		// normalised (even y-coordinate per BIP-340).
		pk, err := btcec.ParsePubKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid compressed pubkey: %w", err)
		}
		return schnorr.SerializePubKey(pk), nil
	default:
		return nil, fmt.Errorf("pubkey must be 32-byte x-only or 33-byte compressed, got %d bytes", len(key))
	}
}

// BuildBabylonTimelockLeaf builds the tapscript leaf for the Babylon timelock
// spending path:
//
//	<staker_xonly> OP_CHECKSIGVERIFY <staking_time_LE2> OP_CSV OP_DROP OP_TRUE
//
// stakingTime is encoded as a 2-byte little-endian uint16 (Bitcoin script number
// for OP_CSV). stakerXonly must be a 32-byte x-only public key.
func BuildBabylonTimelockLeaf(stakerXonly []byte, stakingTime uint16) []byte {
	// CSV value in minimal little-endian script encoding (2 bytes for uint16).
	csvBytes := []byte{byte(stakingTime), byte(stakingTime >> 8)} // #nosec G115 -- stakingTime is a uint16
	script := make([]byte, 0, 33+1+3+1+1+1)
	script = append(script, btcPush(stakerXonly)...)
	script = append(script, 0xad) // OP_CHECKSIGVERIFY
	script = append(script, btcPush(csvBytes)...)
	script = append(script, 0xb2) // OP_CSV
	script = append(script, 0x75) // OP_DROP
	script = append(script, 0x51) // OP_TRUE (OP_1)
	return script
}

// buildBabylonCovenantLeaf builds the tapscript leaf for the Babylon unbonding
// and slashing spending paths (both use the same structure):
//
//	<staker_xonly> OP_CHECKSIGVERIFY
//	<cov_0> OP_CHECKSIG <cov_1> OP_CHECKSIGADD ... <cov_n-1> OP_CHECKSIGADD
//	<quorum> OP_NUMEQUAL
//
// covenantXonlyKeys: each element is a 32-byte x-only covenant public key.
// quorum: the required number of covenant signatures (1 ≤ quorum ≤ n).
func buildBabylonCovenantLeaf(stakerXonly []byte, covenantXonlyKeys [][]byte, quorum int) []byte {
	script := make([]byte, 0, 64+len(covenantXonlyKeys)*34+2)
	script = append(script, btcPush(stakerXonly)...)
	script = append(script, 0xad) // OP_CHECKSIGVERIFY
	for i, ck := range covenantXonlyKeys {
		script = append(script, btcPush(ck)...)
		if i == 0 {
			script = append(script, 0xac) // OP_CHECKSIG (first key)
		} else {
			script = append(script, 0xba) // OP_CHECKSIGADD (subsequent keys)
		}
	}
	// Push quorum as a script number.
	// For values 1..16 use OP_1..OP_16 (0x51..0x60); for 0 use OP_0 (0x00);
	// otherwise push as minimal data.
	switch {
	case quorum == 0:
		script = append(script, 0x00) // OP_0
	case quorum >= 1 && quorum <= 16:
		script = append(script, byte(0x50+quorum)) // #nosec G115 -- quorum validated 1..16
	default:
		// Push as minimal script number (little-endian, high bit = sign).
		script = append(script, btcPush(scriptNum(quorum))...)
	}
	script = append(script, 0x9c) // OP_NUMEQUAL
	return script
}

// scriptNum encodes a small positive integer as a minimal Bitcoin script number
// (little-endian, high bit used for sign; same encoding Bitcoin script uses for
// numbers pushed via OP_PUSHDATA).
func scriptNum(n int) []byte {
	if n == 0 {
		return []byte{}
	}
	var result []byte
	neg := n < 0
	absVal := n
	if neg {
		absVal = -n
	}
	for absVal > 0 {
		result = append(result, byte(absVal&0xff)) // #nosec G115 -- byte extraction
		absVal >>= 8
	}
	// If the high bit of the last byte is set, add a sign byte.
	if result[len(result)-1]&0x80 != 0 {
		if neg {
			result = append(result, 0x80)
		} else {
			result = append(result, 0x00)
		}
	} else if neg {
		result[len(result)-1] |= 0x80
	}
	return result
}

// BuildBabylonStakingOutput computes the P2TR scriptPubKey for a Babylon
// staking output.  It assembles a tap-tree with a timelock leaf, an unbonding
// leaf, and a slashing leaf, rooted under the BIP-341 NUMS unspendable internal
// key.
//
//   - stakerKey:       33-byte compressed or 32-byte x-only public key of the staker.
//   - covenantKeys:    one or more 33-byte compressed or 32-byte x-only covenant keys.
//   - covenantQuorum:  the m in the m-of-n covenant multisig (1 ≤ quorum ≤ len(covenantKeys)).
//   - stakingTime:     the CSV lockup period in blocks (uint16).
//
// Returns the 34-byte P2TR scriptPubKey: OP_1 <32-byte output xonly>.
func BuildBabylonStakingOutput(stakerKey []byte, covenantKeys [][]byte, covenantQuorum int, stakingTime uint16) (scriptPubKey []byte, err error) {
	if len(covenantKeys) == 0 {
		return nil, fmt.Errorf("%w: babylon: at least one covenant key required", ErrTxInput)
	}
	if covenantQuorum < 1 || covenantQuorum > len(covenantKeys) {
		return nil, fmt.Errorf("%w: babylon: covenant quorum %d out of range [1,%d]", ErrTxInput, covenantQuorum, len(covenantKeys))
	}

	stakerXonly, err := babylonXonly(stakerKey)
	if err != nil {
		return nil, fmt.Errorf("%w: babylon: staker key: %v", ErrTxInput, err)
	}

	covXonlyKeys := make([][]byte, len(covenantKeys))
	for i, ck := range covenantKeys {
		xo, err := babylonXonly(ck)
		if err != nil {
			return nil, fmt.Errorf("%w: babylon: covenant key %d: %v", ErrTxInput, i, err)
		}
		covXonlyKeys[i] = xo
	}

	timelockScript := BuildBabylonTimelockLeaf(stakerXonly, stakingTime)
	covenantScript := buildBabylonCovenantLeaf(stakerXonly, covXonlyKeys, covenantQuorum)

	timelockLeaf := txscript.NewBaseTapLeaf(timelockScript)
	unbondingLeaf := txscript.NewBaseTapLeaf(covenantScript)
	slashingLeaf := txscript.NewBaseTapLeaf(covenantScript)

	tree := txscript.AssembleTaprootScriptTree(timelockLeaf, unbondingLeaf, slashingLeaf)
	rootHash := tree.RootNode.TapHash()
	merkleRoot := rootHash[:]

	internalKey := babylonNUMSKey()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, merkleRoot)

	return txscript.PayToTaprootScript(outputKey)
}

// BuildBabylonOpReturn builds the OP_RETURN identifier output used by the
// Babylon protocol to tag a staking transaction on-chain.
//
// Format (after OP_RETURN):
//
//	"bbn\x01" (4 bytes magic + version byte 0x01)
//	+ version byte 0x00
//	+ stakerXonly (32 bytes)
//	+ finalityProviderXonly (32 bytes, or 32 zero bytes if nil)
//	+ stakingTime as 2-byte little-endian uint16
//
// stakerXonly must be a 32-byte x-only public key.
// finalityProviderXonly must be a 32-byte x-only key, or nil (32 zero bytes used).
// Returns the full script: 0x6a (OP_RETURN) + minimal data push of the tag.
func BuildBabylonOpReturn(stakerXonly []byte, finalityProviderXonly []byte, stakingTime uint16) []byte {
	fpXonly := finalityProviderXonly
	if len(fpXonly) != 32 {
		fpXonly = make([]byte, 32) // 32 zero bytes
	}

	tag := make([]byte, 0, 4+1+32+32+2)
	tag = append(tag, 'b', 'b', 'n', '\x01') // magic
	tag = append(tag, 0x00)                  // version
	tag = append(tag, stakerXonly[:32]...)
	tag = append(tag, fpXonly[:32]...)
	tag = append(tag, byte(stakingTime), byte(stakingTime>>8)) // #nosec G115 -- stakingTime is a uint16

	// OP_RETURN + minimal push of tag.
	script := make([]byte, 0, 2+len(tag))
	script = append(script, 0x6a) // OP_RETURN
	if len(tag) < 76 {
		script = append(script, byte(len(tag))) // #nosec G115 -- len(tag) < 76
	} else {
		script = append(script, 0x4c, byte(len(tag))) // OP_PUSHDATA1; #nosec G115 -- len in 76..80
	}
	script = append(script, tag...)
	return script
}
