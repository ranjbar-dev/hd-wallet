package hdwallet

import (
	"bytes"
	"testing"
)

// NOTE: All Babylon tests are skipped pending an authoritative TWC byte vector.
// The structural assertions below confirm the builders produce the correct
// script prefix/opcode layout; they do not pin against an external vector.
// Un-skip and add the expected hex once an official Babylon TWC vector exists.

// TestBabylonTimelockLeaf verifies the structural encoding of the timelock leaf:
//
//	<32-byte push> OP_CHECKSIGVERIFY <csv-bytes push> OP_CSV OP_DROP OP_TRUE
func TestBabylonTimelockLeaf(t *testing.T) {
	t.Skip("TODO: no authoritative TWC byte-vector for Babylon staking")

	stakerXonly := make([]byte, 32)
	stakerXonly[0] = 0x01

	script := BuildBabylonTimelockLeaf(stakerXonly, 1008)

	// First byte must be 0x20 (push 32 bytes).
	if script[0] != 0x20 {
		t.Fatalf("expected script[0]=0x20 (push 32), got 0x%02x", script[0])
	}
	// Byte at offset 33 (after the 32-byte key) must be OP_CHECKSIGVERIFY.
	if script[33] != 0xad {
		t.Fatalf("expected script[33]=0xad (OP_CHECKSIGVERIFY), got 0x%02x", script[33])
	}
	// OP_CSV (0xb2) must appear somewhere in the script.
	if !bytes.Contains(script, []byte{0xb2}) {
		t.Fatal("expected OP_CSV (0xb2) in timelock leaf script")
	}
	// OP_DROP (0x75) must appear.
	if !bytes.Contains(script, []byte{0x75}) {
		t.Fatal("expected OP_DROP (0x75) in timelock leaf script")
	}
	// OP_TRUE / OP_1 (0x51) must appear at the end.
	if script[len(script)-1] != 0x51 {
		t.Fatalf("expected script[-1]=0x51 (OP_TRUE), got 0x%02x", script[len(script)-1])
	}
}

// TestBabylonStakingOutput verifies that BuildBabylonStakingOutput returns a
// valid 34-byte P2TR scriptPubKey (OP_1 <32-byte xonly>).
func TestBabylonStakingOutput(t *testing.T) {
	t.Skip("TODO: no authoritative TWC byte-vector for Babylon staking")

	stakerKey := make([]byte, 32)
	stakerKey[0] = 0x01

	// Use a minimal covenant key (a valid 33-byte compressed key placeholder
	// is not required for the structural check; use a 32-byte x-only stub).
	covenantKey := make([]byte, 32)
	covenantKey[0] = 0x02

	scriptPubKey, err := BuildBabylonStakingOutput(stakerKey, [][]byte{covenantKey}, 1, 1008)
	if err != nil {
		t.Fatalf("BuildBabylonStakingOutput: %v", err)
	}
	if len(scriptPubKey) != 34 {
		t.Fatalf("expected 34-byte P2TR scriptPubKey, got %d bytes", len(scriptPubKey))
	}
	// P2TR: OP_1 (0x51) <OP_DATA_32 = 0x20> <32-byte xonly>
	if scriptPubKey[0] != 0x51 {
		t.Fatalf("expected scriptPubKey[0]=0x51 (OP_1), got 0x%02x", scriptPubKey[0])
	}
	if scriptPubKey[1] != 0x20 {
		t.Fatalf("expected scriptPubKey[1]=0x20 (push 32), got 0x%02x", scriptPubKey[1])
	}
}

// TestBabylonOpReturn verifies that BuildBabylonOpReturn produces a script that
// begins with OP_RETURN (0x6a) and contains the expected tag bytes.
func TestBabylonOpReturn(t *testing.T) {
	t.Skip("TODO: no authoritative TWC byte-vector for Babylon staking")

	stakerXonly := make([]byte, 32)
	fpXonly := make([]byte, 32)
	stakingTime := uint16(1008)

	result := BuildBabylonOpReturn(stakerXonly, fpXonly, stakingTime)

	// First byte must be OP_RETURN.
	if result[0] != 0x6a {
		t.Fatalf("expected result[0]=0x6a (OP_RETURN), got 0x%02x", result[0])
	}

	// The tag content: "bbn\x01" + 0x00 + 32 zero bytes (staker) + 32 zero bytes (fp) + LE(1008)
	magic := []byte{'b', 'b', 'n', '\x01'}
	if !bytes.Contains(result, magic) {
		t.Fatal("expected magic tag 'bbn\\x01' in OP_RETURN output")
	}

	// staking_time as little-endian uint16: 1008 = 0x03f0 → [0xf0, 0x03]
	ltBytes := []byte{byte(stakingTime), byte(stakingTime >> 8)}
	if !bytes.Contains(result, ltBytes) {
		t.Fatalf("expected staking time bytes %v in OP_RETURN output", ltBytes)
	}
}
