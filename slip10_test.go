package hdwallet

import (
	"encoding/hex"
	"testing"
)

// Test vectors are taken verbatim from the SLIP-0010 specification
// (https://github.com/satoshilabs/slips/blob/master/slip-0010.md), Test Vector
// 1 for ed25519. Proving derivation against the spec means the per-curve key
// derivation is correct independently of any coin's encoder.

const slip10Seed1 = "000102030405060708090a0b0c0d0e0f"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestSLIP10Ed25519Vector1(t *testing.T) {
	seed := mustHex(t, slip10Seed1)
	cases := []struct {
		path  string
		chain string
		priv  string
		pub   string // SLIP-0010 lists the 33-byte 0x00-prefixed form
	}{
		{"m", "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"},
		{"m/0'", "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"},
		{"m/0'/1'", "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2", "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"},
		{"m/0'/1'/2'", "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c", "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9", "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"},
		{"m/0'/1'/2'/2'", "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc", "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662", "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"},
		{"m/0'/1'/2'/2'/1000000000'", "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230", "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793", "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			path, err := parsePath(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			node, err := deriveEd25519(seed, path)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(node.chain); got != tc.chain {
				t.Errorf("chain code = %s, want %s", got, tc.chain)
			}
			if got := hex.EncodeToString(node.key); got != tc.priv {
				t.Errorf("private key = %s, want %s", got, tc.priv)
			}
			// Spec public key is 0x00 || A; our derivation yields the 32-byte A.
			wantPub := tc.pub[2:]
			if got := hex.EncodeToString(ed25519PubFromSeed(node.key)); got != wantPub {
				t.Errorf("public key = %s, want %s", got, wantPub)
			}
		})
	}
}

func TestEd25519RejectsNonHardened(t *testing.T) {
	seed := mustHex(t, slip10Seed1)
	if _, err := deriveEd25519(seed, []uint32{0}); err == nil {
		t.Fatal("expected error for non-hardened ed25519 derivation, got nil")
	}
}
