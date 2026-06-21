package hdwallet

import (
	"encoding/hex"
	"testing"
)

// Test vectors are taken verbatim from the SLIP-0010 specification
// (https://github.com/satoshilabs/slips/blob/master/slip-0010.md), Test Vector
// 1 for ed25519 and nist256p1. Proving derivation against the spec means the
// per-curve key derivation is correct independently of any coin's encoder.

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

func TestSLIP10Nist256p1Vector1(t *testing.T) {
	seed := mustHex(t, slip10Seed1)
	cases := []struct {
		path  string
		chain string
		priv  string
		pub   string
	}{
		{"m", "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea", "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2", "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8"},
		{"m/0'", "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11", "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c", "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c"},
		{"m/0'/1", "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c", "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129", "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844"},
		{"m/0'/1/2'", "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318", "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7", "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0"},
		{"m/0'/1/2'/2", "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0", "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa", "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20"},
		{"m/0'/1/2'/2/1000000000", "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059", "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119", "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			path, err := parsePath(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			node, err := deriveNist256p1(seed, path)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(node.chain); got != tc.chain {
				t.Errorf("chain code = %s, want %s", got, tc.chain)
			}
			if got := hex.EncodeToString(node.key); got != tc.priv {
				t.Errorf("private key = %s, want %s", got, tc.priv)
			}
			if got := hex.EncodeToString(compressP256(node.key)); got != tc.pub {
				t.Errorf("public key = %s, want %s", got, tc.pub)
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
