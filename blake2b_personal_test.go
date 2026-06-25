package hdwallet

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// TestBlake2bPersonalMatchesStdlib pins the hand-rolled BLAKE2b core: with a
// zero personalization it must equal golang.org/x/crypto/blake2b.Sum256 across a
// range of input lengths (empty, single block, exact block multiples, and
// multi-block). This proves the compression function, counter handling and
// finalization are byte-correct; the personalized path adds only the h[6]/h[7]
// initialization and is pinned end-to-end by the Zcash transaction vector.
func TestBlake2bPersonalMatchesStdlib(t *testing.T) {
	for _, n := range []int{0, 1, 31, 32, 55, 64, 127, 128, 129, 200, 256, 257, 1000} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + 3)
		}
		got := blake2bPersonal(32, nil, data)
		want := blake2b.Sum256(data)
		if !bytes.Equal(got, want[:]) {
			t.Fatalf("blake2bPersonal(32, nil, %d bytes) = %x, want %x", n, got, want[:])
		}
	}
}

// TestBlake2bPersonalizationChangesDigest is a sanity check that a non-zero
// personalization actually alters the digest (so the parameter wiring is live).
func TestBlake2bPersonalizationChangesDigest(t *testing.T) {
	data := []byte("zip-243 sighash input")
	plain := blake2bPersonal(32, nil, data)
	pers := blake2bPersonal(32, []byte("ZcashSigHash\xbb\x09\xb8\x76"), data)
	if bytes.Equal(plain, pers) {
		t.Fatal("personalized digest equals unpersonalized digest")
	}
	if len(pers) != 32 {
		t.Fatalf("digest length = %d, want 32", len(pers))
	}
}
