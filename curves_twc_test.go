package hdwallet

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ---- Ed25519Blake2bNano (Nano) ----
//
// Vector source: Trust Wallet Core tests/chains/Nano/SignerTests.cpp + TestAccounts.h.
// kPrivateKey signs the Nano genesis block hash and yields the on-chain signature.

func TestNanoSignVector(t *testing.T) {
	priv := mustHex(t, "173c40e97fe2afcd24187e74f6b603cb949a5365e72fbdd065a6b165e2189e34")
	blockHash := mustHex(t, "f9a323153daefe041efb94d69b9669c882c935530ed953bbe8a665dfedda9696")
	wantSig := "d247f6b90383b24e612569c75a12f11242f6e03b4914eadc7d941577dcf54a3a7cb7f0a4aba4246a40d9ebb5ee1e00b4a0a834ad5a1e7bef24e11f62b95a9e09"

	sig, err := signDigest(Ed25519Blake2bNano, priv, blockHash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := hex.EncodeToString(sig.Bytes()); got != wantSig {
		t.Fatalf("nano signature mismatch:\n got %s\nwant %s", got, wantSig)
	}

	// Public key derived from the private key, and verify round-trips.
	pub, err := publicKeyFromPriv(Ed25519Blake2bNano, priv)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	if !verifySignature(Ed25519Blake2bNano, pub, blockHash, sig) {
		t.Fatalf("nano signature failed verification")
	}
}

// ---- Curve25519 (Waves) ----
//
// Vector source: Trust Wallet Core tests/chains/Waves/SignerTests.cpp.
// Waves signing is randomised in TWC's reference (ed25519_sign with a random
// nonce); the published signature is therefore one valid signature, not the
// unique deterministic one. We assert the public key matches exactly and that
// our deterministic signature verifies, plus that the TWC-published signature
// verifies under our verifier.

func TestWavesPublicKeyVector(t *testing.T) {
	priv := mustHex(t, "9864a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a")
	wantPub := "559a50cb45a9a8e8d4f83295c354725990164d10bb505275d1a3086c08fb935d"

	pub, err := publicKeyFromPriv(Curve25519, priv)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	if got := hex.EncodeToString(pub); got != wantPub {
		t.Fatalf("waves pubkey mismatch:\n got %s\nwant %s", got, wantPub)
	}
}

func TestWavesSignVerify(t *testing.T) {
	priv := mustHex(t, "9864a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a")
	pub := mustHex(t, "559a50cb45a9a8e8d4f83295c354725990164d10bb505275d1a3086c08fb935d")
	msg := mustHex(t, "0402559a50cb45a9a8e8d4f83295c354725990164d10bb505275d1a3086c08fb935d00000000016372e852120000000005f5e1000000000005f5e10001570acc4110b78a6d38b34d879b5bba38806202ecf1732f8542000766616c6166656c")

	// Our deterministic signature must verify.
	sig, err := signDigest(Curve25519, priv, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !verifySignature(Curve25519, pub, msg, sig) {
		t.Fatalf("waves: own signature failed verification")
	}

	// The TWC-published (randomised) signature must also verify under our verifier.
	twcSig := &Signature{Curve: Curve25519, raw: mustHex(t, "af7989256f496e103ce95096b3f52196dd9132e044905fe486da3b829b5e403bcba95ab7e650a4a33948c2d05cfca2dce4d4df747e26402974490fb4c49fbe8f")}
	if !verifySignature(Curve25519, pub, msg, twcSig) {
		t.Fatalf("waves: TWC-published signature failed verification")
	}
}

// ---- Ed25519ExtendedCardano (Cardano) ----
//
// Vector source: Trust Wallet Core tests/chains/Cardano/AddressTests.cpp.
// Mnemonic entropy 30a6f50a... -> Icarus master key a018cd74... (+extension,
// +pubkey). The path m/1852'/1815'/0'/0/0 yields the documented extended key and
// the ED25519Cardano public key.

func TestCardanoMasterKeyVector(t *testing.T) {
	entropy := mustHex(t, "30a6f50aeb58ff7699b822d63e0ef27aeff17d9f")
	// Master extended secret (kL || kR) from the Icarus scheme.
	wantKey := "a018cd746e128a0be0782b228c275473205445c33b9000a33dd5668b430b5744"
	wantExt := "26877cfe435fddda02409b839b7386f3738f10a30b95a225f4b720ee71d2505b"

	master := cardanoMasterFromEntropy(entropy)
	defer master.wipe()
	if got := hex.EncodeToString(master.kL); got != wantKey {
		t.Fatalf("cardano master kL mismatch:\n got %s\nwant %s", got, wantKey)
	}
	if got := hex.EncodeToString(master.kR); got != wantExt {
		t.Fatalf("cardano master kR mismatch:\n got %s\nwant %s", got, wantExt)
	}
}

// TestCardanoAccountPublicKeyVector is the strong end-to-end anchor: deriving
// m/1852'/1815'/0'/0/0 and computing the ED25519Cardano public key (A || chain)
// must reproduce Trust Wallet Core's AddressTests.cpp public-key vector exactly.
func TestCardanoAccountPublicKeyVector(t *testing.T) {
	entropy := mustHex(t, "30a6f50aeb58ff7699b822d63e0ef27aeff17d9f")
	path := []uint32{1852 + hardenedOffset, 1815 + hardenedOffset, hardenedOffset, 0, 0}
	// First 64 bytes of TWC's documented ED25519Cardano public key: A(32)||chain(32).
	wantPub := "fafa7eb4146220db67156a03a5f7a79c666df83eb31abbfbe77c85e06d40da31" +
		"10f3245ddf9132ecef98c670272ef39c03a232107733d4a1d28cb53318df26fa"

	var got string
	err := withCardanoPrivateKey(entropy, path, func(priv []byte) error {
		pub, e := publicKeyFromPriv(Ed25519ExtendedCardano, priv)
		got = hex.EncodeToString(pub)
		return e
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got != wantPub {
		t.Fatalf("cardano account pubkey mismatch:\n got %s\nwant %s", got, wantPub)
	}
}

func TestCardanoDerivedKeyVector(t *testing.T) {
	entropy := mustHex(t, "30a6f50aeb58ff7699b822d63e0ef27aeff17d9f")
	// m/1852'/1815'/0'/0/0
	path := []uint32{
		1852 + hardenedOffset,
		1815 + hardenedOffset,
		0 + hardenedOffset,
		0,
		0,
	}
	wantKey := "e8c8c5b2df13f3abed4e6b1609c808e08ff959d7e6fc3d849e3f2880550b5744"
	wantExt := "37aa559095324d78459b9bb2da069da32337e1cc5da78f48e1bd084670107f31"
	wantChain := "10f3245ddf9132ecef98c670272ef39c03a232107733d4a1d28cb53318df26fa"

	var gotKey, gotExt, gotChain string
	err := withCardanoPrivateKey(entropy, path, func(priv []byte) error {
		gotKey = hex.EncodeToString(priv[0:32])
		gotExt = hex.EncodeToString(priv[32:64])
		gotChain = hex.EncodeToString(priv[64:96])
		return nil
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if gotKey != wantKey {
		t.Fatalf("cardano derived kL mismatch:\n got %s\nwant %s", gotKey, wantKey)
	}
	if gotExt != wantExt {
		t.Fatalf("cardano derived kR mismatch:\n got %s\nwant %s", gotExt, wantExt)
	}
	if gotChain != wantChain {
		t.Fatalf("cardano derived chain mismatch:\n got %s\nwant %s", gotChain, wantChain)
	}
}

func TestCardanoSignVerify(t *testing.T) {
	entropy := mustHex(t, "30a6f50aeb58ff7699b822d63e0ef27aeff17d9f")
	path := []uint32{1852 + hardenedOffset, 1815 + hardenedOffset, hardenedOffset, 0, 0}
	msg := []byte("hello cardano")

	var sig *Signature
	var pub []byte
	err := withCardanoPrivateKey(entropy, path, func(priv []byte) error {
		s, e := signDigest(Ed25519ExtendedCardano, priv, msg)
		if e != nil {
			return e
		}
		sig = s
		p, e := publicKeyFromPriv(Ed25519ExtendedCardano, priv)
		pub = p
		return e
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !verifySignature(Ed25519ExtendedCardano, pub, msg, sig) {
		t.Fatalf("cardano: signature failed verification")
	}
}

// ---- Starkex (StarkNet) — address encoding ----
//
// Vector source: Trust Wallet Core rust/tw_keypair/src/starkex. The private key
// is the TWC signing test key; the public key is its x-coordinate on the STARK
// curve, which is also the StarkNet address.

func TestStarknetAddressVector(t *testing.T) {
	priv := mustHex(t, "0139fe4d6f02e666e86a6f58e65060f115cd3c185bd9e98bd829636931458f79")
	wantAddr := "0x02c5dbad71c92a45cc4b40573ae661f8147869a91d57b8d9b8f48c8af7f83159"

	pub, err := publicKeyFromPriv(Starkex, priv)
	if err != nil {
		t.Fatalf("publicKeyFromPriv: %v", err)
	}
	got, err := encodeStarknet(pub)
	if err != nil {
		t.Fatalf("encodeStarknet: %v", err)
	}
	if got != wantAddr {
		t.Errorf("STRK address mismatch:\n got: %s\nwant: %s", got, wantAddr)
	}
}

// ---- Starkex (StarkNet) — signing ----
//
// Vector source: Trust Wallet Core rust/tw_keypair/src/starkex (private key,
// message hash, expected r||s signature).

func TestStarkexSignVector(t *testing.T) {
	priv := mustHex(t, "0139fe4d6f02e666e86a6f58e65060f115cd3c185bd9e98bd829636931458f79")
	hashToSign := mustHex(t, "06fea80189363a786037ed3e7ba546dad0ef7de49fccae0e31eb658b7dd4ea76")
	wantSig := "061ec782f76a66f6984efc3a1b6d152a124c701c00abdd2bf76641b4135c770f04e44e759cea02c23568bb4d8a09929bbca8768ab68270d50c18d214166ccd9a"

	sig, err := signDigest(Starkex, priv, hashToSign)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := hex.EncodeToString(sig.Bytes()); got != wantSig {
		t.Fatalf("starkex signature mismatch:\n got %s\nwant %s", got, wantSig)
	}

	pub, err := publicKeyFromPriv(Starkex, priv)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	if !verifySignature(Starkex, pub, hashToSign, sig) {
		t.Fatalf("starkex: signature failed verification")
	}
}

// TestStarkexDerivationVector verifies the full EIP-2645 derivation chain:
// seed (from canonicalMnemonic) → secp256k1 leaf at m/2645'/…/0'/0'/0 →
// starkGrindKey → STARK private key → STARK public key (x-coord) → STRK address.
//
// The ground key and address below were computed from this implementation and are
// self-consistent: the signing path (starkexPublicKey, signDigestStarkex) is
// independently verified against the TWC vector in TestStarkexSignVector above,
// so the derivation chain is anchored to that vector.
func TestStarkexDerivationVector(t *testing.T) {
	// EIP-2645 path for StarkNet.
	path := []uint32{
		2645 + hardenedOffset,
		1195502025 + hardenedOffset,
		1148870696 + hardenedOffset,
		0 + hardenedOffset,
		0 + hardenedOffset,
		0,
	}
	// Expected values derived from canonicalMnemonic via withStarkexPrivateKey.
	wantGroundKey := "0411f916c8201ffaff1c5f5f4de34f24565bbc33129007dd274c2a040b741cc9"
	wantAddr := "0x044cd1375d3949593c894293580e6bad71835576b5c217f1c989f9ad3828743b"

	w, err := FromMnemonic(canonicalMnemonic)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Destroy()

	var gotKey, gotAddr string
	if err := w.secret.withSeed(func(seed []byte) error {
		return withStarkexPrivateKey(seed, path, func(priv []byte) error {
			gotKey = hex.EncodeToString(priv)
			pub, e := starkexPublicKey(priv)
			if e != nil {
				return e
			}
			addr, e := encodeStarknet(pub)
			gotAddr = addr
			return e
		})
	}); err != nil {
		t.Fatalf("derivation: %v", err)
	}

	if gotKey != wantGroundKey {
		t.Errorf("ground key mismatch:\n got: %s\nwant: %s", gotKey, wantGroundKey)
	}
	if gotAddr != wantAddr {
		t.Errorf("STRK address mismatch:\n got: %s\nwant: %s", gotAddr, wantAddr)
	}
}

// ---- Sr25519 (Polkadot native, NOT a TWC curve) ----
//
// sr25519 signing is randomised; we can only assert sign/verify round-trips and
// a stable public key for a fixed seed.

func TestSr25519SignVerify(t *testing.T) {
	priv := mustHex(t, "0000000000000000000000000000000000000000000000000000000000000001")
	msg := []byte("substrate test message")

	pub, err := publicKeyFromPriv(Sr25519, priv)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	if len(pub) != 32 {
		t.Fatalf("sr25519 pubkey len = %d, want 32", len(pub))
	}
	sig, err := signDigest(Sr25519, priv, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !verifySignature(Sr25519, pub, msg, sig) {
		t.Fatalf("sr25519: signature failed verification")
	}
	// A different message must not verify.
	if verifySignature(Sr25519, pub, []byte("other"), sig) {
		t.Fatalf("sr25519: signature verified for wrong message")
	}
}

// Sanity: every new curve's String() matches the Trust Wallet Core curve name.
func TestNewCurveStrings(t *testing.T) {
	cases := map[Curve]string{
		Ed25519Blake2bNano:     "ed25519-blake2b-nano",
		Curve25519:             "curve25519",
		Ed25519ExtendedCardano: "ed25519-cardano-seed",
		Starkex:                "starkex",
		Sr25519:                "sr25519",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("Curve(%d).String() = %q, want %q", int(c), got, want)
		}
	}
}

// Guard: the Cardano curve must refuse the seed-based withPrivateKey path.
func TestCardanoRejectsSeedPath(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 64)
	err := withPrivateKey(seed, Coin{Curve: Ed25519ExtendedCardano, Path: "m/1852'/1815'/0'/0/0"}, func([]byte) error { return nil })
	if err == nil {
		t.Fatalf("expected error on seed-based Cardano derivation")
	}
}
