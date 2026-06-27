package hdwallet

// This file implements a Trust Wallet Core `AnyAddress` equivalent: validate,
// parse, and derive-from-external-pubkey for every registered network.
//
// It is intentionally self-contained and does NOT modify the Coin struct,
// registry.go, or any encoder file. The validators below are the exact reverse
// of the encoders in encoders_secp256k1.go / encoders_ed25519.go /
// encoders_nist256p1.go and reuse the same primitives from codec.go / crypto.go.
//
// Each validator decodes an address, verifies its checksum / prefix / length,
// and returns the decoded payload (the bytes an encoder would have produced
// before string-encoding: the 20-byte hash160 / key hash, the 32-byte public
// key, the 20/32-byte account identifier, etc.). A non-nil error means the
// address is invalid for that network.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// ErrInvalidAddress is the base sentinel for all address-validation failures.
// Specific reasons (bad checksum, wrong prefix, wrong length, …) wrap it with
// %w, so errors.Is(err, ErrInvalidAddress) matches any validation failure while
// the message still describes the precise cause.
var ErrInvalidAddress = errors.New("hdwallet: invalid address")

// addrErr builds an ErrInvalidAddress with a descriptive, lower-cased reason.
func addrErr(symbol Symbol, reason string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidAddress, symbol, reason)
}

// addressValidator decodes an address and verifies it, returning the decoded
// payload. The map below is the reverse counterpart of the `coins` registry's
// Encode functions; it is keyed by the same Symbol values.
type addressValidator func(addr string) ([]byte, error)

// validators is a SEPARATE registry (it does not touch Coin / registry.go) that
// maps each network to its decode+verify function. EVM chains share the
// Ethereum validator and Cosmos chains share a per-HRP bech32 validator, exactly
// mirroring how the encoders are shared in registry.go.
var validators = map[Symbol]addressValidator{
	// ---- secp256k1 : Bitcoin-style UTXO chains ----
	// BTC/LTC accept any of the four standard formats (P2PKH/P2SH/P2WPKH/P2TR);
	// see bitcoinValidator in address_types.go.
	BTC:  bitcoinValidator(BTC),
	LTC:  bitcoinValidator(LTC),
	DOGE: base58CheckValidator1(0x1e, DOGE),
	DASH: base58CheckValidator1(0x4c, DASH),
	ZEC:  base58CheckValidatorN(base58BTC, []byte{0x1c, 0xb8}, ZEC),
	BCH:  cashAddrValidator("bitcoincash", BCH),

	// ---- secp256k1 : account-based / keccak ----
	ETH: ethValidator(ETH),
	TRX: base58CheckValidator1(0x41, TRX),
	XRP: base58CheckValidatorN(base58XRP, []byte{0x00}, XRP),
	ICX: icxValidator(ICX),
	CKB: ckbValidator(CKB),
	ZIL: zilValidator(ZIL),

	// ---- secp256k1 : EVM chains (identical to Ethereum) ----
	BNB:   ethValidator(BNB),
	MATIC: ethValidator(MATIC),
	AVAX:  ethValidator(AVAX),
	ARB:   ethValidator(ARB),
	OP:    ethValidator(OP),
	FTM:   ethValidator(FTM),
	BASE:  ethValidator(BASE),
	CRO:   ethValidator(CRO),
	GNO:   ethValidator(GNO),
	CELO:  ethValidator(CELO),

	// ---- secp256k1 : Cosmos SDK chains (bech32, per-HRP) ----
	ATOM: cosmosValidator("cosmos", ATOM),
	OSMO: cosmosValidator("osmo", OSMO),
	JUNO: cosmosValidator("juno", JUNO),
	TIA:  cosmosValidator("celestia", TIA),

	// ---- ed25519 (SLIP-0010) ----
	SOL:   solValidator(SOL),
	XLM:   strkeyValidator(6<<3, XLM),
	DOT:   ss58Validator(0, DOT),
	KSM:   ss58Validator(2, KSM),
	NEAR:  nearValidator(NEAR),
	ALGO:  algoValidator(ALGO),
	SUI:   hexHashValidator(SUI),
	APTOS: hexHashValidator(APTOS),
	XTZ:   base58CheckValidatorN(base58BTC, []byte{0x06, 0xa1, 0x9f}, XTZ),

	// ---- nist256p1 (SLIP-0010) ----
	NEO: base58CheckValidator1(0x17, NEO),
}

// IsValidAddress reports whether addr is a syntactically and checksum-valid
// address for the given network. It is a convenience wrapper over
// ValidateAddress.
func IsValidAddress(symbol Symbol, addr string) bool {
	return ValidateAddress(symbol, addr) == nil
}

// ValidateAddress returns nil if addr is a valid address for symbol, or a
// descriptive error wrapping ErrInvalidAddress (bad checksum, wrong prefix,
// wrong length, …) or ErrUnsupportedCoin for an unknown symbol.
func ValidateAddress(symbol Symbol, addr string) error {
	_, err := ParseAddress(symbol, addr)
	return err
}

// ParseAddress decodes addr for symbol, verifies its checksum, and returns the
// decoded payload — e.g. the 20-byte hash160 for Bitcoin/Cosmos/Tron, the
// 32-byte public key for Solana/Stellar/SS58, or the 20/32-byte account
// identifier for EVM/Sui/Aptos. An unknown symbol returns ErrUnsupportedCoin; an
// invalid address returns an error wrapping ErrInvalidAddress.
func ParseAddress(symbol Symbol, addr string) ([]byte, error) {
	v, ok := validators[symbol]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	return v(addr)
}

// AddressFromPublicKey derives the address for symbol directly from an external
// public key, reusing the registry's encoder (read-only). pub must be the
// curve's expected public-key form: a 33-byte compressed key for
// secp256k1/nist256p1, or a 32-byte key for ed25519. An unknown symbol returns
// ErrUnsupportedCoin; a malformed key is reported by the underlying encoder.
func AddressFromPublicKey(symbol Symbol, pub []byte) (string, error) {
	coin, ok := coins[symbol]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	addr, err := coin.Encode(pub)
	if err != nil {
		return "", fmt.Errorf("hdwallet: %s: %w", symbol, err)
	}
	return addr, nil
}

// ---------------------------------------------------------------------------
// base58 decoding for arbitrary alphabets (reverse of base58Encode in codec.go)
// ---------------------------------------------------------------------------

// base58Decode is the inverse of base58Encode (codec.go) for any 58-char
// alphabet. Leading alphabet[0] characters decode to leading zero bytes.
func base58Decode(alphabet, input string) ([]byte, error) {
	// Build a reverse lookup for the alphabet.
	var index [256]int
	for i := range index {
		index[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		index[alphabet[i]] = i
	}

	zeros := 0
	for zeros < len(input) && input[zeros] == alphabet[0] {
		zeros++
	}

	// Decode big-endian base58 into a base256 byte slice.
	size := len(input)*733/1000 + 1 // log(58)/log(256), rounded up
	b256 := make([]byte, size)
	high := size - 1
	for i := 0; i < len(input); i++ {
		v := index[input[i]]
		if v < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", input[i])
		}
		carry := v
		j := size - 1
		for ; j > high || carry != 0; j-- {
			carry += 58 * int(b256[j])
			b256[j] = byte(carry % 256)
			carry /= 256
			if j == 0 {
				break
			}
		}
		high = j
	}

	// Skip leading zero bytes produced by padding, then re-add the encoded ones.
	it := 0
	for it < size && b256[it] == 0 {
		it++
	}
	out := make([]byte, 0, zeros+(size-it))
	for i := 0; i < zeros; i++ {
		out = append(out, 0)
	}
	out = append(out, b256[it:]...)
	return out, nil
}

// base58CheckDecode reverses base58CheckEncode (codec.go): it decodes with the
// given alphabet, splits off the trailing 4-byte double-SHA256 checksum, and
// verifies it against version||payload. It returns version||payload (without the
// checksum) so callers can strip the expected version prefix.
func base58CheckDecode(alphabet, input string) ([]byte, error) {
	raw, err := base58Decode(alphabet, input)
	if err != nil {
		return nil, err
	}
	if len(raw) < 5 {
		return nil, errors.New("too short")
	}
	body := raw[:len(raw)-4]
	checksum := raw[len(raw)-4:]
	want := sha256d(body)[:4]
	if !bytesEqual(checksum, want) {
		return nil, errors.New("bad checksum")
	}
	return body, nil
}

// bytesEqual is a tiny local helper to avoid importing bytes just for this.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// secp256k1 validators
// ---------------------------------------------------------------------------

// segwitValidator validates a native SegWit v0 P2WPKH address (BTC/LTC),
// the reverse of segwitAddress. It verifies the HRP, witness version 0, and a
// 20-byte program (hash160). Returns the 20-byte program.
func segwitValidator(wantHRP string, symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		hrp, data, err := bech32.Decode(addr)
		if err != nil {
			return nil, addrErr(symbol, "bech32 decode failed: "+err.Error())
		}
		if hrp != wantHRP {
			return nil, addrErr(symbol, fmt.Sprintf("wrong prefix %q (want %q)", hrp, wantHRP))
		}
		if len(data) == 0 {
			return nil, addrErr(symbol, "missing witness version")
		}
		if data[0] != 0x00 {
			return nil, addrErr(symbol, fmt.Sprintf("unsupported witness version %d", data[0]))
		}
		program, err := bech32.ConvertBits(data[1:], 5, 8, false)
		if err != nil {
			return nil, addrErr(symbol, "invalid witness program: "+err.Error())
		}
		if len(program) != 20 {
			return nil, addrErr(symbol, fmt.Sprintf("program length %d (want 20)", len(program)))
		}
		return program, nil
	}
}

// base58CheckValidator1 validates a base58check address with a single version
// byte (DOGE 0x1e, DASH 0x4c, TRX 0x41, NEO 0x17) and a 20-byte payload. Returns
// the 20-byte payload (hash160 / keccak[12:] / script hash).
func base58CheckValidator1(version byte, symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		payload, ver, err := base58.CheckDecode(addr)
		if err != nil {
			if errors.Is(err, base58.ErrChecksum) {
				return nil, addrErr(symbol, "bad checksum")
			}
			return nil, addrErr(symbol, "base58check decode failed: "+err.Error())
		}
		if ver != version {
			return nil, addrErr(symbol, fmt.Sprintf("wrong version 0x%02x (want 0x%02x)", ver, version))
		}
		if len(payload) != 20 {
			return nil, addrErr(symbol, fmt.Sprintf("payload length %d (want 20)", len(payload)))
		}
		return payload, nil
	}
}

// base58CheckValidatorN validates a base58check address with a multi-byte
// version prefix and a 20-byte payload, over the supplied alphabet (ZEC, XRP,
// XTZ). Returns the 20-byte payload.
func base58CheckValidatorN(alphabet string, version []byte, symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		body, err := base58CheckDecode(alphabet, addr)
		if err != nil {
			return nil, addrErr(symbol, err.Error())
		}
		if len(body) < len(version) {
			return nil, addrErr(symbol, "too short for version prefix")
		}
		if !bytesEqual(body[:len(version)], version) {
			return nil, addrErr(symbol, fmt.Sprintf("wrong version prefix %x (want %x)", body[:len(version)], version))
		}
		payload := body[len(version):]
		if len(payload) != 20 {
			return nil, addrErr(symbol, fmt.Sprintf("payload length %d (want 20)", len(payload)))
		}
		return payload, nil
	}
}

// ethValidator validates an Ethereum / EVM address (0x + 40 hex), the reverse of
// encodeETH. It accepts an all-lowercase or all-uppercase address, or a
// correctly EIP-55-checksummed mixed-case address, and rejects an incorrect
// mixed-case checksum. Returns the 20-byte address.
func ethValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		if len(addr) != 42 || addr[0] != '0' || (addr[1] != 'x' && addr[1] != 'X') {
			return nil, addrErr(symbol, "must be 0x followed by 40 hex characters")
		}
		hexPart := addr[2:]
		raw, err := hex.DecodeString(hexPart)
		if err != nil {
			return nil, addrErr(symbol, "invalid hex")
		}
		// Checksum policy: all-lower or all-upper always accepted; a mixed-case
		// address must match EIP-55 exactly.
		lower := strings.ToLower(hexPart)
		upper := strings.ToUpper(hexPart)
		if hexPart != lower && hexPart != upper {
			if eip55(raw) != addr {
				return nil, addrErr(symbol, "bad EIP-55 checksum")
			}
		}
		return raw, nil
	}
}

// cashAddrValidator validates a Bitcoin Cash CashAddr (P2KH, 160-bit), the
// reverse of encodeBCH. The prefix may be omitted in the input (Trust Wallet
// accepts both "bitcoincash:..." and the bare body). Returns the 20-byte hash.
func cashAddrValidator(prefix string, symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		body := addr
		if idx := strings.IndexByte(addr, ':'); idx >= 0 {
			gotPrefix := strings.ToLower(addr[:idx])
			if gotPrefix != prefix {
				return nil, addrErr(symbol, fmt.Sprintf("wrong prefix %q (want %q)", addr[:idx], prefix))
			}
			body = addr[idx+1:]
		}
		body = strings.ToLower(body)

		// Decode the base32 (cashCharset) body into 5-bit values.
		values := make([]byte, 0, len(body))
		for i := 0; i < len(body); i++ {
			pos := strings.IndexByte(cashCharset, body[i])
			if pos < 0 {
				return nil, addrErr(symbol, fmt.Sprintf("invalid character %q", body[i]))
			}
			values = append(values, byte(pos)) // #nosec G115 -- pos is an index into a 32-char charset (0..31)
		}
		if len(values) < 8 {
			return nil, addrErr(symbol, "too short")
		}
		// Verify the 8-symbol checksum (polymod over prefix||0||values == 0).
		if cashPolymodCheck(prefix, values) != 0 {
			return nil, addrErr(symbol, "bad checksum")
		}
		payload5 := values[:len(values)-8]
		payload, err := bech32.ConvertBits(payload5, 5, 8, false)
		if err != nil {
			return nil, addrErr(symbol, "invalid payload: "+err.Error())
		}
		if len(payload) < 1 {
			return nil, addrErr(symbol, "empty payload")
		}
		if payload[0] != 0x00 {
			return nil, addrErr(symbol, fmt.Sprintf("unsupported version byte 0x%02x", payload[0]))
		}
		hash := payload[1:]
		if len(hash) != 20 {
			return nil, addrErr(symbol, fmt.Sprintf("hash length %d (want 20)", len(hash)))
		}
		return hash, nil
	}
}

// cashPolymodCheck runs the CashAddr polymod over the full payload (which
// already includes the 8 checksum symbols) and returns 0 for a valid address.
// It reuses cashPolymod from encoders_secp256k1.go.
func cashPolymodCheck(prefix string, values []byte) uint64 {
	enc := make([]byte, 0, len(prefix)+1+len(values))
	for i := 0; i < len(prefix); i++ {
		enc = append(enc, prefix[i]&0x1f)
	}
	enc = append(enc, 0) // separator
	enc = append(enc, values...)
	return cashPolymod(enc)
}

// cosmosValidator validates a Cosmos-family bech32 address for the given HRP,
// the reverse of cosmosEncoder. Returns the 20-byte hash160.
func cosmosValidator(wantHRP string, symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		hrp, data, err := bech32.Decode(addr)
		if err != nil {
			return nil, addrErr(symbol, "bech32 decode failed: "+err.Error())
		}
		if hrp != wantHRP {
			return nil, addrErr(symbol, fmt.Sprintf("wrong prefix %q (want %q)", hrp, wantHRP))
		}
		payload, err := bech32.ConvertBits(data, 5, 8, false)
		if err != nil {
			return nil, addrErr(symbol, "invalid payload: "+err.Error())
		}
		if len(payload) != 20 {
			return nil, addrErr(symbol, fmt.Sprintf("payload length %d (want 20)", len(payload)))
		}
		return payload, nil
	}
}

// ---------------------------------------------------------------------------
// ed25519 validators
// ---------------------------------------------------------------------------

// solValidator validates a Solana address: raw base58 (Bitcoin alphabet, no
// checksum) decoding to a 32-byte public key. Returns the 32-byte key.
func solValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		raw, err := base58Decode(base58BTC, addr)
		if err != nil {
			return nil, addrErr(symbol, err.Error())
		}
		if len(raw) != 32 {
			return nil, addrErr(symbol, fmt.Sprintf("length %d (want 32)", len(raw)))
		}
		return raw, nil
	}
}

// strkeyValidator validates a Stellar strkey (version 'G' account ID), the
// reverse of encodeXLM: base32(version || 32-byte key || CRC16-XMODEM). Returns
// the 32-byte public key.
func strkeyValidator(version byte, symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		raw, err := base32NoPad.DecodeString(addr)
		if err != nil {
			return nil, addrErr(symbol, "base32 decode failed: "+err.Error())
		}
		if len(raw) != 1+32+2 {
			return nil, addrErr(symbol, fmt.Sprintf("length %d (want 35)", len(raw)))
		}
		if raw[0] != version {
			return nil, addrErr(symbol, fmt.Sprintf("wrong version 0x%02x (want 0x%02x)", raw[0], version))
		}
		body := raw[:1+32]
		var want [2]byte
		binary.LittleEndian.PutUint16(want[:], crc16XModem(body))
		if raw[33] != want[0] || raw[34] != want[1] {
			return nil, addrErr(symbol, "bad checksum")
		}
		return raw[1 : 1+32], nil
	}
}

// ss58Validator validates a Polkadot/Kusama SS58 address, the reverse of
// ss58Encoder: base58(prefix || 32-byte key || BLAKE2b checksum[:2]). Returns
// the 32-byte public key.
func ss58Validator(prefix byte, symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		raw, err := base58Decode(base58BTC, addr)
		if err != nil {
			return nil, addrErr(symbol, err.Error())
		}
		if len(raw) != 1+32+2 {
			return nil, addrErr(symbol, fmt.Sprintf("length %d (want 35)", len(raw)))
		}
		if raw[0] != prefix {
			return nil, addrErr(symbol, fmt.Sprintf("wrong network prefix %d (want %d)", raw[0], prefix))
		}
		data := raw[:1+32]
		checksum := blake2b512(append([]byte("SS58PRE"), data...))
		if raw[33] != checksum[0] || raw[34] != checksum[1] {
			return nil, addrErr(symbol, "bad checksum")
		}
		return raw[1 : 1+32], nil
	}
}

// nearValidator validates a NEAR implicit account: 64 lowercase hex characters
// (32-byte public key). Returns the 32-byte key.
func nearValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		if len(addr) != 64 {
			return nil, addrErr(symbol, fmt.Sprintf("length %d (want 64 hex chars)", len(addr)))
		}
		if addr != strings.ToLower(addr) {
			return nil, addrErr(symbol, "implicit account must be lowercase hex")
		}
		raw, err := hex.DecodeString(addr)
		if err != nil {
			return nil, addrErr(symbol, "invalid hex")
		}
		return raw, nil
	}
}

// algoValidator validates an Algorand address, the reverse of encodeALGO:
// base32(32-byte key || SHA512/256(key)[-4:]). Returns the 32-byte public key.
func algoValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		raw, err := base32NoPad.DecodeString(addr)
		if err != nil {
			return nil, addrErr(symbol, "base32 decode failed: "+err.Error())
		}
		if len(raw) != 32+4 {
			return nil, addrErr(symbol, fmt.Sprintf("length %d (want 36)", len(raw)))
		}
		key := raw[:32]
		checksum := sha512Sum256(key)
		want := checksum[len(checksum)-4:]
		if !bytesEqual(raw[32:], want) {
			return nil, addrErr(symbol, "bad checksum")
		}
		return key, nil
	}
}

// cardanoValidator validates a Cardano mainnet base (addr1...) address, the
// reverse of encodeCardano. Cardano addresses exceed bech32's 90-character cap,
// so it uses DecodeNoLimit; it verifies the HRP ("addr"), the mainnet base header
// byte (0x01), and the 57-byte payload (header + 28-byte payment hash + 28-byte
// staking hash). It returns the 57-byte payload (header || paymentHash ||
// stakingHash).
// maxCardanoAddrLen caps bech32.DecodeNoLimit against unbounded-CPU input.
// The longest valid Cardano mainnet base address is ~114 chars.
const maxCardanoAddrLen = 200

func cardanoValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		if len(addr) > maxCardanoAddrLen {
			return nil, addrErr(symbol, "address too long")
		}
		hrp, data, err := bech32.DecodeNoLimit(addr)
		if err != nil {
			return nil, addrErr(symbol, "bech32 decode failed: "+err.Error())
		}
		if hrp != cardanoHRP {
			return nil, addrErr(symbol, fmt.Sprintf("wrong prefix %q (want %q)", hrp, cardanoHRP))
		}
		payload, err := bech32.ConvertBits(data, 5, 8, false)
		if err != nil {
			return nil, addrErr(symbol, "invalid payload: "+err.Error())
		}
		if len(payload) != 1+2*cardanoKeyHashLen {
			return nil, addrErr(symbol, fmt.Sprintf("payload length %d (want %d)", len(payload), 1+2*cardanoKeyHashLen))
		}
		if payload[0] != cardanoBaseHeader {
			return nil, addrErr(symbol, fmt.Sprintf("unsupported header byte 0x%02x (want 0x%02x)", payload[0], cardanoBaseHeader))
		}
		return payload, nil
	}
}

// hexHashValidator validates a Sui/Aptos address: 0x followed by 64 hex
// characters (a 32-byte account/object hash). These addresses carry no internal
// checksum, so this verifies form and length only. Returns the 32-byte hash.
func hexHashValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		if len(addr) != 66 || addr[0] != '0' || (addr[1] != 'x' && addr[1] != 'X') {
			return nil, addrErr(symbol, "must be 0x followed by 64 hex characters")
		}
		raw, err := hex.DecodeString(addr[2:])
		if err != nil {
			return nil, addrErr(symbol, "invalid hex")
		}
		if len(raw) != 32 {
			return nil, addrErr(symbol, fmt.Sprintf("length %d (want 32)", len(raw)))
		}
		return raw, nil
	}
}

// icxValidator validates an ICON address: "hx" + 40 lowercase hex characters (20 bytes).
func icxValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		if len(addr) != 42 || addr[:2] != "hx" {
			return nil, addrErr(symbol, "must start with hx and be 42 characters")
		}
		raw, err := hex.DecodeString(addr[2:])
		if err != nil {
			return nil, addrErr(symbol, "invalid hex: "+err.Error())
		}
		return raw, nil
	}
}

// maxCKBAddrLen caps bech32.DecodeNoLimit against unbounded-CPU input.
// The longest valid CKB full address (54-byte payload) is ~107 chars.
const maxCKBAddrLen = 200

// ckbValidator validates a Nervos CKB full address (RFC 0021): bech32m with HRP "ckb",
// format byte 0x00, 32-byte code_hash, 1-byte hash_type, 20-byte args = 54 bytes payload.
// CKB full addresses exceed the 90-char bech32 length limit, so DecodeNoLimit is used.
func ckbValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		if len(addr) > maxCKBAddrLen {
			return nil, addrErr(symbol, "address too long")
		}
		// ponytail: DecodeNoLimit accepts bech32 and bech32m; CKB RFC 0021 mandates bech32m
		// but the checksum type is not distinguishable here. Payload validation compensates.
		hrp, data, err := bech32.DecodeNoLimit(addr)
		if err != nil {
			return nil, addrErr(symbol, "bech32 decode failed: "+err.Error())
		}
		if hrp != "ckb" {
			return nil, addrErr(symbol, fmt.Sprintf("wrong prefix %q (want ckb)", hrp))
		}
		payload, err := bech32.ConvertBits(data, 5, 8, false)
		if err != nil {
			return nil, addrErr(symbol, "invalid payload: "+err.Error())
		}
		if len(payload) != 54 {
			return nil, addrErr(symbol, fmt.Sprintf("payload length %d (want 54)", len(payload)))
		}
		if payload[0] != 0x00 {
			return nil, addrErr(symbol, fmt.Sprintf("unsupported format byte 0x%02x (want 0x00)", payload[0]))
		}
		return payload[34:], nil // 20-byte args
	}
}

// zilValidator validates a Zilliqa address: bech32 with HRP "zil", 20-byte payload.
func zilValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		hrp, data, err := bech32.Decode(addr)
		if err != nil {
			return nil, addrErr(symbol, "bech32 decode failed: "+err.Error())
		}
		if hrp != "zil" {
			return nil, addrErr(symbol, fmt.Sprintf("wrong prefix %q (want zil)", hrp))
		}
		payload, err := bech32.ConvertBits(data, 5, 8, false)
		if err != nil {
			return nil, addrErr(symbol, "invalid payload: "+err.Error())
		}
		if len(payload) != 20 {
			return nil, addrErr(symbol, fmt.Sprintf("payload length %d (want 20)", len(payload)))
		}
		return payload, nil
	}
}

// starknetValidator validates a StarkNet address: "0x" or "0X" prefix followed by
// 1–64 hex characters representing a 252-bit field element. Returns the value
// zero-padded to 32 bytes. StarkNet addresses with fewer than 64 hex chars after the
// prefix are valid (leading zeros stripped).
func starknetValidator(symbol Symbol) addressValidator {
	return func(addr string) ([]byte, error) {
		if len(addr) < 3 || (addr[:2] != "0x" && addr[:2] != "0X") {
			return nil, addrErr(symbol, "must start with 0x")
		}
		hexStr := addr[2:]
		if len(hexStr) == 0 || len(hexStr) > 64 {
			return nil, addrErr(symbol, "address must be 1-64 hex chars after 0x")
		}
		if len(hexStr)%2 != 0 {
			hexStr = "0" + hexStr
		}
		raw, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, addrErr(symbol, "invalid hex: "+err.Error())
		}
		padded := make([]byte, 32)
		copy(padded[32-len(raw):], raw)
		return padded, nil
	}
}

// ---------------------------------------------------------------------------
// Feature: EIP-55 checksum normalization
// ---------------------------------------------------------------------------

// ChecksumEthAddress returns the EIP-55 mixed-case checksum of an Ethereum
// address. Input may be with or without "0x"/"0X" prefix, any case. Returns
// ErrInvalidAddress if the input is not a valid 20-byte hex address.
func ChecksumEthAddress(addr string) (string, error) {
	s := addr
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	if len(s) != 40 {
		return "", fmt.Errorf("%w: must be 40 hex characters", ErrInvalidAddress)
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex: %s", ErrInvalidAddress, err)
	}
	return eip55(raw), nil
}

// ---------------------------------------------------------------------------
// Feature: multi-symbol detection
// ---------------------------------------------------------------------------

// DetectSymbols returns all registered symbols whose address validator accepts
// addr. The result is sorted alphabetically. Returns nil if no match is found.
// This is O(n) over all registered coins — do not call in hot loops.
func DetectSymbols(addr string) []Symbol {
	var out []Symbol
	for sym := range validators {
		if IsValidAddress(sym, addr) {
			out = append(out, sym)
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

// ---------------------------------------------------------------------------
// Feature: AddressFromPayload — inverse of ParseAddress
// ---------------------------------------------------------------------------

// payloadEncoders maps each symbol to a function that re-encodes the raw
// payload returned by ParseAddress back into the canonical address string.
// Populated by the static map below plus init() for dynamic registry entries.
var payloadEncoders map[Symbol]func([]byte) (string, error)

func init() {
	payloadEncoders = map[Symbol]func([]byte) (string, error){
		// EVM chains: 20-byte → EIP-55 checksummed hex
		ETH:   ethPayload,
		BNB:   ethPayload,
		MATIC: ethPayload,
		AVAX:  ethPayload,
		ARB:   ethPayload,
		OP:    ethPayload,
		FTM:   ethPayload,
		BASE:  ethPayload,
		CRO:   ethPayload,
		GNO:   ethPayload,
		CELO:  ethPayload,
		// Bitcoin-family: 20-byte hash160 → P2PKH base58check
		BTC:  btcP2PKHPayload(0x00),
		LTC:  btcP2PKHPayload(0x30),
		DOGE: btcP2PKHPayload(0x1e),
		DASH: btcP2PKHPayload(0x4c),
		TRX:  btcP2PKHPayload(0x41),
		NEO:  btcP2PKHPayload(0x17),
		BCD:  btcP2PKHPayload(0x00),
		// Multi-byte version base58check
		ZEC:  multiVersionPayload(base58BTC, []byte{0x1c, 0xb8}),
		XTZ:  multiVersionPayload(base58BTC, []byte{0x06, 0xa1, 0x9f}),
		XRP:  multiVersionPayload(base58XRP, []byte{0x00}),
		ZEN:  multiVersionPayload(base58BTC, []byte{0x20, 0x89}),
		FLUX: multiVersionPayload(base58BTC, []byte{0x1c, 0xb8}),
		// CashAddr: 20-byte hash → P2KH cashaddr
		BCH: cashHashPayload("bitcoincash"),
		XEC: cashHashPayload("ecash"),
		// Special encodings
		ICX: icxPayload,
		// Cosmos bech32 (base + registered)
		ATOM: bech32HashPayload("cosmos"),
		OSMO: bech32HashPayload("osmo"),
		JUNO: bech32HashPayload("juno"),
		TIA:  bech32HashPayload("celestia"),
		ZIL:  bech32HashPayload("zil"),
		// ed25519: payload IS the 32-byte public key
		SOL:  pub32Payload(encodeSOL),
		XLM:  pub32Payload(encodeXLM),
		DOT:  pub32Payload(ss58Encoder(0)),
		KSM:  pub32Payload(ss58Encoder(2)),
		NEAR: pub32Payload(encodeNEAR),
		ALGO: pub32Payload(encodeALGO),
		KIN:  pub32Payload(encodeXLM),
		IOST: pub32Payload(encodeSOL),
		// 32-byte hash chains: "0x" + hex
		SUI:   hexHashPayload,
		APTOS: hexHashPayload,
		STRK:  hexHashPayload,
		// Cardano: 57-byte payload → bech32 "addr"
		ADA: cardanoFromPayload,
	}
	// Additional EVM chains
	for _, s := range []Symbol{
		ETC, ZKSYNC, LINEA, SCROLL, MANTLE, BLAST, KAIA, AURORA, GLMR, MOVR,
		BOBA, METIS, OPBNB, POLZKEVM, MANTA, RBTC, HECO, OKT, KCS, WAN,
		POA, CLO, GO, TT, VET, IOTX, THETA, NEON, MERLIN, LIGHT,
		SONIC, ZENEON, ZETAEVM,
	} {
		payloadEncoders[s] = ethPayload
	}
	payloadEncoders[RONIN] = func(p []byte) (string, error) {
		if len(p) != 20 {
			return "", fmt.Errorf("payload length %d (want 20)", len(p))
		}
		return "ronin:" + eip55(p)[2:], nil
	}
	// Additional Cosmos SDK chains (bech32, 20-byte)
	for sym, hrp := range map[Symbol]string{
		LUNA: "terra", KAVA: "kava", SCRT: "secret", BAND: "band", RUNE: "thor",
		STARS: "stars", AXL: "axelar", STRD: "stride", BLD: "agoric", CRE: "cre",
		KUJI: "kujira", CMDX: "comdex", NTRN: "neutron", SOMM: "somm", FET: "fetch",
		MARS: "mars", UMEE: "umee", COREUM: "core", QSR: "quasar", XPRT: "persistence",
		AKT: "akash", NOBLE: "noble", SEI: "sei", DYDX: "dydx", BLZ: "bluzelle",
		CRYPTOORG: "cro",
		EVMOS:     "evmos", INJ: "inj", CANTO: "canto", ZETA: "zeta", ONE: "one",
	} {
		payloadEncoders[sym] = bech32HashPayload(hrp)
	}
	// Additional SegWit UTXO chains (20-byte witness program → bech32 witness v0)
	for sym, hrp := range map[Symbol]string{
		GRS: "grs", DGB: "dgb", BTG: "btg", SYS: "sys", VIA: "via", STRAX: "strax",
	} {
		payloadEncoders[sym] = segwitHashPayload(hrp)
	}
	// Additional legacy P2PKH chains
	for sym, ver := range map[Symbol]byte{
		QTUM: 0x3a, RVN: 0x3c, KMD: 0x3c, FIRO: 0x52, MONA: 0x32,
		XVG: 0x1e, PIVX: 0x1e, NEBL: 0x35, ONT: 0x17,
	} {
		payloadEncoders[sym] = btcP2PKHPayload(ver)
	}
}

// --- payload re-encoder helpers ---

func ethPayload(p []byte) (string, error) {
	if len(p) != 20 {
		return "", fmt.Errorf("payload length %d (want 20)", len(p))
	}
	return eip55(p), nil
}

func btcP2PKHPayload(ver byte) func([]byte) (string, error) {
	return func(p []byte) (string, error) {
		if len(p) != 20 {
			return "", fmt.Errorf("payload length %d (want 20)", len(p))
		}
		return base58.CheckEncode(p, ver), nil
	}
}

func multiVersionPayload(alphabet string, version []byte) func([]byte) (string, error) {
	return func(p []byte) (string, error) {
		if len(p) != 20 {
			return "", fmt.Errorf("payload length %d (want 20)", len(p))
		}
		return base58CheckEncode(alphabet, version, p), nil
	}
}

// bech32HashPayload encodes a 20-byte payload as a standard bech32 address
// (no witness version prefix). Used for Cosmos and Zilliqa chains.
func bech32HashPayload(hrp string) func([]byte) (string, error) {
	return func(p []byte) (string, error) {
		if len(p) != 20 {
			return "", fmt.Errorf("payload length %d (want 20)", len(p))
		}
		conv, err := bech32.ConvertBits(p, 8, 5, true)
		if err != nil {
			return "", err
		}
		return bech32.Encode(hrp, conv)
	}
}

// segwitHashPayload encodes a 20-byte witness program as a bech32 witness-v0
// address (prepends witness version 0). Used for native-SegWit altcoins.
func segwitHashPayload(hrp string) func([]byte) (string, error) {
	return func(p []byte) (string, error) {
		if len(p) != 20 {
			return "", fmt.Errorf("payload length %d (want 20)", len(p))
		}
		conv, err := bech32.ConvertBits(p, 8, 5, true)
		if err != nil {
			return "", err
		}
		return bech32.Encode(hrp, append([]byte{0x00}, conv...))
	}
}

func cashHashPayload(prefix string) func([]byte) (string, error) {
	return func(p []byte) (string, error) {
		if len(p) != 20 {
			return "", fmt.Errorf("payload length %d (want 20)", len(p))
		}
		vp := append([]byte{0x00}, p...)
		conv, err := bech32.ConvertBits(vp, 8, 5, true)
		if err != nil {
			return "", err
		}
		combined := append(conv, cashChecksum(prefix, conv)...)
		var sb strings.Builder
		sb.WriteString(prefix)
		sb.WriteByte(':')
		for _, v := range combined {
			sb.WriteByte(cashCharset[v])
		}
		return sb.String(), nil
	}
}

func icxPayload(p []byte) (string, error) {
	if len(p) != 20 {
		return "", fmt.Errorf("payload length %d (want 20)", len(p))
	}
	return "hx" + hex.EncodeToString(p), nil
}

func hexHashPayload(p []byte) (string, error) {
	if len(p) != 32 {
		return "", fmt.Errorf("payload length %d (want 32)", len(p))
	}
	return "0x" + hex.EncodeToString(p), nil
}

// pub32Payload wraps an ed25519-style encoder with a 32-byte length check.
func pub32Payload(enc func([]byte) (string, error)) func([]byte) (string, error) {
	return func(p []byte) (string, error) {
		if len(p) != 32 {
			return "", fmt.Errorf("payload length %d (want 32)", len(p))
		}
		return enc(p)
	}
}

func cardanoFromPayload(p []byte) (string, error) {
	if len(p) != 1+2*cardanoKeyHashLen {
		return "", fmt.Errorf("payload length %d (want %d)", len(p), 1+2*cardanoKeyHashLen)
	}
	conv, err := bech32.ConvertBits(p, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(cardanoHRP, conv)
}

// AddressFromPayload derives an address for symbol from a raw address payload.
// For EVM/secp256k1 chains: payload is the 20-byte keccak address.
// For Bitcoin P2PKH: payload is the 20-byte hash160 (always encodes as P2PKH).
// For ed25519 chains: payload is the 32-byte public key.
// Returns ErrUnsupportedCoin if the symbol is not in the validator registry
// (or payload re-encoding is not implemented), or ErrInvalidAddress if the
// payload length does not match the expected format.
func AddressFromPayload(symbol Symbol, payload []byte) (string, error) {
	if _, ok := validators[symbol]; !ok {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedCoin, symbol)
	}
	enc, ok := payloadEncoders[symbol]
	if !ok {
		return "", fmt.Errorf("%w: %s: payload re-encoding not implemented", ErrUnsupportedCoin, symbol)
	}
	addr, err := enc(payload)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrInvalidAddress, symbol, err)
	}
	return addr, nil
}
