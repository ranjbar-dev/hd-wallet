package hdwallet

// TON (The Open Network) address derivation for the standard wallet v4r2
// contract, matching Trust Wallet Core.
//
// A TON account address is the SHA-256 representation hash of the account's
// StateInit cell (code + data). For an externally-owned account this is the
// wallet contract's StateInit, so the address is fully determined by:
//   - the wallet v4r2 CODE cell (a fixed constant, identical for every wallet), and
//   - the DATA cell, which embeds the owner's ed25519 public key.
//
// The user-friendly address string base64-encodes tag ‖ workchain ‖ hash ‖ crc16.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// walletV4R2CodeBoC is the wallet-v4r2 smart-contract CODE cell, distributed as a
// standard base64 bag-of-cells.
//
// Source: trustwallet/wallet-core, master branch, file
// rust/chains/tw_ton/resources/wallet/wallet_v4r2.code
// (fetched 2026-07 from
// https://raw.githubusercontent.com/trustwallet/wallet-core/master/rust/chains/tw_ton/resources/wallet/wallet_v4r2.code).
// This is the canonical wallet-v4r2 code published by the TON core team; it must
// not be edited — a wrong code cell yields wrong (fund-losing) addresses.
const walletV4R2CodeBoC = "te6cckECFAEAAtQAART/APSkE/S88sgLAQIBIAIDAgFIBAUE+PKDCNcYINMf0x/THwL4I7vyZO1E0NMf0x/T//QE0VFDuvKhUVG68qIF+QFUEGT5EPKj+AAkpMjLH1JAyx9SMMv/UhD0AMntVPgPAdMHIcAAn2xRkyDXSpbTB9QC+wDoMOAhwAHjACHAAuMAAcADkTDjDQOkyMsfEssfy/8QERITAubQAdDTAyFxsJJfBOAi10nBIJJfBOAC0x8hghBwbHVnvSKCEGRzdHK9sJJfBeAD+kAwIPpEAcjKB8v/ydDtRNCBAUDXIfQEMFyBAQj0Cm+hMbOSXwfgBdM/yCWCEHBsdWe6kjgw4w0DghBkc3RyupJfBuMNBgcCASAICQB4AfoA9AQw+CdvIjBQCqEhvvLgUIIQcGx1Z4MesXCAGFAEywUmzxZY+gIZ9ADLaRfLH1Jgyz8gyYBA+wAGAIpQBIEBCPRZMO1E0IEBQNcgyAHPFvQAye1UAXKwjiOCEGRzdHKDHrFwgBhQBcsFUAPPFiP6AhPLassfyz/JgED7AJJfA+ICASAKCwBZvSQrb2omhAgKBrkPoCGEcNQICEekk30pkQzmkD6f+YN4EoAbeBAUiYcVnzGEAgFYDA0AEbjJftRNDXCx+AA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA4PABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AAG7SB/oA1NQi+QAFyMoHFcv/ydB3dIAYyMsFywIizxZQBfoCFMtrEszMyXP7AMhAFIEBCPRR8qcCAHCBAQjXGPoA0z/IVCBHgQEI9FHyp4IQbm90ZXB0gBjIywXLAlAGzxZQBPoCFMtqEssfyz/Jc/sAAgBsgQEI1xj6ANM/MFIkgQEI9Fnyp4IQZHN0cnB0gBjIywXLAlAFzxZQA/oCE8tqyx8Syz/Jc/sAAAr0AMntVGliJeU="

// tonSubwalletID is the default subwallet id used by wallet v3/v4 (0x29a9a317).
const tonSubwalletID = 698983191

// TON address tag bytes.
const (
	tonTagBounceable    = 0x11
	tonTagNonBounceable = 0x51
	tonTagTestOnly      = 0x80 // OR'd into the tag for testnet-only addresses
)

// tonWalletV4R2Code parses and returns the wallet-v4r2 code cell. Parsing is
// cheap; callers may cache the result if desired.
func tonWalletV4R2Code() (*tonCell, error) {
	return tonCellFromBoCBase64(walletV4R2CodeBoC)
}

// tonStateInitCell builds the wallet-v4r2 StateInit cell (code + data) for a
// 32-byte ed25519 public key. Its representation hash is the account id; the
// cell itself is attached as a ref in a deploy (seqno==0) external message.
func tonStateInitCell(pub []byte) (*tonCell, error) {
	if len(pub) != 32 {
		return nil, fmt.Errorf("hdwallet: TON: public key must be 32 bytes, got %d", len(pub))
	}
	code, err := tonWalletV4R2Code()
	if err != nil {
		return nil, err
	}

	// Data cell: seqno(0,u32) ‖ subwallet_id(u32) ‖ pubkey(256 bits) ‖ 1 zero bit
	// (the trailing zero bit is the empty-plugins-dict Maybe flag).
	data := &tonCell{}
	data.appendUint(0, 32)
	data.appendUint(tonSubwalletID, 32)
	data.appendBytes(pub)
	data.appendBit(0)

	// StateInit cell: header bits b00110 (no split_depth, no special, code✓,
	// data✓, no library) with refs [code, data].
	si := &tonCell{}
	si.appendBit(0) // split_depth: nothing
	si.appendBit(0) // special: nothing
	si.appendBit(1) // code: present
	si.appendBit(1) // data: present
	si.appendBit(0) // library: empty
	si.appendRef(code)
	si.appendRef(data)

	return si, nil
}

// tonStateInitHash builds the wallet-v4r2 StateInit cell for a 32-byte ed25519
// public key and returns its 32-byte representation hash (the account id).
func tonStateInitHash(pub []byte) ([]byte, error) {
	si, err := tonStateInitCell(pub)
	if err != nil {
		return nil, err
	}
	return si.reprHash(), nil
}

// tonEncodeAddress renders a 32-byte account hash as a user-friendly TON address
// (base64 url-safe): tag ‖ workchain(0x00) ‖ hash(32) ‖ crc16(2, big-endian).
func tonEncodeAddress(hash []byte, bounceable bool) string {
	tag := byte(tonTagNonBounceable)
	if bounceable {
		tag = tonTagBounceable
	}
	buf := make([]byte, 0, 36)
	buf = append(buf, tag, 0x00) // tag, workchain 0
	buf = append(buf, hash...)
	crc := crc16XModem(buf)
	buf = append(buf, byte(crc>>8), byte(crc&0xff)) // big-endian
	return base64.URLEncoding.EncodeToString(buf)
}

// encodeTONAddress is the registry encoder: it derives the wallet-v4r2 StateInit
// hash for the ed25519 public key and returns the non-bounceable (UQ)
// user-friendly address — Trust Wallet Core's default for derived addresses.
func encodeTONAddress(pub []byte) (string, error) {
	hash, err := tonStateInitHash(pub)
	if err != nil {
		return "", err
	}
	return tonEncodeAddress(hash, false), nil
}

// tonParseAddress decodes any accepted TON address form and returns the 32-byte
// account hash. Accepted: user-friendly bounceable (EQ) / non-bounceable (UQ) in
// either base64 alphabet, and raw `workchain:hex64` (workchain 0 or -1).
// Testnet-only addresses (tag bit 0x80 set) are rejected.
func tonParseAddress(addr string) ([]byte, error) {
	_, hash, err := tonParseAddressFull(addr)
	return hash, err
}

// tonParseAddressFull decodes any accepted TON address form and returns both the
// signed workchain id and the 32-byte account hash. Workchain is 0 (basechain)
// or -1 (masterchain). The internal-message addr_std encoding needs the
// workchain byte, so transaction building uses this richer form.
func tonParseAddressFull(addr string) (int32, []byte, error) {
	// Raw form: "0:<64 hex>" or "-1:<64 hex>".
	if i := strings.IndexByte(addr, ':'); i >= 0 {
		wcStr := addr[:i]
		var wc int32
		switch wcStr {
		case "0":
			wc = 0
		case "-1":
			wc = -1
		default:
			return 0, nil, addrErr(TON, "raw address: workchain must be 0 or -1")
		}
		h := addr[i+1:]
		if len(h) != 64 {
			return 0, nil, addrErr(TON, "raw address: hash must be 64 hex chars")
		}
		raw, err := hex.DecodeString(h)
		if err != nil {
			return 0, nil, addrErr(TON, "raw address: invalid hex")
		}
		return wc, raw, nil
	}

	// User-friendly form: 48 base64 chars, either alphabet.
	if len(addr) != 48 {
		return 0, nil, addrErr(TON, fmt.Sprintf("user-friendly address must be 48 chars, got %d", len(addr)))
	}
	norm := strings.NewReplacer("-", "+", "_", "/").Replace(addr)
	raw, err := base64.StdEncoding.DecodeString(norm)
	if err != nil {
		return 0, nil, addrErr(TON, "base64 decode failed")
	}
	if len(raw) != 36 {
		return 0, nil, addrErr(TON, fmt.Sprintf("decoded length %d (want 36)", len(raw)))
	}
	tag := raw[0]
	if tag&tonTagTestOnly != 0 {
		return 0, nil, addrErr(TON, "testnet-only address not accepted")
	}
	base := tag &^ tonTagTestOnly
	if base != tonTagBounceable && base != tonTagNonBounceable {
		return 0, nil, addrErr(TON, fmt.Sprintf("unknown address tag 0x%02x", tag))
	}
	// raw[1] is the workchain byte (0x00 basechain / 0xff masterchain), a signed
	// int8; sign-extend it to int32.
	wc := int32(int8(raw[1])) // #nosec G115 -- deliberate two's-complement reinterpretation of the 1-byte workchain tag
	body := raw[:34]
	want := crc16XModem(body)
	got := uint16(raw[34])<<8 | uint16(raw[35])
	if got != want {
		return 0, nil, addrErr(TON, "bad checksum")
	}
	return wc, raw[2:34], nil
}

// tonValidator is the address-validator registry entry for TON.
func tonValidator(_ Chain) addressValidator {
	return func(addr string) ([]byte, error) {
		return tonParseAddress(addr)
	}
}
