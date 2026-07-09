package hdwallet

// Polkadot (DOT) transaction signing.
//
// Wire format: SCALE-encoded signed UncheckedExtrinsic v4:
//
//	compact(len) ‖ 0x84 ‖ signer ‖ 0x00 ‖ sig(64) ‖ era ‖ compact(nonce) ‖
//	compact(tip) ‖ call
//
// 0x84 is the "signed" bit (0x80) | extrinsic format version 4; `signer` is
// the sender account (raw 32-byte AccountId, or MultiAddress::Id — a 0x00
// prefix + AccountId — when multi_address is set); the 0x00 before the
// signature is the MultiSignature::Ed25519 discriminant (DOT derives on
// ed25519 in this library, matching Trust Wallet Core).
//
// Signing preimage:
//
//	call ‖ era ‖ compact(nonce) ‖ compact(tip) ‖ specVersion(u32 LE) ‖
//	transactionVersion(u32 LE) ‖ genesisHash(32) ‖ blockHash(32)
//
// A preimage longer than 256 bytes is replaced by its BLAKE2b-256 digest
// before signing (Substrate rule); ed25519 then signs the raw bytes.
//
// Calls built here: Balances.transfer_keep_alive (default pallet/call indices
// 5/3 on the Polkadot relay chain) and Assets.transfer_keep_alive (default
// 50/9 on Polkadot Asset Hub; the asset id — USDT = 1984, USDC = 1337 — is a
// compact-encoded call argument before the destination). Call indices are
// runtime-metadata values, so both accept a CallIndices override for other
// Substrate runtimes or future renumbering.
//
// Pinned byte-for-byte (signing preimage and signed extrinsic) against Trust
// Wallet Core's TWAnySignerPolkadot.SignTransfer_9fd062 (ed25519 is
// deterministic, so the full extrinsic including the signature is exact):
// https://github.com/trustwallet/wallet-core/blob/master/tests/chains/Polkadot/TWAnySignerTests.cpp

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"

	"google.golang.org/protobuf/proto"

	txdot "github.com/ranjbar-dev/hd-wallet/txproto/polkadot"
)

// Default (pallet, call) indices from the live runtime metadata. Balances is
// pallet 5 on the Polkadot relay chain; Assets is pallet 50 on Asset Hub.
const (
	dotBalancesPallet            = 5
	dotBalancesTransferKeepAlive = 3
	dotAssetsPallet              = 50
	dotAssetsTransferKeepAlive   = 9
)

// signPolkadotTx builds, signs and serializes a Polkadot extrinsic.
func (w *HDWallet) signPolkadotTx(chain Chain, index uint32, in *txdot.SigningInput) (proto.Message, error) {
	call, err := dotBuildCall(in)
	if err != nil {
		return nil, err
	}
	preimage, extra, err := dotSigningPayload(in, call)
	if err != nil {
		return nil, err
	}

	// ed25519 signs the preimage directly; key derived and wiped inside.
	sig, err := w.SignIndex(chain, index, preimage)
	if err != nil {
		return nil, fmt.Errorf("DOT: sign: %w", err)
	}
	pub, err := w.PublicKeyIndex(chain, index)
	if err != nil {
		return nil, fmt.Errorf("DOT: derive public key: %w", err)
	}

	signer := dotEncodeAccount(pub, in.MultiAddress)
	body := make([]byte, 0, 1+len(signer)+1+64+len(extra)+len(call))
	body = append(body, 0x84) // signed flag | extrinsic version 4
	body = append(body, signer...)
	body = append(body, 0x00) // MultiSignature::Ed25519
	body = append(body, sig.Bytes()...)
	body = append(body, extra...)
	body = append(body, call...)

	encoded := scaleCompactU64(uint64(len(body))) // #nosec G115 -- len() is non-negative
	encoded = append(encoded, body...)

	return &txdot.SigningOutput{
		Encoded:    encoded,
		EncodedHex: "0x" + bytesToHex(encoded),
	}, nil
}

// dotBuildCall SCALE-encodes the call described by the input's message oneof.
func dotBuildCall(in *txdot.SigningInput) ([]byte, error) {
	if in.Network > 0xff {
		return nil, fmt.Errorf("%w: DOT: network prefix %d exceeds one byte", ErrTxInput, in.Network)
	}
	prefix := lowByte(int(in.Network))

	switch m := in.MessageOneof.(type) {
	case *txdot.SigningInput_BalanceTransfer:
		t := m.BalanceTransfer
		dest, err := ss58Validator(prefix, DOT)(t.ToAddress)
		if err != nil {
			return nil, fmt.Errorf("%w: DOT: to_address: %v", ErrTxInput, err)
		}
		value, err := dotU128("balance_transfer.value", t.Value)
		if err != nil {
			return nil, err
		}
		call, err := dotCallIndex(t.CallIndices, dotBalancesPallet, dotBalancesTransferKeepAlive)
		if err != nil {
			return nil, err
		}
		call = append(call, dotEncodeAccount(dest, in.MultiAddress)...)
		call = append(call, scaleCompact(value)...)
		return call, nil

	case *txdot.SigningInput_AssetTransfer:
		t := m.AssetTransfer
		dest, err := ss58Validator(prefix, DOT)(t.ToAddress)
		if err != nil {
			return nil, fmt.Errorf("%w: DOT: to_address: %v", ErrTxInput, err)
		}
		value, err := dotU128("asset_transfer.value", t.Value)
		if err != nil {
			return nil, err
		}
		call, err := dotCallIndex(t.CallIndices, dotAssetsPallet, dotAssetsTransferKeepAlive)
		if err != nil {
			return nil, err
		}
		call = append(call, scaleCompactU64(uint64(t.AssetId))...)
		call = append(call, dotEncodeAccount(dest, in.MultiAddress)...)
		call = append(call, scaleCompact(value)...)
		return call, nil

	default:
		return nil, fmt.Errorf("%w: DOT: balance_transfer or asset_transfer is required", ErrTxInput)
	}
}

// dotSigningPayload builds the extrinsic signing preimage and returns it along
// with the `extra` section (era ‖ compact(nonce) ‖ compact(tip)) that is reused
// verbatim in the signed extrinsic body.
func dotSigningPayload(in *txdot.SigningInput, call []byte) (preimage, extra []byte, err error) {
	if len(in.GenesisHash) != 32 {
		return nil, nil, fmt.Errorf("%w: DOT: genesis_hash must be 32 bytes", ErrTxInput)
	}
	blockHash := in.BlockHash
	if in.Era == nil {
		// Immortal extrinsics checkpoint at genesis.
		blockHash = in.GenesisHash
	}
	if len(blockHash) != 32 {
		return nil, nil, fmt.Errorf("%w: DOT: block_hash must be 32 bytes", ErrTxInput)
	}
	tip, err := dotU128("tip", in.Tip)
	if err != nil {
		return nil, nil, err
	}

	extra = dotEncodeEra(in.Era)
	extra = append(extra, scaleCompactU64(in.Nonce)...)
	extra = append(extra, scaleCompact(tip)...)

	preimage = make([]byte, 0, len(call)+len(extra)+8+64)
	preimage = append(preimage, call...)
	preimage = append(preimage, extra...)
	preimage = binary.LittleEndian.AppendUint32(preimage, in.SpecVersion)
	preimage = binary.LittleEndian.AppendUint32(preimage, in.TransactionVersion)
	preimage = append(preimage, in.GenesisHash...)
	preimage = append(preimage, blockHash...)
	if len(preimage) > 256 {
		preimage = blake2bPersonal(32, nil, preimage)
	}
	return preimage, extra, nil
}

// dotCallIndex returns the 2-byte (pallet, call) index, defaulting when no
// override is supplied. Out-of-range overrides are rejected rather than
// silently truncated — a wrong call index spends funds on the wrong call.
func dotCallIndex(ci *txdot.CallIndices, defModule, defMethod byte) ([]byte, error) {
	if ci == nil {
		return []byte{defModule, defMethod}, nil
	}
	if ci.ModuleIndex > 0xff || ci.MethodIndex > 0xff {
		return nil, fmt.Errorf("%w: DOT: call_indices (%d, %d) exceed one byte", ErrTxInput, ci.ModuleIndex, ci.MethodIndex)
	}
	return []byte{lowByte(int(ci.ModuleIndex)), lowByte(int(ci.MethodIndex))}, nil
}

// dotEncodeAccount encodes a 32-byte AccountId either raw (pre-spec-28
// runtimes; matches the pinned TWC vector) or as MultiAddress::Id (0x00 ‖
// AccountId; the Polkadot relay chain since spec 28 and Asset Hub).
func dotEncodeAccount(account []byte, multiAddress bool) []byte {
	if !multiAddress {
		return account
	}
	out := make([]byte, 0, 1+len(account))
	out = append(out, 0x00)
	return append(out, account...)
}

// dotEncodeEra encodes extrinsic mortality. A nil era is immortal (one 0x00
// byte). A mortal era is a u16 (little-endian): the period is rounded up to a
// power of two and clamped to [4, 65536]; the low 4 bits store
// log2(period)-1 (clamped to 1..15) and the high 12 bits the quantized phase,
// exactly matching Trust Wallet Core's encodeEra quantization.
func dotEncodeEra(era *txdot.Era) []byte {
	if era == nil {
		return []byte{0x00}
	}
	period := min(max(era.Period, 4), 1<<16)
	if period&(period-1) != 0 {
		period = 1 << bits.Len64(period) // round up to the next power of two
	}
	phase := era.BlockNumber % period
	quantize := max(period>>12, 1)
	low := uint64(bits.TrailingZeros64(period)) - 1 // #nosec G115 -- period >= 4, so trailing zeros >= 2
	low = min(low, 15)
	encoded := low | (phase/quantize)<<4
	return []byte{
		byte(encoded & 0xff),      // #nosec G115 -- explicit low-byte mask; era fits u16
		byte(encoded >> 8 & 0xff), // #nosec G115 -- explicit low-byte mask; era fits u16
	}
}

// dotU128 parses a big-endian proto bytes field as a Substrate Balance (u128).
func dotU128(field string, b []byte) (*big.Int, error) {
	if len(b) > 16 {
		return nil, fmt.Errorf("%w: DOT: %s exceeds u128 (16 bytes)", ErrTxInput, field)
	}
	return new(big.Int).SetBytes(b), nil
}

// scaleCompact encodes a non-negative integer in SCALE compact form: 1 byte
// for values < 2^6, 2 bytes < 2^14, 4 bytes < 2^30, and the big-integer mode
// (a length header followed by minimal little-endian bytes) beyond that.
func scaleCompact(n *big.Int) []byte {
	if n.Sign() <= 0 {
		return []byte{0x00}
	}
	if n.BitLen() <= 30 {
		v := n.Uint64()
		switch {
		case v < 1<<6:
			return []byte{byte(v << 2)} // #nosec G115 -- v < 64, shifted value fits one byte
		case v < 1<<14:
			x := v<<2 | 0b01
			return []byte{
				byte(x & 0xff),      // #nosec G115 -- explicit low-byte mask; x fits u16
				byte(x >> 8 & 0xff), // #nosec G115 -- explicit low-byte mask; x fits u16
			}
		default:
			x := v<<2 | 0b10
			return []byte{
				byte(x & 0xff),       // #nosec G115 -- explicit low-byte mask; x fits u32
				byte(x >> 8 & 0xff),  // #nosec G115 -- explicit low-byte mask; x fits u32
				byte(x >> 16 & 0xff), // #nosec G115 -- explicit low-byte mask; x fits u32
				byte(x >> 24 & 0xff), // #nosec G115 -- explicit low-byte mask; x fits u32
			}
		}
	}
	// Big-integer mode: header 0b11 with (len-4) in the upper 6 bits, then the
	// value as minimal little-endian bytes. Values here are validated to u128
	// (dotU128), far below the 67-byte format ceiling.
	be := n.Bytes()
	le := make([]byte, len(be))
	for i, b := range be {
		le[len(be)-1-i] = b
	}
	header := lowByte((len(le)-4)<<2 | 0b11)
	return append([]byte{header}, le...)
}

// scaleCompactU64 is scaleCompact for values already held as uint64.
func scaleCompactU64(v uint64) []byte {
	return scaleCompact(new(big.Int).SetUint64(v))
}
