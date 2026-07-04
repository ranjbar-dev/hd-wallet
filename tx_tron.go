package hdwallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	txtron "github.com/ranjbar-dev/hd-wallet/txproto/tron"
)

// Tron transaction signing (TransferContract).
//
// Tron transactions are signed over txID = sha256(raw_data), where raw_data is
// the protobuf serialization of the on-chain Transaction.raw message. The
// resulting signature is the 65-byte recoverable secp256k1 signature (r||s||v,
// v in {0,1}) — Tron does NOT add Ethereum's 27 offset or an EIP-155 chain id.
//
// The internal raw_data layout (Tron protocol, field numbers fixed by the chain):
//
//	raw_data {
//	  1: ref_block_bytes  (bytes)  // last 2 bytes of LE(blockNumber), big-endian
//	  4: ref_block_hash   (bytes)  // sha256(blockHeader.raw)[8:16]
//	  8: expiration       (int64, ms)
//	  11: contract        (repeated Contract)
//	  14: timestamp       (int64, ms)
//	  18: fee_limit       (int64)  // omitted when zero
//	}
//	Contract {
//	  1: type      (enum; TransferContract = 1)
//	  2: parameter (google.protobuf.Any { 1: type_url, 2: value })
//	}
//	Any.value = TransferContract { 1: owner_address, 2: to_address, 3: amount }
//
// The block header used to derive ref_block_bytes/ref_block_hash is itself a
// protobuf (BlockHeader.raw): {1: timestamp, 2: tx_trie_root, 3: parent_hash,
// 7: number, 9: witness_address, 10: version}.
//
// We serialize these by hand with protowire so the bytes match Trust Wallet
// Core's protobuf output exactly; verified byte-for-byte against TWC's Tron
// AnySigner vector (see tx_tron_test.go).

// Tron ContractType enum values.
const (
	tronTransferType               = 1
	tronTransferAssetType          = 2
	tronVoteAssetType              = 3
	tronVoteWitnessType            = 4
	tronTriggerSmartContractType   = 31
	tronFreezeBalanceV2Type        = 54
	tronWithdrawExpireUnfreezeType = 56
	tronUnfreezeBalanceV2Type      = 55
	tronDelegateResourceType       = 57
	tronUndelegateResourceType     = 58
	tronFreezeBalanceType          = 11
	tronUnfreezeBalanceType        = 12
	tronWithdrawBalanceType        = 13
	tronUnfreezeAssetType          = 14
)

// google.protobuf.Any type_url strings for each contract type.
const (
	tronTransferTypeURL               = "type.googleapis.com/protocol.TransferContract"
	tronTransferAssetTypeURL          = "type.googleapis.com/protocol.TransferAssetContract"
	tronVoteAssetTypeURL              = "type.googleapis.com/protocol.VoteAssetContract"
	tronVoteWitnessTypeURL            = "type.googleapis.com/protocol.VoteWitnessContract"
	tronTriggerSmartContractTypeURL   = "type.googleapis.com/protocol.TriggerSmartContract"
	tronFreezeBalanceV2TypeURL        = "type.googleapis.com/protocol.FreezeBalanceV2Contract"
	tronWithdrawExpireUnfreezeTypeURL = "type.googleapis.com/protocol.WithdrawExpireUnfreezeContract"
	tronUnfreezeBalanceV2TypeURL      = "type.googleapis.com/protocol.UnfreezeBalanceV2Contract"
	tronDelegateResourceTypeURL       = "type.googleapis.com/protocol.DelegateResourceContract"
	tronUndelegateResourceTypeURL     = "type.googleapis.com/protocol.UndelegateResourceContract"
	tronFreezeBalanceTypeURL          = "type.googleapis.com/protocol.FreezeBalanceContract"
	tronUnfreezeBalanceTypeURL        = "type.googleapis.com/protocol.UnfreezeBalanceContract"
	tronUnfreezeAssetTypeURL          = "type.googleapis.com/protocol.UnfreezeAssetContract"
	tronWithdrawBalanceTypeURL        = "type.googleapis.com/protocol.WithdrawBalanceContract"
)

// signTronTx builds, signs and serializes a Tron transaction (TRX transfer or
// TRC-20 token transfer).
func (w *HDWallet) signTronTx(chain Chain, index uint32, in *txtron.SigningInput) (*txtron.SigningOutput, error) {
	if in.GetRawJson() != "" {
		return w.signTronRawJSON(chain, index, in.GetRawJson())
	}

	tx := in.GetTransaction()
	if tx == nil {
		return nil, fmt.Errorf("%w: tron: missing transaction", ErrTxInput)
	}

	contractMsg, err := tronContractMsg(tx)
	if err != nil {
		return nil, err
	}

	bh := tx.GetBlockHeader()
	if bh == nil {
		return nil, fmt.Errorf("%w: tron: missing block_header", ErrTxInput)
	}
	refBlockBytes := tronRefBlockBytes(bh.GetNumber())
	refBlockHash, err := tronRefBlockHash(bh)
	if err != nil {
		return nil, err
	}

	rawData := tronRawData(in, contractMsg, refBlockBytes, refBlockHash)

	// txID = sha256(raw_data); the signature is over this digest.
	id := sha256Sum(rawData)
	sig, err := w.SignIndex(chain, index, id)
	if err != nil {
		return nil, err
	}
	rec := sig.Recoverable() // 65 bytes r||s||v with v in {0,1}; Tron uses it as-is
	if rec == nil {
		return nil, fmt.Errorf("%w: %s is not a secp256k1 coin", ErrTxInput, chain)
	}

	return &txtron.SigningOutput{
		Id:            id,
		Signature:     rec,
		RawData:       rawData,
		RefBlockBytes: hex.EncodeToString(refBlockBytes),
		RefBlockHash:  refBlockHash,
	}, nil
}

// tronContractMsg builds the field-11 Contract message for the transaction's
// contract type (TransferContract or a TRC-20 TriggerSmartContract).
func tronContractMsg(tx *txtron.Transaction) ([]byte, error) {
	switch {
	case tx.GetTransfer() != nil:
		t := tx.GetTransfer()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		to, err := tronAddressBytes(t.GetToAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: to_address: %v", ErrTxInput, err)
		}
		return tronTransferContractMsg(owner, to, t.GetAmount()), nil
	case tx.GetTransferTrc20() != nil:
		t := tx.GetTransferTrc20()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		contract, err := tronAddressBytes(t.GetContractAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: contract_address: %v", ErrTxInput, err)
		}
		recipient, err := tronAddressBytes(t.GetToAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: to_address: %v", ErrTxInput, err)
		}
		data, err := tronTRC20TransferData(recipient, t.GetAmount())
		if err != nil {
			return nil, err
		}
		return tronTriggerSmartContractMsg(owner, contract, data, 0, 0, 0), nil
	case tx.GetTriggerSmartContract() != nil:
		t := tx.GetTriggerSmartContract()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		contract, err := tronAddressBytes(t.GetContractAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: contract_address: %v", ErrTxInput, err)
		}
		return tronTriggerSmartContractMsg(owner, contract, t.GetData(), t.GetCallValue(), t.GetCallTokenValue(), t.GetTokenId()), nil
	case tx.GetTransferAsset() != nil:
		t := tx.GetTransferAsset()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		to, err := tronAddressBytes(t.GetToAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: to_address: %v", ErrTxInput, err)
		}
		return tronTransferAssetContractMsg([]byte(t.GetAssetName()), owner, to, t.GetAmount()), nil
	case tx.GetFreezeBalanceV2() != nil:
		t := tx.GetFreezeBalanceV2()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		return tronFreezeBalanceV2Msg(owner, t.GetFrozenBalance(), int32(t.GetResource())), nil
	case tx.GetUnfreezeBalanceV2() != nil:
		t := tx.GetUnfreezeBalanceV2()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		return tronUnfreezeBalanceV2Msg(owner, t.GetUnfreezeBalance(), int32(t.GetResource())), nil
	case tx.GetDelegateResource() != nil:
		t := tx.GetDelegateResource()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		receiver, err := tronAddressBytes(t.GetReceiverAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: receiver_address: %v", ErrTxInput, err)
		}
		return tronDelegateResourceMsg(owner, int32(t.GetResource()), t.GetBalance(), receiver, t.GetLock()), nil
	case tx.GetUndelegateResource() != nil:
		t := tx.GetUndelegateResource()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		receiver, err := tronAddressBytes(t.GetReceiverAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: receiver_address: %v", ErrTxInput, err)
		}
		return tronUndelegateResourceMsg(owner, int32(t.GetResource()), t.GetBalance(), receiver), nil
	case tx.GetVoteWitness() != nil:
		t := tx.GetVoteWitness()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		voteAddrs := make([][]byte, 0, len(t.GetVotes()))
		voteCounts := make([]int64, 0, len(t.GetVotes()))
		for i, v := range t.GetVotes() {
			addr, err := tronAddressBytes(v.GetVoteAddress())
			if err != nil {
				return nil, fmt.Errorf("%w: tron: vote[%d] address: %v", ErrTxInput, i, err)
			}
			voteAddrs = append(voteAddrs, addr)
			voteCounts = append(voteCounts, v.GetVoteCount())
		}
		return tronVoteWitnessMsg(owner, voteAddrs, voteCounts, t.GetSupport()), nil
	case tx.GetWithdrawExpireUnfreeze() != nil:
		t := tx.GetWithdrawExpireUnfreeze()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		return tronWithdrawExpireUnfreezeMsg(owner), nil
	case tx.GetFreezeBalance() != nil:
		t := tx.GetFreezeBalance()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		var receiver []byte
		if t.GetReceiverAddress() != "" {
			receiver, err = tronAddressBytes(t.GetReceiverAddress())
			if err != nil {
				return nil, fmt.Errorf("%w: tron: receiver_address: %v", ErrTxInput, err)
			}
		}
		return tronFreezeBalanceMsg(owner, t.GetFrozenBalance(), t.GetFrozenDuration(), int32(t.GetResource()), receiver), nil
	case tx.GetUnfreezeBalance() != nil:
		t := tx.GetUnfreezeBalance()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		var receiver []byte
		if t.GetReceiverAddress() != "" {
			receiver, err = tronAddressBytes(t.GetReceiverAddress())
			if err != nil {
				return nil, fmt.Errorf("%w: tron: receiver_address: %v", ErrTxInput, err)
			}
		}
		return tronUnfreezeBalanceMsg(owner, int32(t.GetResource()), receiver), nil
	case tx.GetUnfreezeAsset() != nil:
		t := tx.GetUnfreezeAsset()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		return tronUnfreezeAssetMsg(owner), nil
	case tx.GetWithdrawBalance() != nil:
		t := tx.GetWithdrawBalance()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		return tronWithdrawBalanceMsg(owner), nil
	case tx.GetVoteAsset() != nil:
		t := tx.GetVoteAsset()
		owner, err := tronAddressBytes(t.GetOwnerAddress())
		if err != nil {
			return nil, fmt.Errorf("%w: tron: owner_address: %v", ErrTxInput, err)
		}
		voteAddrs := make([][]byte, 0, len(t.GetVoteAddress()))
		for i, addr := range t.GetVoteAddress() {
			b, err := tronAddressBytes(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: tron: vote_address[%d]: %v", ErrTxInput, i, err)
			}
			voteAddrs = append(voteAddrs, b)
		}
		return tronVoteAssetMsg(owner, voteAddrs, t.GetSupport(), t.GetCount()), nil
	default:
		return nil, fmt.Errorf("%w: tron: no supported contract set", ErrTxInput)
	}
}

// tronTransferContractMsg builds the Contract {1: type=TransferContract, 2: Any}.
func tronTransferContractMsg(owner, to []byte, amount int64) []byte {
	// Inner TransferContract: {1: owner, 2: to, 3: amount}.
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	inner = protowire.AppendTag(inner, 2, protowire.BytesType)
	inner = protowire.AppendBytes(inner, to)
	inner = protowire.AppendTag(inner, 3, protowire.VarintType)
	inner = protowire.AppendVarint(inner, i64AsU64(amount))
	return tronContractWrap(tronTransferType, tronTransferTypeURL, inner)
}

// tronTriggerSmartContractMsg builds the Contract {1: type=TriggerSmartContract,
// 2: Any} for a smart-contract call. Fields are appended in ascending order;
// zero-valued varint fields and empty bytes fields are omitted (proto3 defaults).
func tronTriggerSmartContractMsg(owner, contractAddr, data []byte, callValue, callTokenValue, tokenID int64) []byte {
	// TriggerSmartContract: {1: owner, 2: contract, [3: call_value], [4: data],
	//                         [5: call_token_value], [6: token_id]}.
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	inner = protowire.AppendTag(inner, 2, protowire.BytesType)
	inner = protowire.AppendBytes(inner, contractAddr)
	if callValue != 0 {
		inner = protowire.AppendTag(inner, 3, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i64AsU64(callValue))
	}
	if len(data) > 0 {
		inner = protowire.AppendTag(inner, 4, protowire.BytesType)
		inner = protowire.AppendBytes(inner, data)
	}
	if callTokenValue != 0 {
		inner = protowire.AppendTag(inner, 5, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i64AsU64(callTokenValue))
	}
	if tokenID != 0 {
		inner = protowire.AppendTag(inner, 6, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i64AsU64(tokenID))
	}
	return tronContractWrap(tronTriggerSmartContractType, tronTriggerSmartContractTypeURL, inner)
}

// tronContractWrap wraps an inner contract message in its google.protobuf.Any and
// the enclosing Contract {1: type, 2: parameter(Any)} message.
func tronContractWrap(ctype uint64, typeURL string, inner []byte) []byte {
	var anyMsg []byte
	anyMsg = protowire.AppendTag(anyMsg, 1, protowire.BytesType)
	anyMsg = protowire.AppendString(anyMsg, typeURL)
	anyMsg = protowire.AppendTag(anyMsg, 2, protowire.BytesType)
	anyMsg = protowire.AppendBytes(anyMsg, inner)

	var contractMsg []byte
	contractMsg = protowire.AppendTag(contractMsg, 1, protowire.VarintType)
	contractMsg = protowire.AppendVarint(contractMsg, ctype)
	contractMsg = protowire.AppendTag(contractMsg, 2, protowire.BytesType)
	contractMsg = protowire.AppendBytes(contractMsg, anyMsg)
	return contractMsg
}

// tronTRC20TransferData builds the transfer(address,uint256) calldata for a
// TRC-20 transfer: the 4-byte selector followed by two 32-byte words.
//
// Matching Trust Wallet Core, the recipient is the FULL 21-byte Tron address
// (0x41 || hash20) left-padded to 32 bytes — the 0x41 prefix lands in the high
// (masked) bits, so it is on-chain-equivalent to the 20-byte form but is a
// distinct byte sequence that the signed txID depends on. amount is big-endian
// uint256 bytes.
func tronTRC20TransferData(recipient, amount []byte) ([]byte, error) {
	if len(recipient) != 21 {
		return nil, fmt.Errorf("%w: tron: recipient must be 21 bytes", ErrTxInput)
	}
	selector := ABIFunctionSelector("transfer", []string{"address", "uint256"}) // 0xa9059cbb
	data := make([]byte, 0, 4+32+32)
	data = append(data, selector...)
	data = append(data, leftPad(recipient, 32)...)
	data = append(data, leftPad(amount, 32)...)
	return data, nil
}

// tronTransferAssetContractMsg builds the Contract for a TRC-10 token transfer.
// TransferAssetContract inner: {1: asset_name, 2: owner, 3: to, 4: amount}.
func tronTransferAssetContractMsg(assetName, owner, to []byte, amount int64) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, assetName)
	inner = protowire.AppendTag(inner, 2, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	inner = protowire.AppendTag(inner, 3, protowire.BytesType)
	inner = protowire.AppendBytes(inner, to)
	inner = protowire.AppendTag(inner, 4, protowire.VarintType)
	inner = protowire.AppendVarint(inner, i64AsU64(amount))
	return tronContractWrap(tronTransferAssetType, tronTransferAssetTypeURL, inner)
}

// tronFreezeBalanceV2Msg builds FreezeBalanceV2Contract: {1: owner, 2: frozen_balance, 3: resource}.
func tronFreezeBalanceV2Msg(owner []byte, frozenBalance int64, resource int32) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	inner = protowire.AppendTag(inner, 2, protowire.VarintType)
	inner = protowire.AppendVarint(inner, i64AsU64(frozenBalance))
	if resource != 0 {
		inner = protowire.AppendTag(inner, 3, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i32AsU64(resource))
	}
	return tronContractWrap(tronFreezeBalanceV2Type, tronFreezeBalanceV2TypeURL, inner)
}

// tronUnfreezeBalanceV2Msg builds UnfreezeBalanceV2Contract: {1: owner, 2: unfreeze_balance, 3: resource}.
func tronUnfreezeBalanceV2Msg(owner []byte, unfreezeBalance int64, resource int32) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	inner = protowire.AppendTag(inner, 2, protowire.VarintType)
	inner = protowire.AppendVarint(inner, i64AsU64(unfreezeBalance))
	if resource != 0 {
		inner = protowire.AppendTag(inner, 3, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i32AsU64(resource))
	}
	return tronContractWrap(tronUnfreezeBalanceV2Type, tronUnfreezeBalanceV2TypeURL, inner)
}

// tronDelegateResourceMsg builds DelegateResourceContract:
// {1: owner, 2: resource, 3: balance, 4: receiver, 5: lock}.
func tronDelegateResourceMsg(owner []byte, resource int32, balance int64, receiver []byte, lock bool) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	if resource != 0 {
		inner = protowire.AppendTag(inner, 2, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i32AsU64(resource))
	}
	inner = protowire.AppendTag(inner, 3, protowire.VarintType)
	inner = protowire.AppendVarint(inner, i64AsU64(balance))
	inner = protowire.AppendTag(inner, 4, protowire.BytesType)
	inner = protowire.AppendBytes(inner, receiver)
	if lock {
		inner = protowire.AppendTag(inner, 5, protowire.VarintType)
		inner = protowire.AppendVarint(inner, 1)
	}
	return tronContractWrap(tronDelegateResourceType, tronDelegateResourceTypeURL, inner)
}

// tronUndelegateResourceMsg builds UndelegateResourceContract:
// {1: owner, 2: resource, 3: balance, 4: receiver}.
func tronUndelegateResourceMsg(owner []byte, resource int32, balance int64, receiver []byte) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	if resource != 0 {
		inner = protowire.AppendTag(inner, 2, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i32AsU64(resource))
	}
	inner = protowire.AppendTag(inner, 3, protowire.VarintType)
	inner = protowire.AppendVarint(inner, i64AsU64(balance))
	inner = protowire.AppendTag(inner, 4, protowire.BytesType)
	inner = protowire.AppendBytes(inner, receiver)
	return tronContractWrap(tronUndelegateResourceType, tronUndelegateResourceTypeURL, inner)
}

// tronVoteWitnessMsg builds VoteWitnessContract from parallel slices of addresses and counts.
func tronVoteWitnessMsg(owner []byte, addrs [][]byte, counts []int64, support bool) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	for i, addr := range addrs {
		var voteMsg []byte
		voteMsg = protowire.AppendTag(voteMsg, 1, protowire.BytesType)
		voteMsg = protowire.AppendBytes(voteMsg, addr)
		voteMsg = protowire.AppendTag(voteMsg, 2, protowire.VarintType)
		voteMsg = protowire.AppendVarint(voteMsg, i64AsU64(counts[i]))
		inner = protowire.AppendTag(inner, 2, protowire.BytesType)
		inner = protowire.AppendBytes(inner, voteMsg)
	}
	if support {
		inner = protowire.AppendTag(inner, 3, protowire.VarintType)
		inner = protowire.AppendVarint(inner, 1)
	}
	return tronContractWrap(tronVoteWitnessType, tronVoteWitnessTypeURL, inner)
}

// tronWithdrawExpireUnfreezeMsg builds WithdrawExpireUnfreezeContract: {1: owner}.
func tronWithdrawExpireUnfreezeMsg(owner []byte) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	return tronContractWrap(tronWithdrawExpireUnfreezeType, tronWithdrawExpireUnfreezeTypeURL, inner)
}

// tronUnfreezeAssetMsg builds UnfreezeAssetContract: {1: owner}.
func tronUnfreezeAssetMsg(owner []byte) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	return tronContractWrap(tronUnfreezeAssetType, tronUnfreezeAssetTypeURL, inner)
}

// tronWithdrawBalanceMsg builds WithdrawBalanceContract: {1: owner}.
func tronWithdrawBalanceMsg(owner []byte) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	return tronContractWrap(tronWithdrawBalanceType, tronWithdrawBalanceTypeURL, inner)
}

// tronVoteAssetMsg builds VoteAssetContract (TRC-10 asset voting).
// On-chain inner layout: {1: owner, 2*: vote_addr (flat repeated bytes),
// [3: support varint], [5: count varint]}.
// Fields are in ascending order: 1, 2, 3, 5.
// Note: on-chain field number for count is 5, not proto field 4.
func tronVoteAssetMsg(owner []byte, voteAddrs [][]byte, support bool, count int32) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	for _, addr := range voteAddrs {
		inner = protowire.AppendTag(inner, 2, protowire.BytesType)
		inner = protowire.AppendBytes(inner, addr)
	}
	if support {
		inner = protowire.AppendTag(inner, 3, protowire.VarintType)
		inner = protowire.AppendVarint(inner, 1)
	}
	if count != 0 {
		inner = protowire.AppendTag(inner, 5, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i32AsU64(count))
	}
	return tronContractWrap(tronVoteAssetType, tronVoteAssetTypeURL, inner)
}

// tronFreezeBalanceMsg builds the legacy FreezeBalanceContract (Stake 1.0):
// on-chain inner layout: {1: owner, 2: frozen_balance, [3: frozen_duration],
// [10: resource], [15: receiver_address]}.
// Fields are in ascending order; varint fields are omitted when zero,
// bytes fields are omitted when empty (proto3 default-omission).
func tronFreezeBalanceMsg(owner []byte, frozenBalance, frozenDuration int64, resource int32, receiver []byte) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	inner = protowire.AppendTag(inner, 2, protowire.VarintType)
	inner = protowire.AppendVarint(inner, i64AsU64(frozenBalance))
	if frozenDuration != 0 {
		inner = protowire.AppendTag(inner, 3, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i64AsU64(frozenDuration))
	}
	if resource != 0 {
		inner = protowire.AppendTag(inner, 10, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i32AsU64(resource))
	}
	if len(receiver) > 0 {
		inner = protowire.AppendTag(inner, 15, protowire.BytesType)
		inner = protowire.AppendBytes(inner, receiver)
	}
	return tronContractWrap(tronFreezeBalanceType, tronFreezeBalanceTypeURL, inner)
}

// tronUnfreezeBalanceMsg builds the legacy UnfreezeBalanceContract (Stake 1.0):
// on-chain inner layout: {1: owner, [10: resource], [15: receiver_address]}.
// Fields are in ascending order; resource is omitted when 0 (BANDWIDTH),
// receiver is omitted when empty (self-unfreeze).
func tronUnfreezeBalanceMsg(owner []byte, resource int32, receiver []byte) []byte {
	var inner []byte
	inner = protowire.AppendTag(inner, 1, protowire.BytesType)
	inner = protowire.AppendBytes(inner, owner)
	if resource != 0 {
		inner = protowire.AppendTag(inner, 10, protowire.VarintType)
		inner = protowire.AppendVarint(inner, i32AsU64(resource))
	}
	if len(receiver) > 0 {
		inner = protowire.AppendTag(inner, 15, protowire.BytesType)
		inner = protowire.AppendBytes(inner, receiver)
	}
	return tronContractWrap(tronUnfreezeBalanceType, tronUnfreezeBalanceTypeURL, inner)
}

// tronRawData serializes the on-chain Transaction.raw message around a prebuilt
// Contract message. Zero-valued expiration/timestamp/fee_limit are omitted, per
// proto3 serialization (matching Trust Wallet Core).
func tronRawData(in *txtron.SigningInput, contractMsg, refBlockBytes, refBlockHash []byte) []byte {
	tx := in.GetTransaction()

	// Trust Wallet Core defaults: timestamp -> now if unset; expiration ->
	// timestamp + 10h if unset. Both are always present in raw_data; fee_limit is
	// emitted only when non-zero (no default).
	ts := tx.GetTimestamp()
	if ts == 0 {
		ts = time.Now().UnixMilli()
	}
	exp := tx.GetExpiration()
	if exp == 0 {
		exp = ts + tronDefaultExpirationMs
	}

	// raw_data, fields in ascending order: 1, 4, (5 memo), 8, 11, 14, (18).
	var raw []byte
	raw = protowire.AppendTag(raw, 1, protowire.BytesType)
	raw = protowire.AppendBytes(raw, refBlockBytes)
	raw = protowire.AppendTag(raw, 4, protowire.BytesType)
	raw = protowire.AppendBytes(raw, refBlockHash)
	if memo := tx.GetMemo(); len(memo) > 0 {
		raw = protowire.AppendTag(raw, 5, protowire.BytesType)
		raw = protowire.AppendBytes(raw, memo)
	}
	raw = protowire.AppendTag(raw, 8, protowire.VarintType)
	raw = protowire.AppendVarint(raw, i64AsU64(exp))
	raw = protowire.AppendTag(raw, 11, protowire.BytesType)
	raw = protowire.AppendBytes(raw, contractMsg)
	raw = protowire.AppendTag(raw, 14, protowire.VarintType)
	raw = protowire.AppendVarint(raw, i64AsU64(ts))
	if fee := tx.GetFeeLimit(); fee != 0 {
		raw = protowire.AppendTag(raw, 18, protowire.VarintType)
		raw = protowire.AppendVarint(raw, i64AsU64(fee))
	}
	return raw
}

// tronDefaultExpirationMs is Trust Wallet Core's default transaction lifetime
// (10 hours) applied when no expiration is provided.
const tronDefaultExpirationMs int64 = 10 * 60 * 60 * 1000

// tronRefBlockBytes returns the 2-byte ref_block_bytes for a block number: the
// last two bytes of the 8-byte big-endian number (TWC encodes LE then reverses,
// equivalently bytes [6:8] of the big-endian encoding).
func tronRefBlockBytes(number int64) []byte {
	var be [8]byte
	n := i64AsU64(number)
	for i := 7; i >= 0; i-- {
		be[i] = byte(n)
		n >>= 8
	}
	out := make([]byte, 2)
	copy(out, be[6:8])
	return out
}

// tronRefBlockHash serializes the block header's raw message, hashes it with
// sha256, and returns bytes [8:16] (ref_block_hash).
func tronRefBlockHash(bh *txtron.BlockHeader) ([]byte, error) {
	// BlockHeader.raw: {1: timestamp, 2: tx_trie_root, 3: parent_hash,
	// 7: number, 9: witness_address, 10: version}, ascending order.
	var raw []byte
	raw = protowire.AppendTag(raw, 1, protowire.VarintType)
	raw = protowire.AppendVarint(raw, i64AsU64(bh.GetTimestamp()))
	raw = protowire.AppendTag(raw, 2, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bh.GetTxTrieRoot())
	raw = protowire.AppendTag(raw, 3, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bh.GetParentHash())
	raw = protowire.AppendTag(raw, 7, protowire.VarintType)
	raw = protowire.AppendVarint(raw, i64AsU64(bh.GetNumber()))
	raw = protowire.AppendTag(raw, 9, protowire.BytesType)
	raw = protowire.AppendBytes(raw, bh.GetWitnessAddress())
	raw = protowire.AppendTag(raw, 10, protowire.VarintType)
	raw = protowire.AppendVarint(raw, i32AsU64(bh.GetVersion()))

	hash := sha256Sum(raw)
	if len(hash) < 16 {
		return nil, fmt.Errorf("%w: tron: short block hash", ErrTxInput)
	}
	return hash[8:16], nil
}

// tronAddressBytes resolves a Tron address string to its 21-byte form (0x41 ||
// 20-byte hash160). It accepts a base58check "T..." address or a raw hex string
// (with or without the 0x41 prefix already present).
func tronAddressBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty address")
	}
	// Try base58check first (Tron's external form).
	if b, err := base58CheckDecode(base58BTC, s); err == nil && len(b) == 21 && b[0] == 0x41 {
		return b, nil
	}
	// Fall back to raw hex.
	raw, err := hexToBytes(s)
	if err != nil {
		return nil, fmt.Errorf("not base58check or hex: %v", err)
	}
	switch {
	case len(raw) == 21 && raw[0] == 0x41:
		return raw, nil
	case len(raw) == 20:
		return append([]byte{0x41}, raw...), nil
	default:
		return nil, fmt.Errorf("unexpected address length %d", len(raw))
	}
}

// signTronRawJSON signs a pre-built Tron transaction provided as node/DApp JSON
// (the wallet-connect flow). It extracts raw_data_hex, computes txID =
// sha256(raw_data), optionally verifies that txID matches the supplied txID
// field, then signs and returns the output.
func (w *HDWallet) signTronRawJSON(chain Chain, index uint32, jsonStr string) (*txtron.SigningOutput, error) {
	// Unmarshal only the fields we need.
	var parsed struct {
		TxID       string `json:"txID"`
		RawDataHex string `json:"raw_data_hex"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return nil, fmt.Errorf("%w: tron: raw_json: %v", ErrTxInput, err)
	}
	if parsed.RawDataHex == "" {
		return nil, fmt.Errorf("%w: tron: raw_json: missing raw_data_hex", ErrTxInput)
	}
	rawData, err := hex.DecodeString(parsed.RawDataHex)
	if err != nil {
		return nil, fmt.Errorf("%w: tron: raw_json: invalid raw_data_hex: %v", ErrTxInput, err)
	}
	id := sha256Sum(rawData)
	// Fund-critical guard: if txID is present, it MUST match our computed hash.
	if parsed.TxID != "" && hex.EncodeToString(id) != strings.ToLower(parsed.TxID) {
		return nil, fmt.Errorf("%w: tron: raw_json: txID mismatch", ErrTxInput)
	}
	sig, err := w.SignIndex(chain, index, id)
	if err != nil {
		return nil, fmt.Errorf("%w: tron: %v", ErrTxInput, err)
	}
	rec := sig.Recoverable()
	if rec == nil {
		return nil, fmt.Errorf("%w: %s is not a secp256k1 coin", ErrTxInput, chain)
	}
	return &txtron.SigningOutput{Id: id, Signature: rec, RawData: rawData}, nil
}
