// Oracle program: uses go-ethereum to sign EIP-4844 and EIP-7702 transactions
// and print the expected hex bytes, which are then hardcoded as test vectors.
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// The canonical test private key used across the EVM tests.
const privHex = "4646464646464646464646464646464646464646464646464646464646464646"

func mustPrivKey() *ecdsa.PrivateKey {
	b, err := hex.DecodeString(privHex)
	if err != nil {
		panic(err)
	}
	key, err := crypto.ToECDSA(b)
	if err != nil {
		panic(err)
	}
	return key
}

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func u256hex(s string) *uint256.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex: " + s)
	}
	u, overflow := uint256.FromBig(b)
	if overflow {
		panic("overflow: " + s)
	}
	return u
}

func main() {
	key := mustPrivKey()
	chainID := big.NewInt(1)

	// ---- EIP-4844 vector ----
	// Simple native transfer with one blob versioned hash, no access list.
	// Parameters mirror the existing EIP-2930/1559 vectors for easy cross-reference.
	{
		// A blob versioned hash: version byte 0x01 followed by 31 bytes of sha256("blob0")[1:]
		// Using sha256 (not keccak) to match the EIP-4844 KZG versioned hash format.
		hasher := sha256.New()
		hasher.Write([]byte("commitment0"))
		digest := hasher.Sum(nil)
		var blobHash [32]byte
		blobHash[0] = 0x01
		copy(blobHash[1:], digest[1:])

		to := common.HexToAddress("0x3535353535353535353535353535353535353535")
		tx4844 := types.NewTx(&types.BlobTx{
			ChainID:    uint256.NewInt(1),
			Nonce:      9,
			GasTipCap:  u256hex("77359400"), // 2 gwei
			GasFeeCap:  u256hex("B2D05E00"), // 3 gwei
			Gas:        0x5208,
			To:         to,
			Value:      u256hex("0de0b6b3a7640000"), // 1 ETH
			Data:       nil,
			BlobFeeCap: uint256.NewInt(1), // max_fee_per_blob_gas = 1
			BlobHashes: []common.Hash{blobHash},
		})

		signer4844 := types.NewCancunSigner(chainID)
		signed4844, err := types.SignTx(tx4844, signer4844, key)
		if err != nil {
			panic(fmt.Sprintf("EIP-4844 sign: %v", err))
		}
		raw4844, err := signed4844.MarshalBinary()
		if err != nil {
			panic(fmt.Sprintf("EIP-4844 marshal: %v", err))
		}
		fmt.Printf("// EIP-4844 (type-3) vector\n")
		fmt.Printf("// max_fee_per_blob_gas = 1 (0x01)\n")
		fmt.Printf("// blob_versioned_hash[0] = 0x%s\n", hex.EncodeToString(blobHash[:]))
		fmt.Printf("// (version byte 0x01 + sha256('commitment0')[1:])\n")
		fmt.Printf("eip4844Want := %q\n\n", hex.EncodeToString(raw4844))
	}

	// ---- EIP-7702 vector ----
	// Simple native transfer with one authorization.
	{
		to := common.HexToAddress("0x3535353535353535353535353535353535353535")
		delegationTarget := common.HexToAddress("0xdEADBEEf00000000000000000000000000000000")

		// Build a deterministic "pre-signed" authorization tuple.
		// The authorizer uses a secondary test key for clear separation.
		authKeyHex := "1234567812345678123456781234567812345678123456781234567812345678"
		authKeyBytes, _ := hex.DecodeString(authKeyHex)
		authKey, _ := crypto.ToECDSA(authKeyBytes)

		auth := types.SetCodeAuthorization{
			ChainID: *uint256.NewInt(1),
			Address: delegationTarget,
			Nonce:   1,
		}
		signedAuth, err := types.SignSetCode(authKey, auth)
		if err != nil {
			panic(fmt.Sprintf("EIP-7702 sign auth: %v", err))
		}
		fmt.Printf("// EIP-7702 authorization details:\n")
		fmt.Printf("// auth key    = 0x%s\n", authKeyHex)
		fmt.Printf("// delegation  = %s\n", delegationTarget.Hex())
		fmt.Printf("// auth.nonce  = 1\n")
		fmt.Printf("// signed auth (chain_id=1 address=%s nonce=1):\n", signedAuth.Address.Hex())
		rBytes := signedAuth.R.Bytes32()
		sBytes := signedAuth.S.Bytes32()
		fmt.Printf("//   y_parity = %d\n", signedAuth.V)
		fmt.Printf("//   r = 0x%s\n", hex.EncodeToString(rBytes[:]))
		fmt.Printf("//   s = 0x%s\n", hex.EncodeToString(sBytes[:]))

		tx7702 := types.NewTx(&types.SetCodeTx{
			ChainID:   uint256.NewInt(1),
			Nonce:     9,
			GasTipCap: u256hex("77359400"),
			GasFeeCap: u256hex("B2D05E00"),
			Gas:       0x5208,
			To:        to,
			Value:     u256hex("0de0b6b3a7640000"),
			Data:      nil,
			AuthList:  []types.SetCodeAuthorization{signedAuth},
		})

		signer7702 := types.NewPragueSigner(chainID)
		signed7702, err := types.SignTx(tx7702, signer7702, key)
		if err != nil {
			panic(fmt.Sprintf("EIP-7702 sign: %v", err))
		}
		raw7702, err := signed7702.MarshalBinary()
		if err != nil {
			panic(fmt.Sprintf("EIP-7702 marshal: %v", err))
		}
		fmt.Printf("eip7702Want := %q\n\n", hex.EncodeToString(raw7702))
	}
}
