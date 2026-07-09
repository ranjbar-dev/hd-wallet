package hdwallet

// providers.go — the "network seam" for SignTransaction callers.
//
// This library performs no network I/O. SignTransaction builds, signs, and
// serializes a broadcast-ready transaction from a protobuf SigningInput, but the
// caller is responsible for supplying all chain state (nonce, fees, UTXOs,
// recent blockhash). The interfaces below make that contract explicit and typed
// without introducing any concrete network code.
//
// None of these interfaces are called anywhere inside the package; they exist
// to document what each signing family needs so a production caller can wire
// them up correctly. See the per-family matrix in the package-level doc (doc.go)
// for the exact SigningInput field each value populates.

import (
	txbtc "github.com/ranjbar-dev/hd-wallet/txproto/bitcoin"
)

// NonceProvider returns the next outbound nonce (or sequence number) for the
// given account address. Callers supply the returned value as:
//
//   - SigningInput.nonce      — EVM chains (ETH, BNB, MATIC, …): the
//     sender's transaction count, as returned by eth_getTransactionCount with
//     the "pending" tag.
//   - SigningInput.sequence   — XRP Ledger: the account's Sequence field from
//     the account_info command. Cosmos SDK: the account's sequence from
//     GET /cosmos/auth/v1beta1/accounts/{address}.
//
// Note: Cosmos signing also requires account_number (a separate field on the
// same endpoint response). Call the endpoint once, extract both values, and
// set them independently on the SigningInput.
type NonceProvider interface {
	Nonce(address string) (uint64, error)
}

// UTXOProvider returns the set of unspent transaction outputs for the given
// address. Callers supply the returned slice as SigningInput.utxo for
// Bitcoin-family chains (BTC, LTC, DOGE, BCH, ZEC, DASH, and other registered
// UTXO altcoins in utxoTxChains).
//
// A production implementation queries an Electrum server, a block explorer
// REST API (Blockstream esplora, mempool.space), or a full-node
// listunspent RPC, then constructs one UnspentTransaction per output with
// out_point_hash (32-byte txid, internal byte order), out_point_index (vout),
// amount (satoshis), and script (scriptPubKey of the output being spent).
type UTXOProvider interface {
	UTXOs(address string) ([]*txbtc.UnspentTransaction, error)
}

// FeeOracle returns a fee recommendation for the given chain. The returned
// value maps to SigningInput fields as follows:
//
//   - EVM chains:       gas_price (wei, legacy) or max_fee_per_gas (wei,
//     EIP-1559). Obtain from eth_gasPrice or eth_feeHistory. Pair with
//     EthGasLimit to compute gas_limit.
//   - Bitcoin-family:   byte_fee (satoshis per virtual byte). Obtain from
//     estimatesmartfee or a fee-estimation API. CPFPFee and EstimateTxVsize
//     are available for CPFP bump calculations.
//   - XRP Ledger:       fee (drops). Obtain from the fee command.
//   - Tron TRC-20:      fee_limit (sun). Caller sets a conservative cap.
//
// For Cosmos chains, use CosmosGasLimit and CosmosMinFee with the chain's
// minimum gas price from CosmosMinGasPrices instead of calling FeeOracle.
type FeeOracle interface {
	FeeRate(chain Chain) (uint64, error)
}

// RecentBlockhashProvider returns the latest confirmed blockhash for a Solana
// cluster. Callers supply the returned base58-encoded string as
// SigningInput.recent_blockhash for SOL transactions.
//
// A production implementation calls the getLatestBlockhash JSON-RPC method
// and returns result.value.blockhash.
type RecentBlockhashProvider interface {
	RecentBlockhash() (string, error)
}

// SubstrateContextProvider supplies the chain/runtime context a mortal
// Substrate extrinsic (DOT) needs beyond the account nonce (which comes from
// NonceProvider / the system_accountNextIndex RPC). Callers map the returned
// values onto polkadot.SigningInput as follows:
//
//   - RuntimeVersion → spec_version and transaction_version, from the
//     state_getRuntimeVersion RPC (fields specVersion / transactionVersion).
//     Both enter the signing preimage, so a stale value invalidates the
//     signature at the node — refresh around runtime upgrades.
//   - GenesisHash → genesis_hash, from chain_getBlockHash(0). Constant per
//     chain; safe to cache forever.
//   - MortalityCheckpoint → block_hash and Era.block_number, from a recent
//     finalized block (chain_getFinalizedHead + chain_getHeader). Pick
//     Era.period (e.g. 64) for the validity window. For an immortal
//     extrinsic omit Era and leave block_hash unset (genesis is used).
type SubstrateContextProvider interface {
	RuntimeVersion(chain Chain) (specVersion, transactionVersion uint32, err error)
	GenesisHash(chain Chain) ([]byte, error)
	MortalityCheckpoint(chain Chain) (blockNumber uint64, blockHash []byte, err error)
}

// Broadcaster is a client-implemented sink that submits a signed, serialized
// raw transaction to the network. The library produces signed bytes in
// SigningOutput.Encoded and never broadcasts itself.
//
// chain identifies the target chain. rawTx is the value of
// SigningOutput.Encoded (binary) — use the corresponding _hex or TxBytes field
// if the endpoint expects hex or base64. Returns the transaction identifier
// (hash/txid) as reported by the node, or an error if submission fails.
type Broadcaster interface {
	Broadcast(chain Chain, rawTx []byte) (txID string, err error)
}
