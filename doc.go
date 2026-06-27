// Package hdwallet is a Trust Wallet–compatible hierarchical-deterministic (HD)
// wallet library for Go. It derives addresses and signs transactions for 130+
// networks across six elliptic curves, with secrets sealed in memguard enclaves
// so private keys are never exposed to the caller.
//
// # What you must supply (the network seam)
//
// [HDWallet.SignTransaction] builds, signs, and serializes a broadcast-ready
// raw transaction from a protobuf SigningInput. It performs NO network I/O.
// The caller is responsible for fetching all chain state before calling
// SignTransaction and setting it on the relevant SigningInput fields.
//
// The table below is the authoritative per-family reference: for each signing
// family it lists the SigningInput fields that carry chain state, the data
// source, and the provider interface (from providers.go) that formalises the
// contract. "Local" means the value is derived locally (from the wallet or
// known chain constants) without a network call.
//
// ## EVM — ethereum.SigningInput (ETH, BNB, MATIC, AVAX, …)
//
//	Field                    Source                          Provider
//	────────────────────────────────────────────────────────────────────
//	chain_id                 Known chain constant            Local
//	nonce                    eth_getTransactionCount         NonceProvider
//	gas_limit                eth_estimateGas / EthGasLimit   Local (helper)
//	gas_price (legacy)       eth_gasPrice                    FeeOracle
//	max_fee_per_gas (1559)   eth_feeHistory / baseFee        FeeOracle
//	max_inclusion_fee_per_gas eth_feeHistory                 FeeOracle
//	to_address               Caller knows                    —
//	transaction payload      Caller knows                    —
//
// tx_mode selects the serialization format: EthTxModeLegacy (0),
// EthTxModeEIP2930 (1), or EthTxModeEIP1559 (2).
//
// ## Tron — tron.SigningInput (TRX, TRC-20)
//
//	Field                          Source                      Provider
//	────────────────────────────────────────────────────────────────────
//	transaction.block_header       getNowBlock / getBlockByNum —
//	  .number                      block.block_header.raw.number
//	  .timestamp                   block.block_header.raw.timestamp
//	  .tx_trie_root                block.block_header.raw.txTrieRoot
//	  .parent_hash                 block.block_header.raw.parentHash
//	  .witness_address             block.block_header.raw.witnessAddress
//	  .version                     block.block_header.raw.version
//	transaction.expiration         timestamp + expiry window   Local (defaults +10 h)
//	transaction.timestamp          Current time                Local (defaults now)
//	transaction.fee_limit          Caller decision (TRC-20)    FeeOracle
//	contract payload               Caller knows                —
//
// ref_block_bytes and ref_block_hash are derived from block_header by the
// library; callers do not set them directly.
//
// ## XRP — ripple.SigningInput (XRP, issued currencies)
//
//	Field                Source                              Provider
//	────────────────────────────────────────────────────────────────────
//	sequence             account_info → Sequence             NonceProvider
//	last_ledger_sequence Current ledger index + safety margin —
//	fee                  fee command → base_fee (drops)      FeeOracle
//	account              Derived from wallet (Address/ParseAddress) Local
//	flags                Caller sets (e.g. tfFullyCanonicalSig)   —
//	payment / trust_set / offer fields   Caller knows        —
//
// ## Cosmos — cosmos.SigningInput (ATOM, OSMO, JUNO, EVMOS, INJ, …)
//
//	Field                Source                              Provider
//	────────────────────────────────────────────────────────────────────
//	account_number       /cosmos/auth/v1beta1/accounts/{addr} → account_number   NonceProvider (first call)
//	sequence             /cosmos/auth/v1beta1/accounts/{addr} → sequence         NonceProvider (second call)
//	chain_id             Known chain constant                Local
//	fee.gas              CosmosGasLimit(in) helper           Local (helper)
//	fee.amount / denom   CosmosMinFee(gas, price, denom)     Local (helper)
//	memo                 Caller                              —
//	messages / send      Caller knows                        —
//
// Both account_number and sequence come from the same REST endpoint; fetch
// once and assign both fields. CosmosMinGasPrices maps well-known chains to
// their minimum gas price if you do not have a live oracle.
//
// Cosmos Ethermint chains (EVMOS, INJ) use keccak256(SignDoc) instead of
// sha256 and a chain-specific pubkey type URL in AuthInfo; both are handled
// automatically by the SignTransaction dispatcher.
//
// ## Solana — solana.SigningInput (SOL, SPL tokens)
//
//	Field                Source                              Provider
//	────────────────────────────────────────────────────────────────────
//	recent_blockhash     getLatestBlockhash → value.blockhash RecentBlockhashProvider
//	transfer / token_transfer fields   Caller knows          —
//
// The transaction fee on Solana is 5 000 lamports per signature and is deducted
// from the fee-payer's account automatically; it does not appear in SigningInput.
//
// ## Bitcoin-family — bitcoin.SigningInput (BTC, LTC, DOGE, BCH, ZEC, DASH, …)
//
//	Field                Source                              Provider
//	────────────────────────────────────────────────────────────────────
//	utxo (repeated)      Electrum / esplora / listunspent    UTXOProvider
//	  .out_point_hash    32-byte txid, internal byte order   UTXOProvider
//	  .out_point_index   vout                                UTXOProvider
//	  .amount            Value in satoshis                   UTXOProvider
//	  .script            scriptPubKey of the UTXO            UTXOProvider
//	byte_fee             estimatesmartfee / fee API (sat/vb) FeeOracle
//	to_address           Caller knows                        —
//	change_address       Caller knows (typically from wallet) Local
//	amount               Caller knows                        —
//	use_max_amount       Caller decision (send-all)          —
//
// # Broadcasting
//
// SignTransaction returns a signed SigningOutput. The library never submits to
// the network. Pass SigningOutput.Encoded (binary) to [Broadcaster.Broadcast],
// or use SigningOutput.EncodedHex / TxBytes for chain endpoints that expect hex
// or base64.
//
// # Security model
//
// The mnemonic and derived seed are sealed in memguard enclaves — encrypted in
// RAM, page-locked against swap, automatically wiped on [HDWallet.Destroy]. The
// derived private key is materialised once per signing call inside the package
// and wiped on return; it is never returned to the caller. All signing inputs
// and outputs are plain structs with no secret material.
package hdwallet
