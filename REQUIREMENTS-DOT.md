# Requirements: Polkadot (DOT) support

Driven by crypto-gateway adding DOT (native) plus USDT/USDC on Polkadot Asset Hub
to its supported coins. Gateway and merchant-api are wired to consume `DOT` the
moment it's registered here — no crypto-gateway code changes needed once this
ships (see `chainMap["DOT"] = hdw.Chain("DOT")` in
`gateway/internal/adapters/hdwallet/coin_map.go`, already in place as a string
cast that doesn't require this constant to exist yet).

## Tier 1 — address derivation + validation (blocks gateway + merchant-api)

This already existed in this repo and was removed 6 days ago in `a4b0838`
("feat!: drop 36 unsupported chains (derivation-only)"), cascaded from the
never-used `Sr25519` curve cleanup. It's a revert-and-adapt job, not new
design. Everything below is recovered verbatim from `a4b0838~1`.

- **Registry row** (`registry.go`), keyed under the existing `Ed25519` curve —
  no new `Curve` value needed:
  ```go
  DOT Chain = "DOT"
  ...
  "DOT": {"Polkadot", "DOT", Ed25519, "m/44'/354'/0'/0'/0'", ss58Encoder(0), 10, 0},
  ```
  (Type was `Symbol` at removal time, renamed to `Chain` in `db4a637` since —
  use `Chain` in the new code.)

- **Encoder** (`encoders_ed25519.go`), recovered from `git show a4b0838~1:encoders_ed25519.go`:
  ```go
  func ss58Encoder(prefix byte) func([]byte) (string, error) {
      return func(pub []byte) (string, error) {
          data := make([]byte, 0, 1+32+2)
          data = append(data, prefix)
          data = append(data, pub...)
          checksum := blake2b512(append([]byte("SS58PRE"), data...))
          data = append(data, checksum[0], checksum[1])
          return base58Encode(base58BTC, data), nil
      }
  }
  ```
  `blake2b512` was a thin wrapper the old code had — reimplement it as
  `blake2bPersonal(64, nil, data)` (current signature in `blake2b_personal.go:94`)
  instead of pulling in `golang.org/x/crypto/blake2b`; the personalization-less
  path is already proven equivalent by that file's own test. Zero new
  dependencies either way.

- **Validator** (`address_validate.go`), recovered from `git show a4b0838~1:address_validate.go:473-489`
  — exact reverse of the encoder (length 35, prefix byte match, checksum
  match). Wire it the same way the current `validators[chain] = ...` `init()`
  entries work.

- **Derivation**: nothing new — `DOT` rides the existing `Ed25519`/SLIP-0010
  path (`slip10.go:29-48`, `deriveEd25519`), already proven against the
  official SLIP-0010 vectors. No new derivation code, no new derivation test.

- **Test vector** (`encoders_test.go`), recovered value, a real TWC
  `CoinAddressDerivationTests` vector for the fixed dummy key (`0x46...46`):
  ```go
  "DOT": "16PpFrXrC6Ko3pYcyMAx6gPMp3mFFaxgyYMt4G5brkgNcSz8",
  ```

- **Docs**: remove `DOT` from the "36 deliberately unsupported" list in the 4
  places it's currently enumerated (all prose, no enforcement code):
  `registry.go:173`, `README.md:464`, `CLAUDE.md:92`, `llms.txt:9`.

- **Tokens need nothing extra here.** USDT/USDC on Polkadot Asset Hub are
  pallet-assets balances on the *same* SS58 account as native DOT (Asset Hub
  is account-based, like Ethereum — one address, multiple asset balances by
  numeric ID: USDT = 1984, USDC = 1337). crypto-gateway's own coin registry
  points both at `Chain: "DOT"`, the same way `USDT_ERC20`/`USDC_ERC20`
  already point at `Chain: "ETH"`. This tier is address-only; asset IDs never
  reach this library.

**Not in scope for Tier 1, worth a conscious decision:** this reuses `Ed25519`,
not `Sr25519` (polkadot.js's default account scheme). That's what DOT used in
this library before, it's what the recovered TWC vector above is pinned to,
and it needs no new dependency. Real mainnet Polkadot accounts are commonly
sr25519, but ed25519 accounts are equally valid — pick this up only if
ecosystem-tooling parity (e.g. addresses matching what polkadot.js/Talisman
generate by default) turns out to matter later. If so: `sr25519.go` from
`2dc03e7` is a full, working schnorrkel implementation (go-schnorrkel +
merlin transcript, `"substrate"` context label) that was graded below the
authoritative-vector bar ("round-trip verified, no fixed vector" — see
`CLAUDE.md:105`) and never wired to a chain. Reviving it needs a real
signing/derivation vector to clear that bar, not just round-trip
self-consistency.

## Tier 2 — transaction signing (blocks treasury; not needed yet — treasury
is PRD-only in crypto-gateway right now, no code exists to consume this)

No precedent in this repo at all — this is genuinely new, unlike Tier 1.

- **SCALE codec + extrinsic builder**: nothing like this exists yet. Closest
  shape to copy is Solana's compact-u16 message compiler
  (`tx_solana_msg.go:54-136`) or Aptos's BCS encoder (`tx_aptos.go:12-35`) —
  both hand-rolled in this repo from scratch, never an imported SDK. Same
  expectation for SCALE.
- **Calls needed**: `Balances.transfer_keep_alive` (native DOT payouts/sweeps)
  and `Assets.transfer_keep_alive` (USDT/USDC payouts/sweeps, asset ID
  1984/1337 as call args).
- **Signature wrapping**: Substrate's `MultiSignature` enum — 1-byte
  discriminant (`Ed25519`/`Sr25519`/`Ecdsa`) + signature bytes. Discriminant
  follows whatever Tier 1 picked.
- **New provider need**: none of the 5 existing provider interfaces
  (`NonceProvider`/`UTXOProvider`/`FeeOracle`/`RecentBlockhashProvider`/
  `Broadcaster` in `providers.go`) cover what a mortal Substrate extrinsic
  needs from the caller: `spec_version`, `transaction_version`, `genesis_hash`,
  and a mortality checkpoint block hash. This is a 6th provider shape, honoring
  the same "no network I/O in this library" rule everything else follows.
- **Test vector**: check Trust Wallet Core's own `AnySigner`/Polkadot signing
  tests first — TWC does support Polkadot transaction signing, so an
  authoritative vector may already exist without needing a bespoke oracle. If
  it doesn't cover what's needed, stand up `_oracle_substrate/` as its own
  excluded Go module (mirrors `_oracle/` for go-ethereum,
  `_oracle_cosmos/` for cosmos-sdk — see `CLAUDE.md:74`), importing
  `centrifuge/go-substrate-rpc-client` purely to generate pinned vectors
  offline; it never enters this library's real dependency graph.

**Open question for whoever consumes this (treasury), not this library's to
resolve:** Substrate's weight-based, natively-denominated fee model plus
existential-deposit account reaping don't map 1:1 onto other chains' fee
mechanics. `pallet_asset_tx_payment` may let a transaction pay its own fee
directly in USDT/USDC rather than requiring a native-DOT top-up — if so,
treasury's existing ERC-20/TRC-20-style two-phase "gas funding" pattern may
not be needed at all for Polkadot token sweeps. Flagging so it isn't silently
assumed the two-phase pattern is required.
