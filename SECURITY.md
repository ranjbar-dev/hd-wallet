# Security Policy

## Supported Versions

Only the latest release on the `v0.x` line receives security fixes. Please update to the most recent tagged version before reporting.

| Version | Supported |
|---------|-----------|
| latest `v0.x` | Yes |
| older `v0.x` | No |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Public disclosure before a fix is available puts every user at risk.

Please report vulnerabilities through **GitHub private security advisories**:

> [https://github.com/ranjbar-dev/hd-wallet/security/advisories/new](https://github.com/ranjbar-dev/hd-wallet/security/advisories/new)

Include as much detail as you can: a description of the issue, reproduction steps, the affected version(s), and any proof-of-concept code. The more context you provide, the faster a fix can be prepared.

**Response target:** acknowledgement within **72 hours**. A patch timeline will be communicated once the report has been triaged. We follow responsible-disclosure practices and will credit reporters in the release notes unless you prefer to remain anonymous.

---

## Scope

Issues in scope include, but are not limited to:

- Incorrect address derivation that could cause fund loss
- Mnemonic or seed material leaking outside a memguard enclave
- Memory-safety issues (data written to swap, appearing in core dumps, etc.)
- Dependency vulnerabilities with a direct security impact (the CI pipeline runs `govulncheck` and `gosec` on every push)

Out of scope: UI/UX suggestions, network compatibility requests, and general Go toolchain issues unrelated to this library.

---

## Security Model

**Secrets in RAM.** The mnemonic and derived seed are held exclusively in [memguard](https://github.com/awnumar/memguard) enclaves — encrypted at rest in RAM, pinned with `mlock`/`VirtualLock` against swap, guarded with canary pages, and automatically wiped when the enclave is destroyed. Private keys derived during an address computation are zeroed immediately after use; they are never stored.

**Caller responsibilities.**

- Prefer `FromMnemonicBuffer(*memguard.LockedBuffer)` or `FromMnemonicBytes([]byte)` over `FromMnemonic(string)`. A Go `string` is immutable and cannot be wiped — see the README's [Passing a mnemonic in securely](README.md#passing-a-mnemonic-in-securely) section for entry-point guidance.
- Use `WithMnemonic(func([]byte) error)` to read the mnemonic; do not let the byte slice escape the callback.
- Call `w.Destroy()` on every `*HDWallet` when it is no longer needed, and `defer memguard.Purge()` at program exit to wipe all remaining protected memory.

**Known limitation.** The underlying `tyler-smith/go-bip39` API accepts only `string`, so the library makes one short-lived `string` copy of the mnemonic for BIP-39 validation and seed derivation. This copy is GC-bounded and not wiped. Every durable copy of the mnemonic and seed is sealed in a memguard enclave.

**You are responsible for your own keys.** This library is provided "as is" without warranty of any kind. Always verify derived addresses against a reference wallet (e.g. Trust Wallet) before sending real funds. Start with small amounts.
