<div align="center">

# 🔐&nbsp;&nbsp;go-tumbler

**Envelope encryption with independent keyslots for Go — unlock one payload with a password, a YubiKey, both (2FA), or a recovery code, and add or remove methods without ever re-encrypting the payload.**

<br/>

<a href="https://github.com/mrz1836/go-tumbler/releases"><img src="https://img.shields.io/github/release-pre/mrz1836/go-tumbler?include_prereleases&style=flat-square&logo=github&color=black" alt="Release"></a>
<a href="https://golang.org/"><img src="https://img.shields.io/github/go-mod/go-version/mrz1836/go-tumbler?style=flat-square&logo=go&color=00ADD8" alt="Go Version"></a>
<a href="https://pkg.go.dev/github.com/mrz1836/go-tumbler"><img src="https://pkg.go.dev/badge/github.com/mrz1836/go-tumbler.svg" alt="Go Reference"></a>
<a href="https://github.com/mrz1836/go-tumbler/blob/master/LICENSE"><img src="https://img.shields.io/github/license/mrz1836/go-tumbler?style=flat-square&color=blue&v=1" alt="License"></a>

<br/>

<table align="center" border="0">
  <tr>
    <td align="right">
       <code>CI / CD</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://github.com/mrz1836/go-tumbler/actions"><img src="https://img.shields.io/github/actions/workflow/status/mrz1836/go-tumbler/fortress.yml?branch=master&label=build&logo=github&style=flat-square" alt="Build"></a>
       <a href="https://github.com/mrz1836/go-tumbler/actions"><img src="https://img.shields.io/github/last-commit/mrz1836/go-tumbler?style=flat-square&logo=git&logoColor=white&label=last%20update" alt="Last Commit"></a>
    </td>
    <td align="right">
       &nbsp;&nbsp;&nbsp;&nbsp; <code>Quality</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://codecov.io/gh/mrz1836/go-tumbler"><img src="https://codecov.io/gh/mrz1836/go-tumbler/branch/master/graph/badge.svg?style=flat-square" alt="Coverage"></a>
    </td>
  </tr>

  <tr>
    <td align="right">
       <code>Security</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://scorecard.dev/viewer/?uri=github.com/mrz1836/go-tumbler"><img src="https://api.scorecard.dev/projects/github.com/mrz1836/go-tumbler/badge?style=flat-square" alt="Scorecard"></a>
       <a href="SECURITY.md"><img src="https://img.shields.io/badge/policy-active-success?style=flat-square&logo=security&logoColor=white" alt="Security"></a>
    </td>
    <td align="right">
       &nbsp;&nbsp;&nbsp;&nbsp; <code>Community</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://github.com/mrz1836/go-tumbler/graphs/contributors"><img src="https://img.shields.io/github/contributors/mrz1836/go-tumbler?style=flat-square&color=orange" alt="Contributors"></a>
       <a href="https://mrz1818.com/"><img src="https://img.shields.io/badge/donate-bitcoin-ff9900?style=flat-square&logo=bitcoin" alt="Bitcoin"></a>
    </td>
  </tr>
</table>

</div>

<br/>

Named for a lock's **tumbler** — the mechanism whose pins must align before it turns. A random **data key (DEK)** encrypts your payload once; each enrolled unlock method wraps the DEK in its own independent **keyslot**. Any one slot yields the DEK, and adding or removing a method touches only that slot — the [LUKS](https://gitlab.com/cryptsetup/cryptsetup) / [`systemd-cryptenroll`](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html) model, in a small, auditable, pure-Go core.

> **Status: `v0.x` — the on-disk format is unstable until an external cryptographic review.** Not yet recommended for production outside its originating projects. See [SECURITY.md](SECURITY.md).

<br/>

<div align="center">

### <code>Project Navigation</code>

</div>

<table align="center">
  <tr>
    <td align="center" width="33%">
       🚀&nbsp;<a href="#-installation"><code>Installation</code></a>
    </td>
    <td align="center" width="33%">
       ⚡&nbsp;<a href="#-quick-start"><code>Quick&nbsp;Start</code></a>
    </td>
    <td align="center" width="33%">
       🧩&nbsp;<a href="#-how-it-works"><code>How&nbsp;It&nbsp;Works</code></a>
    </td>
  </tr>
  <tr>
    <td align="center">
       🔑&nbsp;<a href="#-policies"><code>Policies</code></a>
    </td>
    <td align="center">
      📦&nbsp;<a href="#-packages"><code>Packages</code></a>
    </td>
    <td align="center">
      📚&nbsp;<a href="#-documentation"><code>Documentation</code></a>
    </td>
  </tr>
  <tr>
    <td align="center">
       🔐&nbsp;<a href="#-security"><code>Security</code></a>
    </td>
    <td align="center">
      🧪&nbsp;<a href="#-examples--tests"><code>Examples&nbsp;&&nbsp;Tests</code></a>
    </td>
    <td align="center">
      🛠️&nbsp;<a href="#-code-standards"><code>Code&nbsp;Standards</code></a>
    </td>
  </tr>
  <tr>
    <td align="center">
       🤖&nbsp;<a href="#-ai-usage--assistant-guidelines"><code>AI&nbsp;Usage</code></a>
    </td>
    <td align="center">
       🤝&nbsp;<a href="#-contributing"><code>Contributing</code></a>
    </td>
    <td align="center">
       ⚖️&nbsp;<a href="#-license"><code>License</code></a>
    </td>
  </tr>
</table>

<br/>

## 🚀 Installation

**go-tumbler** requires a [supported release of Go](https://golang.org/doc/devel/release.html#policy) (1.26+). Add it to your module with a single command:

```bash
go get github.com/mrz1836/go-tumbler
```

Then import the packages you need:

```go
import (
    tumbler "github.com/mrz1836/go-tumbler"
    "github.com/mrz1836/go-tumbler/securebytes"
    "github.com/mrz1836/go-tumbler/transport"
)
```

The module compiles under `CGO_ENABLED=0` to every supported target and adds **no third-party cryptographic or hardware dependency** — it is built entirely on the Go standard library and [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) (the Go team's own packages). Raw YubiKey I/O is delegated to Yubico's official [`ykman`](https://developers.yubico.com/yubikey-manager/) CLI through a fixed-argv, never-a-shell transport.

<br/>

## ⚡ Quick Start

Get up and running with these essential flows.

<br>

### Password-only enrollment

```go
ctx := context.Background()

// A fresh random data key (or pass your app's existing seed as the DEK).
dek, _ := tumbler.GenerateDEK(32)
defer dek.Destroy()

pw, _ := securebytes.New([]byte("correct horse battery staple"))
defer pw.Destroy()

env, _ := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
    tumbler.NewPasswordMethod(tumbler.NewScryptKDF(18, 8, 1), pw))

// Persist the self-describing envelope anywhere (file, DB, sidecar).
blob, _ := env.Marshal()
```

```go
// Later: parse and unlock.
parsed, _ := tumbler.ParseEnvelope(blob)

pw2, _ := securebytes.New([]byte("correct horse battery staple"))
defer pw2.Destroy()

key, err := parsed.Unlock(ctx, tumbler.NewPasswordMethod(tumbler.NewScryptKDF(18, 8, 1), pw2))
// key is the recovered DEK; err collapses to a uniform ErrAuthFailed on ANY failure.
defer key.Destroy()
```

<br>

### Two-factor (password + YubiKey)

True 2FA: the challenge is secret and derived from the password key, and the password key is also mixed directly into the key-encryption key — so **both factors are mandatory**.

```go
tr, _ := transport.NewYkmanTransport("ykman") // fixed-argv; never a shell

m := tumbler.NewYubiKeyMethod(
    tr,
    tumbler.YubiKeyConfig{Slot: 2, KDF: tumbler.NewArgon2idKDF(4, 256*1024, 4)},
    passphrase, // *securebytes.SecureBytes
)
env, _ := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordAndYubiKey, m)
```

<br>

### Add a recovery code (escape hatch)

Recovery slots are additive under any policy — the lockout insurance for a lost key.

```go
code, _ := tumbler.GenerateRecoveryCode()
defer code.Destroy()

_ = env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code))

printed, _ := tumbler.FormatRecoveryCode(code) // display ONCE, never persist
```

<br>

### Add or remove methods — O(1), no re-encryption

Enrolling a backup key or revoking a slot rewraps (or drops) a single keyslot. The payload and its sibling slots are never touched.

```go
// Enroll a backup YubiKey — one extra slot.
_ = env.AddSlot(ctx, dek, backupMethod)

// Inspect the enrolled slots (non-secret metadata only).
for _, info := range env.SlotInfos() {
    fmt.Printf("%x  %s  %s\n", info.ID, info.Type, info.Label)
}

// Revoke a slot by ID (refuses to remove the last slot, or the last
// primary slot — swap a primary with add-before-remove).
_ = env.RemoveSlot(slotID)

// Enforce the real posture — recomputed from authenticated slot types,
// never the advisory header byte.
policy := env.EffectivePolicy()

// Safe-default validator: advisory warnings + a fatal error for dangerous shapes.
report, err := env.ValidateSafety(false)
```

<br>

### Hardware-free testing

`transport.FakeTransport` is a deterministic in-memory HMAC-SHA1 backend with touch, presence, and error injection, so the full enroll → unlock → tamper path is exercised **without a physical key** — `-race` clean, no CGO.

```go
fake := transport.NewFakeTransport(2, []byte("device-hmac-secret-20"))
m := tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil)
// enroll + unlock exactly as production, deterministically.
```

<br/>

> 📖 **Full API reference on [pkg.go.dev →](https://pkg.go.dev/github.com/mrz1836/go-tumbler)**

<br/>

## 🧩 How It Works

A single random **data key (DEK)** seals the payload once. Every enrolled unlock method wraps that DEK in its own **keyslot**; any one slot recovers the DEK, and add/remove touches only that slot — never the payload or its siblings.

```text
                         ┌──────────────── envelope (self-describing blob) ────────────────┐
   password ─▶ KDF ─┐    │  "TMBL" magic │ version │ advisory policy hint │ [ keyslots… ]  │
                    ├─▶  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐     │
   YubiKey  ─▶ CR  ─┤    │  │ slot: pw  │  │ slot: 2FA │  │ slot: key │  │ slot: rec │ ··· │
                    │    │  │ wraps DEK │  │ wraps DEK │  │ wraps DEK │  │ wraps DEK │     │
   recovery ────────┘    │  └───────────┘  └───────────┘  └───────────┘  └───────────┘     │
                         └─────────────────────────────────────────────────────────────────┘
                                     any one slot ─▶ DEK ─▶ decrypt payload
```

**Per-slot key derivation.** Each slot derives a single-use key-encryption key (KEK) with **HKDF-SHA256** — `PRK = Extract(perSlotSalt, IKM)`, `KEK = Expand(PRK, version‖type‖slotID)` — where `IKM` is a **length-prefixed, role-tagged** combination of the present factors (password key, YubiKey response, recovery code).

**Tamper-evident sealing.** The DEK is sealed with **ChaCha20-Poly1305** (pure-Go, constant-time on every target) and the slot's own metadata is bound in as **associated data**. Mutating any slot parameter breaks that slot's tag and surfaces as a uniform `ErrAuthFailed` — **downgrade-evident by construction**.

**Self-describing, bounded wire format.** Envelopes serialize to a versioned binary form (`"TMBL"` magic + version + advisory policy hint + length-prefixed keyslots). `ParseEnvelope` performs only structural and bounds checks; enforcement always uses `EffectivePolicy()` (recomputed from the authenticated slot types), **never** the advisory header byte.

**Pluggable, self-authenticating KDFs.** Choose **Argon2id** or **scrypt** per method; cost parameters are stored in — and authenticated by — each slot, so files describe exactly how to open themselves.

**Secrets never leak.** Every data key, key-encryption key, derived password key, YubiKey response, and recovery code lives in a [`securebytes.SecureBytes`](securebytes/) for its whole lifetime (mlock where supported, zero-on-destroy, redacted rendering, borrow-only access) and is `Destroy`-ed the moment it is no longer needed.

For the full threat model, the presence-vs-identity limit of the challenge-response path, and the v2 PIV (PIN + touch) upgrade seam, see [SECURITY.md](SECURITY.md).

<br/>

### Key Features

- 🔑 **Independent keyslots** — one DEK, many wrapping methods; the LUKS / `systemd-cryptenroll` model.
- 🧩 **O(1) enroll & revoke** — add a backup key or drop a slot without re-encrypting the payload.
- 🔐 **Password · YubiKey · 2FA · Recovery** — mix factors per envelope; recovery codes are additive under any policy.
- 🛡️ **Downgrade-evident AEAD** — ChaCha20-Poly1305 with slot metadata bound as associated data; tampering collapses to a uniform `ErrAuthFailed`.
- 🧮 **Pluggable KDF** — Argon2id or scrypt, cost parameters authenticated inside each slot.
- 🧠 **`securebytes` everywhere** — mlocked, zero-on-destroy, borrow-only secret containers; no secret ever becomes a Go `string`.
- 🪶 **Pure-Go, `CGO_ENABLED=0`** — zero new crypto/hardware deps beyond `golang.org/x/crypto`; cross-compiles everywhere.
- 🔌 **Fixed-argv `ykman` transport** — never a shell; plus a `FakeTransport` for deterministic, hardware-free tests.
- 🧭 **Safe-default validator** — `ValidateSafety` flags lockout-prone shapes (single-factor yubikey-only, no backup/recovery).
- 📐 **Versioned, bounded, self-describing format** — strict parsing; enforcement always via `EffectivePolicy`.

<br/>

## 🔑 Policies

| Policy | Factors | Notes |
|--------|---------|-------|
| `PolicyPasswordOnly` | password | Argon2id- or scrypt-hardened. |
| `PolicyPasswordAndYubiKey` | password **and** YubiKey | True 2FA; the secret challenge is derived from the password key, which is also mixed into the KEK. |
| `PolicyYubiKeyOnly` | YubiKey | Presence, **not identity** — the CR path has no PIN (see [SECURITY.md](SECURITY.md)); the safe-default validator requires a backup or recovery slot. |

Recovery slots (`MethodRecovery`) are **additive** under any policy. Enforcement always uses `EffectivePolicy()` — recomputed from the authenticated slot types — never the advisory header byte.

<br/>

## 📦 Packages

| Package | Import | Responsibility |
|---------|--------|----------------|
| `tumbler` | [`github.com/mrz1836/go-tumbler`](https://pkg.go.dev/github.com/mrz1836/go-tumbler) | Envelope, unlock methods, KDFs, policy, and the wire format. |
| `securebytes` | [`github.com/mrz1836/go-tumbler/securebytes`](https://pkg.go.dev/github.com/mrz1836/go-tumbler/securebytes) | The mlocked, redacted, borrow-only secret container used for every secret. |
| `transport` | [`github.com/mrz1836/go-tumbler/transport`](https://pkg.go.dev/github.com/mrz1836/go-tumbler/transport) | The `Transport` interface, the `ykman` backend, `FakeTransport`, and the v2 PIV seam. |

<br/>

## 📚 Documentation

| Resource | Description |
|----------|-------------|
| **[pkg.go.dev](https://pkg.go.dev/github.com/mrz1836/go-tumbler)** | Complete, generated API reference for every package. |
| **[SECURITY.md](SECURITY.md)** | Threat model, cryptographic primitives, honest limits, and the v2 PIV upgrade seam. |
| **[doc.go](doc.go)** | The package-level overview rendered at the top of the Go reference. |

<br/>

> **Heads up!** go-tumbler is built for a small, auditable surface. Every cryptographic operation uses battle-tested, first-party packages:
> - **`crypto/hkdf` + `crypto/sha256`** (Go standard library) for key combination and derivation
> - **`golang.org/x/crypto/chacha20poly1305`** for AEAD sealing
> - **`golang.org/x/crypto/argon2`, `.../scrypt`** for password hardening
> - **`crypto/hmac` + `crypto/sha1`** for the YubiKey challenge-response contract (see [SECURITY.md](SECURITY.md#why-hmac-sha1-is-safe-here))

<br/>

## 🔐 Security

### Important Disclaimer

> ⚠️ **Experimental Software — Use at Your Own Risk**
>
> go-tumbler is experimental, open-source software provided "AS-IS" without warranty. By using go-tumbler, you acknowledge:
>
> - **The on-disk format is unstable** until an external cryptographic review; it may change without a compatibility shim during `v0.x`.
> - **You control your keys:** go-tumbler never transmits secrets. A lost factor with no backup or recovery slot means the payload is unrecoverable — by design.
> - **Presence is not identity:** the YubiKey challenge-response path proves possession, not identity (no PIN). Prefer `password-and-yubikey`.
> - **No formal audit:** this software has not yet undergone professional cryptographic auditing.
>
> **Do not protect data you cannot afford to lose without an enrolled backup or recovery slot.**

For the full threat model, defended-vs-undefended matrix, and reporting instructions, see the [Security Policy](SECURITY.md).

<br/>

### Additional Documentation & Repository Management

<details>
<summary><strong><code>Development Setup (Getting Started)</code></strong></summary>
<br/>

Install the [MAGE-X](https://github.com/mrz1836/go-mage) build tool for development:

```bash
# Install MAGE-X for development and building
go install github.com/magefile/mage@latest
go install github.com/mrz1836/go-mage/magex@latest
magex update:install
```
</details>

<details>
<summary><strong><code>Build Commands</code></strong></summary>
<br/>

View all build commands:

```bash script
magex help
```

Common commands:
- `magex test` — Run the test suite
- `magex test:race` — Run the test suite with the race detector
- `magex lint` — Run all linters (golangci-lint against this repo's profile)
- `magex bench` — Run benchmarks
- `magex deps:update` — Update dependencies

</details>

<details>
<summary><strong><code>GitHub Workflows</code></strong></summary>
<br/>

go-tumbler uses the **Fortress** workflow system for comprehensive CI/CD:

- **fortress-test-suite.yml** — Complete test suite across multiple Go versions
- **fortress-code-quality.yml** — Code quality checks (gofmt, golangci-lint, staticcheck)
- **fortress-security-scans.yml** — Security vulnerability scanning (govulncheck, gitleaks)
- **fortress-test-fuzz.yml** — Fuzz targets over the envelope parser, enroll/unlock round-trip, recovery-code and KDF-parameter parsing, and the transport response/version parsers
- **fortress-coverage.yml** — Code coverage reporting to Codecov
- **fortress-release.yml** — Automated releases via GoReleaser

See all workflows in [`.github/workflows/`](.github/workflows/).

</details>

<details>
<summary><strong><code>Updating Dependencies</code></strong></summary>
<br/>

To update all dependencies (Go modules, linters, and related tools), run:

```bash
magex deps:update
```

This brings all dependencies up to date in a single step, including Go modules and any managed tools. It is the recommended way to keep your development environment and CI in sync.

</details>

<br/>

## 🧪 Examples & Tests

All unit tests run via [GitHub Actions](https://github.com/mrz1836/go-tumbler/actions) using the workflows in [`.github/workflows/`](.github/workflows/). Every YubiKey path is exercised **without hardware** via `transport.FakeTransport`, so the full enroll/unlock/tamper surface is `-race` clean and CGO-free.

Run all tests (fast):

```bash script
magex test
```

Run all tests with the race detector (slower):

```bash script
magex test:race
```

### Test Coverage

View the coverage report:

```bash script
magex test:coverage
```

Coverage is automatically uploaded to [Codecov](https://codecov.io/gh/mrz1836/go-tumbler) on every commit. The suite includes table/property tests, tamper and fault-injection paths, adversarial-finding regressions, a checked-in golden wire-format fixture, and fuzz targets over `ParseEnvelope`, recovery-code / KDF-parameter parsing, and the transport response/version parsers. Statement coverage sits at **100%** (`securebytes`), **~98%** (core), and **~99%** (`transport`).

<br/>

## 🛠️ Code Standards

Read more about this Go project's [code standards](.github/CODE_STANDARDS.md). In short: **pure-Go, `CGO_ENABLED=0`**, no new dependencies beyond `golang.org/x/crypto` and `golang.org/x/sys`; every secret in `securebytes` end-to-end; constant-time comparisons; slot metadata bound as AEAD associated data; and hardware-free tests for every path via `transport.FakeTransport`.

<br/>

## 🤖 AI Usage & Assistant Guidelines

Read the [AI Usage & Assistant Guidelines](.github/AGENTS.md) for details on how AI is used in this project and how to interact with AI assistants.

<br/>

## 👥 Maintainers

| [<img src="https://github.com/mrz1836.png" height="50" alt="MrZ" />](https://github.com/mrz1836) |
|:------------------------------------------------------------------------------------------------:|
|                                [MrZ](https://github.com/mrz1836)                                 |

<br/>

## 🤝 Contributing

View the [contributing guidelines](.github/CONTRIBUTING.md) and please follow the [code of conduct](.github/CODE_OF_CONDUCT.md).

### How can I help?

All kinds of contributions are welcome :raised_hands:!
The most basic way to show your support is to star :star2: the project, or to raise issues :speech_balloon:.
You can also support this project by [becoming a sponsor on GitHub](https://github.com/sponsors/mrz1836) :clap:
or by making a [**bitcoin donation**](https://mrz1818.com/?tab=tips&utm_source=github&utm_medium=sponsor-link&utm_campaign=go-tumbler&utm_term=go-tumbler&utm_content=go-tumbler) to ensure this journey continues indefinitely! :rocket:

[![Stars](https://img.shields.io/github/stars/mrz1836/go-tumbler?label=Please%20like%20us&style=social)](https://github.com/mrz1836/go-tumbler/stargazers)

<br/>

## 📝 License

[![License](https://img.shields.io/github/license/mrz1836/go-tumbler.svg?style=flat&v=1)](LICENSE)
