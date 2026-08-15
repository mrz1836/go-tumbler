# Security Model — go-tumbler

`go-tumbler` guards high-value secrets (wallet seeds, secret-manager master
keys). This document states what it defends, what it does **not**, and the
cryptographic reasoning behind the design. The on-disk format is **unstable
until an external cryptographic review**; the module ships as `v0.x`.

## Reporting

Report vulnerabilities privately to the maintainer (see the repository owner).
Do not open public issues for security reports until a fix is released.

## Design in one paragraph

A random **data key (DEK)** encrypts the payload once. Each enrolled unlock
method wraps the DEK in its own **keyslot**. Any one keyslot yields the DEK;
adding or removing a method never re-encrypts the payload or touches sibling
slots (the LUKS / `systemd-cryptenroll` model). Every keyslot derives a
single-use **key-encryption key (KEK)** with HKDF-SHA256 over a length-prefixed,
role-tagged combination of the present factors, and seals the DEK with
ChaCha20-Poly1305, binding the slot's own metadata in as associated data.

## Cryptographic primitives

| Purpose | Primitive | Source |
| --- | --- | --- |
| Password stretch | Argon2id (RFC 9106) / scrypt (RFC 7914) | `golang.org/x/crypto` |
| Key combination | HKDF-SHA256 | `crypto/hkdf` (stdlib) |
| Authenticated encryption | ChaCha20-Poly1305 | `golang.org/x/crypto` |
| YubiKey factor | HMAC-SHA1 challenge-response | Yubico `ykman` CLI |
| Randomness | `crypto/rand` | stdlib |

No third-party Go cryptographic or hardware dependency is introduced. The
module compiles under `CGO_ENABLED=0` to every supported target.

### Why HMAC-SHA1 is safe here

The YubiKey challenge-response uses HMAC-SHA1. HMAC's security rests on the
PRF/MAC properties of the compression function, **not** on collision
resistance, so SHA-1's collision weakness does not apply (NIST SP 800-131A
continues to permit HMAC-SHA1). The 20-byte response is never used directly as
a key; it is HKDF-SHA256 input keying material that expands to a full 256-bit
KEK.

### Why ChaCha20-Poly1305 (not AES-GCM)

ChaCha20-Poly1305 is constant-time in pure Go on every target. Pure-Go AES-GCM
is **not** constant-time without AES-NI, which would leak on some platforms
under `CGO_ENABLED=0`. An `AEADID` byte in the format reserves room for AES-GCM
later without a format break.

## What is defended

- **Offline theft of the sealed file.** Without the enrolled factor(s) the DEK
  cannot be recovered. Password slots are Argon2id/scrypt-hardened.
- **Tampering / downgrade.** Each slot's full metadata (type, KDF id and cost,
  stored challenge, salts, nonce) is AEAD associated data. Editing any of it —
  e.g. flipping a 2FA slot down to yubikey-only, swapping the stored challenge,
  lowering the KDF cost — breaks that slot's tag and surfaces as a uniform
  `ErrAuthFailed`. The advisory policy byte in the header is **never** trusted;
  enforcement uses `EffectivePolicy()`, recomputed from authenticated slot types.
- **Oracle leakage.** Every unlock failure collapses to a single `ErrAuthFailed`
  with no detail about which check failed. Secret comparisons happen only inside
  the AEAD `Open` (constant-time tag check).
- **Resource-exhaustion via a tampered file.** KDF parameters are bounds-checked
  before any derivation (memory ceiling 2 GiB); all wire fields are length-bounded.
- **Nonce reuse.** Each slot has a fresh 12-byte nonce and a single-use HKDF
  salt, so KEKs are unique by construction.
- **Secrets in memory.** Every DEK, KEK, password key, YubiKey response, and
  recovery code lives in `securebytes` (mlock where supported, zero-on-destroy,
  redacted rendering) and is destroyed as soon as it is no longer needed.

## What is NOT defended (honest limits)

- **Challenge-response proves presence, not identity.** The HMAC-SHA1 path has
  **no PIN**: a touch proves someone is physically present, not *who*. In
  **YubiKey-only** mode, a **stolen key + stolen file = unlock**. This is
  acceptable for the convenience tier and fine for password-only/2FA modes, but
  the safe-default validator refuses single-slot yubikey-only without `--force`.
  The genuinely strong passwordless mode is the **v2 PIV seam** below.
- **Challenge in argv (2FA is an offline password oracle).** The `ykman`
  challenge is passed as a command-line argument, readable via `ps` /
  `/proc/<pid>/cmdline` / `auditd` while the process runs — and `auditd`/EDR may
  **persist** it beyond the process. For **yubikey-only** the challenge is a
  stored non-secret. For **2FA** the challenge is `HKDF(KDF(password))`: an
  attacker who **both** holds the stolen envelope **and** observes this argv
  gains an **offline password verifier** — they can recompute the challenge from
  the slot's salts + KDF params and confirm password guesses without the device.
  This defeats the "challenge is not stored" offline-resistance property. It does
  **not** by itself reveal the DEK: the live YubiKey response is still required,
  and the password key is *also* mixed directly into the KEK, so a captured
  `(challenge, response)` pair cannot be replayed to derive the KEK. Reaching it
  needs the stolen file **and** argv observation, and yields only offline
  *password* guessing. Mitigation: restrict `/proc` visibility (`hidepid=2`) and
  argv auditing; the real fix is the **v2 PIV path** (PIN over a pipe, no argv —
  see below).
- **Root-level memory forensics.** `mlock` pins pages against swap but the Go
  runtime may transiently copy heap objects during GC; a determined root
  attacker doing live memory forensics is out of scope (as it is for the parent
  projects).
- **Revocation of a possibly-compromised key.** `RemoveSlot` protects only the
  *current* file. True revocation requires **DEK rotation**: unlock → generate a
  new DEK → re-enroll the trusted methods → re-seal → delete old copies.
- **Compromised host at unlock time.** If the machine is compromised while you
  unlock, the recovered DEK is exposed. Nothing in-process prevents this.

## Two-factor (password + YubiKey) construction

For a 2FA slot the challenge is **secret and derived from the password key**
(`HKDF(pk) → challenge`, not stored on disk), and `pk` is **also mixed directly
into the KEK**. Consequences:

- A captured `(challenge, response)` pair is useless without the password.
- The YubiKey response alone is useless without the password.
- Compromise of *either* factor alone yields nothing.

## v2 upgrade seam — PIV (PIN + touch)

> **Future milestone — NOT implemented in v1.** `transport/piv.go` carries a
> compile-only stub (`transport.PIVDecipher`); there is no PIV unlock yet.

For a genuinely strong passwordless mode, a **PIV** method (YubiKey PIV slot
`9d`, **PIN + touch**, non-extractable **RSA-2048** key in the secure element)
would add a factor that proves *identity* (the PIN), not just presence. The
mechanism, grounded in what the CLIs can actually do:

- **Unlock (decrypt):** `openssl pkeyutl -decrypt` driven by **`pkcs11-provider`**,
  or **`pkcs11-tool`** (OpenSC / ykcs11). The PIN is passed **off argv AND off
  env** via `pin-source=file:/dev/fd/N` over an anonymous pipe — never in
  `cmdline` or `environ`. **`yubico-piv-tool` cannot perform the unlock:** its
  `test-decipher` is a self-test that generates its own data and prints only a
  pass/fail line, so it cannot decrypt caller ciphertext.
- **Enroll:** `yubico-piv-tool` is the right tool for key generation, attestation
  (`-a attest`, OID `1.3.6.1.4.1.41482.3.8`, proving non-extractability and
  `--pin-policy always --touch-policy always`), and reading the public key; the
  enroll-side OAEP encrypt is pure-Go `crypto/rsa`. Its PIN goes over the hidden
  `--stdin-input`, not argv.

This is **not** a drop-in behind the v1 wire format: a 256-byte RSA-OAEP
ciphertext exceeds the current `maxChallengeLen` (64), so it needs a **new
AAD-bound KEM-ciphertext slot field + algorithm id**, a new `MethodPIV`, and an
**append-only, version-gated** 4th IKM role (so existing golden envelopes keep
verifying). It also adds a heavier runtime dependency (OpenSC / `pkcs11-provider`
+ openssl) than the ykman-only posture — a deliberate tradeoff. **FIDO2
hmac-secret** is the theoretical best but is blocked today (needs CGO and a
community Go wrapper); revisit if Yubico ships an official Go binding.

## Recovery & lockout (the #1 operational risk)

Lockout is more likely than compromise. Mitigations, in order of preference:

1. Enroll a **backup YubiKey** (`AddSlot`).
2. Enroll a **256-bit printed recovery code** (shown once, never persisted).
3. App-level ultimate fallbacks: sigil's BIP39 mnemonic (`wallet restore`);
   hush's pre-migration vault snapshot.

The safe-default validator (`ValidateSafety`) warns on `< 2` unlock slots and
on a missing recovery code, and recommends `PasswordAndYubiKey` + recovery code
+ backup key.

## Testing posture

- Exhaustive **single-byte-flip** property test: no tamper of a valid envelope
  can ever unlock to a *different* DEK.
- **Fuzzing**: `FuzzParseEnvelope` (never panics; parse→marshal idempotent),
  `FuzzEnrollUnlockRoundTrip`, `FuzzParseRecoveryCode`, `FuzzParseKDFParams`, and
  the transport `FuzzDecodeResponse` / `FuzzParseYkmanVersion`.
- **Audit-finding regressions** pin the known limits: the 2FA challenge reaching
  `ykman` argv, `RemoveSlot` refusing to strip the last primary slot, the
  recovery-only `PolicyInvalid`-but-unlockable shape, and over-ceiling KDF
  parameters rejected at parse.
- **KATs** pin KEK derivation and (at hardware time) `ykman` output parsing.
- **Golden** `testdata/` envelope proves wire-format back-compat.
- Fault injection covers mlock/rand/transport failure paths.
- Statement coverage: `securebytes` 100%, core ~98%, transport ~99%; `-race`
  clean. The ~2% of core left uncovered is enumerated, genuinely-unreachable
  defensive branches (e.g. stdlib HKDF / `chacha20poly1305.New` cannot error on
  valid inputs) — see `coverage_notes_test.go`.

## Hardware-verification checklist (before hardware release)

The pure-software path and the FakeTransport are fully tested. Against real
hardware and the pinned `ykman` version, still verify and capture as a KAT:

- exact `ykman otp calculate` flags and output shape (this build assumes
  `otp calculate <slot> <hex-challenge>` → 40 lowercase hex chars);
- touch and touch-timeout behavior (the runner sets `cmd.WaitDelay` and the
  construction-time `--version` probe is bounded by `context.WithTimeout`).

The transport shells out **only** to `ykman` (a fixed, non-shell argv); there is
no alternate/fallback CLI backend in this build.
