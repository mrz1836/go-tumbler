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
- **Challenge in argv.** The `ykman` challenge is passed as a command argument.
  For yubikey-only it is non-secret. For 2FA it is derived from the password key
  and therefore secret; passing it in argv is a **defense-in-depth-degraded but
  safe** exposure, because (a) the response alone is useless without the
  password key, which is *also* mixed directly into the KEK, and (b) the
  captured `(challenge, response)` pair cannot be replayed to derive the KEK.
  Mitigation: restrict `/proc` visibility (`hidepid=2`), or use the v2 PIV path
  (PIN over stdin).
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

For a genuinely strong passwordless mode, a **PIV** method (`yubico-piv-tool`,
slot `9d`, **PIN + touch**, non-extractable key in the secure element) drops in
behind the same `Method` / `Transport` / wire-format machinery with no format
break (`transport.PIVDecipher`, stubbed in `transport/piv.go`). **FIDO2
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
- **Fuzzing**: `FuzzParseEnvelope` (never panics; parse→marshal idempotent) and
  `FuzzEnrollUnlockRoundTrip`.
- **KATs** pin KEK derivation and (at hardware time) `ykman` output parsing.
- **Golden** `testdata/` envelope proves wire-format back-compat.
- Fault injection covers mlock/rand/transport failure paths.
- `securebytes` at 100% statement coverage; `-race` clean.

## Hardware-verification checklist (before hardware release)

The pure-software path and the FakeTransport are fully tested. Against real
hardware and the pinned `ykman` version, still verify and capture as a KAT:

- exact `ykman otp calculate` flags and output shape (this build assumes
  `otp calculate <slot> <hex-challenge>` → 40 lowercase hex chars);
- touch and touch-timeout behavior;
- the documented `ykchalresp -2 -x <hex>` fallback transport.
