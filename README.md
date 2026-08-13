# go-tumbler

Envelope encryption with independent keyslots for Go — unlock one payload with
a **password**, a **YubiKey**, **both (2FA)**, or a **recovery code**, and add
or remove methods without ever re-encrypting the payload.

Named for a lock's **tumbler** (the mechanism whose pins must align); each
**keyslot** holds one wrapped key.

> **Status: `v0.x` — the on-disk format is unstable until an external
> cryptographic review.** Not yet recommended for production outside its
> originating projects. See [SECURITY.md](SECURITY.md).

## Why

A random **data key (DEK)** encrypts the payload once. Each enrolled unlock
method wraps the DEK in its own **keyslot**. Any one slot yields the DEK; adding
or removing a method touches only that slot — the LUKS / `systemd-cryptenroll`
model. This lets an app offer per-secret unlock policies (password-only,
password+YubiKey, YubiKey-only) with backup keys and recovery codes, all over
one small, auditable core.

## Design highlights

- **Pure-Go, `CGO_ENABLED=0`, zero new crypto/hardware deps.** Built on the Go
  standard library and `golang.org/x/crypto` (the Go team's own packages). Raw
  YubiKey I/O is delegated to Yubico's official `ykman` CLI via a fixed-argv,
  never-a-shell transport.
- **HKDF-SHA256** key combination over length-prefixed, role-tagged factors;
  **ChaCha20-Poly1305** (constant-time on every target) seals the DEK with the
  slot's own metadata bound in as associated data — so tampering is
  downgrade-evident and surfaces as a uniform `ErrAuthFailed`.
- **Pluggable KDF** per app: Argon2id or scrypt, cost parameters stored in and
  authenticated by each slot (self-describing files).
- **`securebytes`** everywhere: mlock (where supported), zero-on-destroy,
  redacted rendering, borrow-only access.

## Install

```
go get github.com/mrz1836/go-tumbler
```

Requires Go 1.25+.

## Quick start

```go
ctx := context.Background()

// A fresh data key (or pass your app's existing seed as the DEK).
dek, _ := tumbler.GenerateDEK(32)
defer dek.Destroy()

// Password-only enrollment.
pw, _ := securebytes.New([]byte("correct horse battery staple"))
defer pw.Destroy()
env, _ := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
    tumbler.NewPasswordMethod(tumbler.NewScryptKDF(18, 8, 1), pw))

// Persist.
blob, _ := env.Marshal()

// Later: parse and unlock.
parsed, _ := tumbler.ParseEnvelope(blob)
pw2, _ := securebytes.New([]byte("correct horse battery staple"))
defer pw2.Destroy()
key, err := parsed.Unlock(ctx, tumbler.NewPasswordMethod(tumbler.NewScryptKDF(18, 8, 1), pw2))
// key is the recovered DEK; err is a uniform ErrAuthFailed on any failure.
```

### Two-factor (password + YubiKey)

```go
m := tumbler.NewYubiKeyMethod(
    transport,                                   // NewYkmanTransport("ykman")
    tumbler.YubiKeyConfig{Slot: 2, KDF: tumbler.NewArgon2idKDF(4, 256*1024, 4)},
    passphrase,                                  // *securebytes.SecureBytes
)
env, _ := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordAndYubiKey, m)

// Add a printed recovery code as an escape hatch.
code, _ := tumbler.GenerateRecoveryCode()
_ = env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code))
printed, _ := tumbler.FormatRecoveryCode(code) // show once, never persist
```

### Hardware-free testing

`transport.FakeTransport` is a deterministic in-memory HMAC-SHA1 with touch,
presence, and error injection, so the full enroll/unlock path is tested without
a physical key.

## Policies

| Policy | Factors | Notes |
| --- | --- | --- |
| `PolicyPasswordOnly` | password | Argon2id/scrypt-hardened |
| `PolicyPasswordAndYubiKey` | password **and** YubiKey | true 2FA; secret challenge derived from the password key |
| `PolicyYubiKeyOnly` | YubiKey | presence not identity — see SECURITY.md; validator requires a backup/recovery slot |

Enforcement always uses `EffectivePolicy()` (recomputed from authenticated slot
types), never the advisory header byte.

## Packages

- `tumbler` — envelope, methods, KDFs, wire format.
- `tumbler/securebytes` — the mlocked, redacted, borrow-only secret container.
- `tumbler/transport` — `Transport` interface, `ykman` backend, `FakeTransport`,
  and the v2 PIV seam.

## License

[MIT](LICENSE).
