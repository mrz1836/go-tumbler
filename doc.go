// Package tumbler implements envelope encryption with independent keyslots:
// a single random data key (DEK) wraps a payload, and each enrolled unlock
// method wraps the DEK in its own keyslot. Any one keyslot yields the DEK;
// adding or removing a method touches only that slot, never the payload or
// its siblings — the LUKS / systemd-cryptenroll model.
//
// It is named for a lock's tumbler, the mechanism whose pins must align for
// the lock to open; each keyslot holds one wrapped key.
//
// # Unlock methods
//
//   - PasswordMethod       — KDF(password) only.
//   - YubiKeyMethod        — YubiKey HMAC-SHA1 challenge-response, alone
//     (touch-gated, presence not identity) or as true two-factor with a
//     password (secret challenge derived from the password key, which is
//     also mixed directly into the KEK).
//   - RecoveryCodeMethod   — a 256-bit printed code, an additive escape hatch.
//
// # Cryptography
//
// Each slot derives a single-use key-encryption key with HKDF-SHA256 —
// PRK = Extract(perSlotSalt, IKM); KEK = Expand(PRK, version||type||slotID) —
// where IKM is a length-prefixed, role-tagged combination of the present
// factors (password key, YubiKey response, recovery code). The DEK is sealed
// with ChaCha20-Poly1305 (pure-Go, constant-time on every target) and the
// slot's own metadata is bound in as associated data, so tampering with any
// slot parameter breaks that slot's tag and surfaces as a uniform
// ErrAuthFailed — downgrade-evident by construction.
//
// # Wire format
//
// Envelopes serialize to a versioned, self-describing, strictly-bounded
// binary form ("TMBL" magic + version + advisory policy hint + length-
// prefixed keyslots). ParseEnvelope performs only structural and bounds
// checks; enforcement of policy uses EffectivePolicy (recomputed from the
// authenticated slot types), never the advisory header byte.
//
// # Secret handling
//
// Every data key, key-encryption key, derived password key, YubiKey response,
// and recovery code lives in a securebytes.SecureBytes for its whole lifetime
// and is Destroy-ed as soon as it is no longer needed. The module adds no
// third-party cryptographic or hardware dependency: it is built entirely on
// the Go standard library and golang.org/x/crypto (the Go team's own
// packages), and delegates raw YubiKey I/O to Yubico's official ykman CLI via
// a small, fixed-argv transport. It compiles under CGO_ENABLED=0 to every
// supported target.
//
// See SECURITY.md for the threat model, the presence-vs-identity limit of the
// challenge-response path, and the v2 PIV upgrade seam.
package tumbler
