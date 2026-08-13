package tumbler

import (
	"errors"
	"fmt"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// FormatVersion is the current on-disk envelope format version. It is bound
// into every KEK derivation (as HKDF info) and written into the file header.
// Bumping it is a deliberate, breaking-format act; golden testdata pins the
// v1 layout for back-compat.
const FormatVersion uint8 = 1

// MethodType identifies the kind of unlock method a keyslot was enrolled
// with. It is written into each slot (and authenticated as AAD), and it is
// the value Envelope.Unlock matches a caller-supplied Method against.
type MethodType uint8

const (
	// MethodPassword is a keyslot unlocked by a password alone: the data key
	// is wrapped under a KEK derived from KDF(password) only.
	MethodPassword MethodType = 1

	// MethodYubiKey is a keyslot unlocked by a YubiKey alone (HMAC-SHA1
	// challenge-response, touch-gated, no PIN): the KEK is derived from the
	// 20-byte YubiKey response to a stored random challenge. Presence, not
	// identity — see SECURITY.md.
	MethodYubiKey MethodType = 2

	// MethodPasswordAndYubiKey is a true two-factor keyslot: the challenge
	// sent to the YubiKey is secret and derived from the password key, and
	// the password key is ALSO mixed directly into the KEK. Compromise of
	// either factor alone yields nothing.
	MethodPasswordAndYubiKey MethodType = 3

	// MethodRecovery is a keyslot unlocked by a high-entropy printed recovery
	// code (256-bit). No KDF is applied (kdfID=0); the code is uniform input
	// keying material fed straight to HKDF.
	MethodRecovery MethodType = 4
)

// String renders a MethodType for diagnostics (never secret).
func (t MethodType) String() string {
	switch t {
	case MethodPassword:
		return "password"
	case MethodYubiKey:
		return "yubikey"
	case MethodPasswordAndYubiKey:
		return "password+yubikey"
	case MethodRecovery:
		return "recovery"
	default:
		return fmt.Sprintf("method(%d)", uint8(t))
	}
}

// valid reports whether t is a known method type.
func (t MethodType) valid() bool {
	return t >= MethodPassword && t <= MethodRecovery
}

// Policy is the per-envelope security posture. It is stored in the header as
// an ADVISORY hint only; enforcement always uses Envelope.EffectivePolicy,
// which is recomputed from the authenticated slot types.
type Policy uint8

const (
	// PolicyInvalid is the zero value and the result of EffectivePolicy when
	// an envelope's primary slots disagree (only reachable via tampering or
	// misuse). Callers comparing against an expected policy will reject it.
	PolicyInvalid Policy = 0

	// PolicyPasswordOnly unlocks with a password.
	PolicyPasswordOnly Policy = 1

	// PolicyPasswordAndYubiKey unlocks with password AND YubiKey (2FA).
	PolicyPasswordAndYubiKey Policy = 2

	// PolicyYubiKeyOnly unlocks with a YubiKey alone (no password).
	PolicyYubiKeyOnly Policy = 3
)

// String renders a Policy for diagnostics and CLI flags.
func (p Policy) String() string {
	switch p {
	case PolicyPasswordOnly:
		return "password-only"
	case PolicyPasswordAndYubiKey:
		return "password-and-yubikey"
	case PolicyYubiKeyOnly:
		return "yubikey-only"
	default:
		return "invalid"
	}
}

// valid reports whether p is one of the three real policies.
func (p Policy) valid() bool {
	return p >= PolicyPasswordOnly && p <= PolicyYubiKeyOnly
}

// policyForMethod maps a primary (non-recovery) slot's method type to the
// policy it implies. Recovery slots do not participate in policy derivation.
func policyForMethod(t MethodType) Policy {
	switch t {
	case MethodPassword:
		return PolicyPasswordOnly
	case MethodYubiKey:
		return PolicyYubiKeyOnly
	case MethodPasswordAndYubiKey:
		return PolicyPasswordAndYubiKey
	default:
		return PolicyInvalid
	}
}

// AEADID selects the authenticated cipher used to wrap the data key in a
// slot. Only ChaCha20-Poly1305 is defined today; the byte leaves room for
// AES-GCM later without a format break.
type AEADID uint8

const (
	// AEADChaCha20Poly1305 is the only AEAD defined in v1. It is pure-Go and
	// constant-time on every target (unlike AES-GCM without AES-NI).
	AEADChaCha20Poly1305 AEADID = 1
)

// KDFID selects the password key-derivation function used by a slot. The ID
// plus its serialized parameters are stored in (and authenticated by) the
// slot, so the file is self-describing.
type KDFID uint8

const (
	// KDFNone means no password KDF is applied (recovery-code slots): the
	// input keying material is already uniform and high-entropy.
	KDFNone KDFID = 0

	// KDFArgon2id is Argon2id (RFC 9106), used by hush.
	KDFArgon2id KDFID = 1

	// KDFScrypt is scrypt (RFC 7914), used by sigil to preserve age's cost.
	KDFScrypt KDFID = 2
)

// Sentinel errors. Compare with errors.Is. Unlock failures deliberately
// collapse to a single ErrAuthFailed so no information about WHICH check
// failed (KDF, transport, AEAD tag) can leak to an attacker.
var (
	// ErrAuthFailed is the single, uniform failure returned by every unlock
	// path (wrong password, wrong/absent YubiKey, tampered slot, bad tag).
	ErrAuthFailed = errors.New("tumbler: authentication failed")

	// ErrBadMagic is returned by ParseEnvelope when the leading magic bytes
	// are not "TMBL".
	ErrBadMagic = errors.New("tumbler: bad magic")

	// ErrBadVersion is returned by ParseEnvelope for an unknown format version.
	ErrBadVersion = errors.New("tumbler: unsupported format version")

	// ErrShortData is returned when the input is too short to contain a
	// required field.
	ErrShortData = errors.New("tumbler: short data")

	// ErrMalformed is returned for structurally invalid (but non-truncated)
	// envelopes: bad field lengths, out-of-range enums, oversized fields.
	ErrMalformed = errors.New("tumbler: malformed envelope")

	// ErrSlotNotFound is returned by RemoveSlot when no slot has the given ID.
	ErrSlotNotFound = errors.New("tumbler: slot not found")

	// ErrNoMethods is returned by NewEnvelope/Unlock when no methods are given.
	ErrNoMethods = errors.New("tumbler: no methods supplied")

	// ErrDEKSize is returned when a data key is empty or exceeds the bound.
	ErrDEKSize = errors.New("tumbler: data key size out of range")

	// ErrKDFParams is returned when serialized KDF parameters are out of the
	// safe bounds enforced on parse (a defense against resource-exhaustion
	// via a tampered file).
	ErrKDFParams = errors.New("tumbler: kdf parameters out of range")

	// ErrUnsupportedKDF is returned for an unknown KDFID.
	ErrUnsupportedKDF = errors.New("tumbler: unsupported kdf")

	// ErrUnsupportedAEAD is returned for an unknown AEADID.
	ErrUnsupportedAEAD = errors.New("tumbler: unsupported aead")

	// ErrPolicyMismatch is returned when a caller's expected policy does not
	// match the envelope's EffectivePolicy.
	ErrPolicyMismatch = errors.New("tumbler: policy mismatch")

	// ErrPolicyUnsafe is returned by the safe-default validator for a
	// dangerous configuration (e.g. single-slot YubiKey-only without force).
	ErrPolicyUnsafe = errors.New("tumbler: unsafe policy")
)

// Data-key and field bounds. These bound parse-time allocations and reject
// absurd values from a tampered file before any expensive work.
const (
	// maxDEKLen bounds the data key / seed a slot may wrap. Real payloads are
	// 32–64 bytes; 240 leaves generous headroom while capping wrapped size.
	maxDEKLen = 240

	// wrappedOverhead is the AEAD tag length added to the DEK when wrapped.
	wrappedOverhead = 16
)

// GenerateDEK returns a fresh random data key of the given size, held in a
// SecureBytes the caller owns and must Destroy. size must be in [1, 240].
//
// Apps that already hold a seed (sigil's wallet seed, hush's master seed)
// pass that seed as the DEK to NewEnvelope instead of generating one here.
func GenerateDEK(size int) (*securebytes.SecureBytes, error) {
	if size <= 0 || size > maxDEKLen {
		return nil, fmt.Errorf("%w: %d not in [1,%d]", ErrDEKSize, size, maxDEKLen)
	}
	dek, err := sbNewZero(size)
	if err != nil {
		return nil, fmt.Errorf("tumbler: allocate dek: %w", err)
	}
	var readErr error
	if useErr := dek.Use(func(b []byte) {
		_, readErr = randRead(b)
	}); useErr != nil {
		_ = dek.Destroy()
		return nil, fmt.Errorf("tumbler: dek use: %w", useErr)
	}
	if readErr != nil {
		_ = dek.Destroy()
		return nil, fmt.Errorf("tumbler: rand dek: %w", readErr)
	}
	return dek, nil
}
