package tumbler

import (
	"context"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// RecoveryCodeLen is the byte length of a recovery code (256 bits of entropy).
const RecoveryCodeLen = 32

// recoveryEncoding is unpadded, uppercase RFC 4648 base32 — no ambiguous
// padding, case-insensitive on entry, and friendly to print on paper.
var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding) //nolint:gochecknoglobals // immutable codec

// ErrInvalidRecoveryCode is returned by ParseRecoveryCode for input that does
// not decode to exactly RecoveryCodeLen bytes.
var ErrInvalidRecoveryCode = fmt.Errorf("tumbler: invalid recovery code")

// RecoveryCodeMethod wraps the data key under a KEK derived directly from a
// high-entropy recovery code (no password KDF — the code is already uniform).
// It is an additive escape hatch: enroll it via Envelope.AddSlot under any
// policy so a lost password or YubiKey cannot cause permanent lockout.
type RecoveryCodeMethod struct {
	code  *securebytes.SecureBytes
	label []byte
}

// NewRecoveryMethod builds a recovery method around a live code (as returned
// by GenerateRecoveryCode or ParseRecoveryCode). The method borrows the code;
// the caller retains ownership and must Destroy it.
func NewRecoveryMethod(code *securebytes.SecureBytes, opts ...Option) *RecoveryCodeMethod {
	o := applyOptions("recovery-code", opts)
	return &RecoveryCodeMethod{code: code, label: o.label}
}

// Type implements Method.
func (m *RecoveryCodeMethod) Type() MethodType { return MethodRecovery }

// Enroll implements Method.
func (m *RecoveryCodeMethod) Enroll(ctx context.Context, dek *securebytes.SecureBytes) (Slot, error) {
	if err := ctx.Err(); err != nil {
		return Slot{}, err
	}
	if m.code.Len() != RecoveryCodeLen {
		return Slot{}, fmt.Errorf("%w: code must be %d bytes", ErrInvalidRecoveryCode, RecoveryCodeLen)
	}
	return wrapDEK(dek, ikmInputs{recovery: m.code}, slotShape{
		mt:    MethodRecovery,
		kdfID: KDFNone,
		label: m.label,
	})
}

// Unlock implements Method.
func (m *RecoveryCodeMethod) Unlock(ctx context.Context, slot Slot) (*securebytes.SecureBytes, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return unwrapDEK(slot, ikmInputs{recovery: m.code})
}

// GenerateRecoveryCode returns a fresh 256-bit recovery code in a SecureBytes
// the caller owns and must Destroy. Display it exactly once (see
// FormatRecoveryCode) and never persist it.
func GenerateRecoveryCode() (*securebytes.SecureBytes, error) {
	raw, err := randBytes(RecoveryCodeLen)
	if err != nil {
		return nil, err
	}
	defer zero(raw)
	code, err := sbNew(raw) // New copies raw then zeroes it.
	if err != nil {
		return nil, fmt.Errorf("tumbler: recovery code: %w", err)
	}
	return code, nil
}

// FormatRecoveryCode renders a code as grouped base32 for one-time display,
// e.g. "ABCD-EFGH-IJKL-...". The result is an ordinary Go string (it must be
// shown to a human and cannot be zeroed); treat it as sensitive and do not
// log or persist it.
func FormatRecoveryCode(code *securebytes.SecureBytes) (string, error) {
	var out string
	if err := code.Use(func(b []byte) {
		out = groupString(recoveryEncoding.EncodeToString(b), 4)
	}); err != nil {
		return "", fmt.Errorf("tumbler: format recovery code: %w", err)
	}
	return out, nil
}

// ParseRecoveryCode decodes a user-entered recovery code (any casing, with or
// without grouping separators) back into a SecureBytes the caller owns and
// must Destroy.
func ParseRecoveryCode(s string) (*securebytes.SecureBytes, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r
		case r >= 'a' && r <= 'z':
			return r - ('a' - 'A')
		case r >= '0' && r <= '9':
			return r
		default:
			return -1 // drop separators / whitespace
		}
	}, s)

	raw, err := recoveryEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRecoveryCode, err)
	}
	defer zero(raw)
	if len(raw) != RecoveryCodeLen {
		return nil, fmt.Errorf("%w: decoded %d bytes", ErrInvalidRecoveryCode, len(raw))
	}
	code, err := sbNew(raw)
	if err != nil {
		return nil, fmt.Errorf("tumbler: recovery code: %w", err)
	}
	return code, nil
}

// groupString inserts a hyphen every n characters for readability.
func groupString(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/n)
	for i, r := range s {
		if i > 0 && i%n == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}
