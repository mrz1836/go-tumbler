package tumbler

import (
	"context"
	"fmt"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// PasswordMethod wraps the data key under a KEK derived solely from
// KDF(password). It is the sole method for PolicyPasswordOnly and preserves
// each app's existing password cost via a pluggable KDF.
type PasswordMethod struct {
	kdf      KDF
	password *securebytes.SecureBytes
	label    []byte
}

// NewPasswordMethod builds a password method from a KDF and the live
// password. The method borrows the password for enroll/unlock; the caller
// retains ownership and must Destroy it. kdf is used at enroll to choose
// parameters; at unlock the parameters stored in the slot are used instead,
// so the file remains self-describing.
func NewPasswordMethod(kdf KDF, password *securebytes.SecureBytes, opts ...Option) *PasswordMethod {
	o := applyOptions("password", opts)
	return &PasswordMethod{kdf: kdf, password: password, label: o.label}
}

// Type implements Method.
func (m *PasswordMethod) Type() MethodType { return MethodPassword }

// Enroll implements Method.
func (m *PasswordMethod) Enroll(ctx context.Context, dek *securebytes.SecureBytes) (Slot, error) {
	if err := ctx.Err(); err != nil {
		return Slot{}, err
	}
	if m.kdf == nil {
		return Slot{}, fmt.Errorf("%w: password method requires a KDF", ErrUnsupportedKDF)
	}
	salt, err := randBytes(m.kdf.SaltLen())
	if err != nil {
		return Slot{}, err
	}
	pk, err := m.kdf.Derive(m.password, salt)
	if err != nil {
		return Slot{}, fmt.Errorf("tumbler: password derive: %w", err)
	}
	defer func() { _ = pk.Destroy() }()

	return wrapDEK(dek, ikmInputs{password: pk}, slotShape{
		mt:        MethodPassword,
		kdfID:     m.kdf.ID(),
		kdfParams: m.kdf.MarshalParams(),
		kdfSalt:   salt,
		label:     m.label,
	})
}

// Unlock implements Method.
func (m *PasswordMethod) Unlock(ctx context.Context, slot Slot) (*securebytes.SecureBytes, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	kdf, err := parseKDF(slot.KDFID, slot.KDFParams)
	if err != nil {
		return nil, err
	}
	if kdf == nil {
		// A password slot without a KDF is malformed (parse rejects this;
		// guard defensively for in-memory-constructed slots).
		return nil, fmt.Errorf("%w: password slot missing KDF", ErrMalformed)
	}
	pk, err := kdf.Derive(m.password, slot.KDFSalt)
	if err != nil {
		return nil, fmt.Errorf("tumbler: password derive: %w", err)
	}
	defer func() { _ = pk.Destroy() }()

	return unwrapDEK(slot, ikmInputs{password: pk})
}
