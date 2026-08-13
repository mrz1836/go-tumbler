package tumbler

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"github.com/mrz1836/go-tumbler/securebytes"
	"github.com/mrz1836/go-tumbler/transport"
)

// yubiChallengeLen is the fixed challenge length (bytes) tumbler uses for
// HMAC-SHA1 challenge-response. It is bound into FormatVersion: for yubi-only
// slots the random challenge of this length is stored; for 2FA slots a secret
// challenge of this length is derived from the password key and NOT stored.
const yubiChallengeLen = 32

// YubiKeyConfig configures a YubiKey method.
type YubiKeyConfig struct {
	// Slot is the YubiKey OTP slot programmed for HMAC-SHA1 (1 or 2).
	Slot uint8

	// KDF derives the password key for 2FA (MethodPasswordAndYubiKey). It is
	// required when a password is supplied to NewYubiKeyMethod and ignored for
	// yubi-only enrollment. As with PasswordMethod, unlock re-derives from the
	// slot's stored KDF parameters, so the file stays self-describing.
	KDF KDF
}

// YubiKeyMethod wraps the data key under a KEK that incorporates a YubiKey
// HMAC-SHA1 response. With no password it is yubi-only (MethodYubiKey,
// presence not identity); with a password it is true two-factor
// (MethodPasswordAndYubiKey): the challenge is secret and derived from the
// password key, which is also mixed directly into the KEK.
type YubiKeyMethod struct {
	transport transport.Transport
	cfg       YubiKeyConfig
	password  *securebytes.SecureBytes // nil => yubi-only; set => 2FA
	label     []byte
}

// NewYubiKeyMethod builds a YubiKey method. Pass password=nil for yubi-only,
// or a live password for two-factor (cfg.KDF then required). The method
// borrows the password; the caller retains ownership and must Destroy it.
func NewYubiKeyMethod(t transport.Transport, cfg YubiKeyConfig, password *securebytes.SecureBytes, opts ...Option) *YubiKeyMethod {
	label := "yubikey"
	if password != nil {
		label = "password+yubikey"
	}
	o := applyOptions(label, opts)
	return &YubiKeyMethod{transport: t, cfg: cfg, password: password, label: o.label}
}

// Type implements Method.
func (m *YubiKeyMethod) Type() MethodType {
	if m.password == nil {
		return MethodYubiKey
	}
	return MethodPasswordAndYubiKey
}

// Enroll implements Method.
func (m *YubiKeyMethod) Enroll(ctx context.Context, dek *securebytes.SecureBytes) (Slot, error) {
	if err := ctx.Err(); err != nil {
		return Slot{}, err
	}
	if !slotValid(m.cfg.Slot) {
		return Slot{}, fmt.Errorf("%w: yubikey otp slot %d", ErrMalformed, m.cfg.Slot)
	}
	if m.password == nil {
		return m.enrollYubiOnly(ctx, dek)
	}
	return m.enroll2FA(ctx, dek)
}

func (m *YubiKeyMethod) enrollYubiOnly(ctx context.Context, dek *securebytes.SecureBytes) (Slot, error) {
	challenge, err := randBytes(yubiChallengeLen)
	if err != nil {
		return Slot{}, err
	}
	yr, err := m.transport.ChallengeResponse(ctx, m.cfg.Slot, challenge)
	if err != nil {
		return Slot{}, err
	}
	defer func() { _ = yr.Destroy() }()

	return wrapDEK(dek, ikmInputs{yubiResp: yr}, slotShape{
		mt:        MethodYubiKey,
		kdfID:     KDFNone,
		ykSlot:    m.cfg.Slot,
		challenge: challenge, // stored: a non-secret random challenge
		label:     m.label,
	})
}

func (m *YubiKeyMethod) enroll2FA(ctx context.Context, dek *securebytes.SecureBytes) (Slot, error) {
	if m.cfg.KDF == nil {
		return Slot{}, fmt.Errorf("%w: 2FA yubikey method requires a KDF", ErrUnsupportedKDF)
	}
	kdfSalt, err := randBytes(m.cfg.KDF.SaltLen())
	if err != nil {
		return Slot{}, err
	}
	pk, err := m.cfg.KDF.Derive(m.password, kdfSalt)
	if err != nil {
		return Slot{}, fmt.Errorf("tumbler: 2fa derive: %w", err)
	}
	defer func() { _ = pk.Destroy() }()

	chalSalt, err := randBytes(defaultSaltLen)
	if err != nil {
		return Slot{}, err
	}
	challenge, err := deriveChallenge(pk, chalSalt)
	if err != nil {
		return Slot{}, err
	}
	defer zero(challenge)

	yr, err := m.transport.ChallengeResponse(ctx, m.cfg.Slot, challenge)
	if err != nil {
		return Slot{}, err
	}
	defer func() { _ = yr.Destroy() }()

	return wrapDEK(dek, ikmInputs{password: pk, yubiResp: yr}, slotShape{
		mt:        MethodPasswordAndYubiKey,
		kdfID:     m.cfg.KDF.ID(),
		kdfParams: m.cfg.KDF.MarshalParams(),
		kdfSalt:   kdfSalt,
		chalSalt:  chalSalt,
		ykSlot:    m.cfg.Slot,
		// challenge deliberately NOT stored for 2FA: it is secret, derived
		// from the password key at unlock time.
		label: m.label,
	})
}

// Unlock implements Method.
func (m *YubiKeyMethod) Unlock(ctx context.Context, slot Slot) (*securebytes.SecureBytes, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !slotValid(slot.YKSlot) {
		return nil, fmt.Errorf("%w: yubikey otp slot %d", ErrMalformed, slot.YKSlot)
	}
	if m.password == nil {
		return m.unlockYubiOnly(ctx, slot)
	}
	return m.unlock2FA(ctx, slot)
}

func (m *YubiKeyMethod) unlockYubiOnly(ctx context.Context, slot Slot) (*securebytes.SecureBytes, error) {
	yr, err := m.transport.ChallengeResponse(ctx, slot.YKSlot, slot.Challenge)
	if err != nil {
		return nil, err
	}
	defer func() { _ = yr.Destroy() }()
	return unwrapDEK(slot, ikmInputs{yubiResp: yr})
}

func (m *YubiKeyMethod) unlock2FA(ctx context.Context, slot Slot) (*securebytes.SecureBytes, error) {
	kdf, err := parseKDF(slot.KDFID, slot.KDFParams)
	if err != nil {
		return nil, err
	}
	if kdf == nil {
		return nil, fmt.Errorf("%w: 2fa slot missing KDF", ErrMalformed)
	}
	pk, err := kdf.Derive(m.password, slot.KDFSalt)
	if err != nil {
		return nil, fmt.Errorf("tumbler: 2fa derive: %w", err)
	}
	defer func() { _ = pk.Destroy() }()

	challenge, err := deriveChallenge(pk, slot.ChalSalt)
	if err != nil {
		return nil, err
	}
	defer zero(challenge)

	yr, err := m.transport.ChallengeResponse(ctx, slot.YKSlot, challenge)
	if err != nil {
		return nil, err
	}
	defer func() { _ = yr.Destroy() }()

	return unwrapDEK(slot, ikmInputs{password: pk, yubiResp: yr})
}

// deriveChallenge computes the secret 2FA challenge from the password key:
// HKDF-SHA256(pk, chalSalt, "tumbler/v1 challenge") -> yubiChallengeLen bytes.
// The result transits to the device but is never stored; it is zeroed by the
// caller after use.
func deriveChallenge(pk *securebytes.SecureBytes, chalSalt []byte) ([]byte, error) {
	var (
		out    []byte
		outErr error
	)
	if useErr := pk.Use(func(pkb []byte) {
		prk, e := hkdf.Extract(sha256.New, pkb, chalSalt)
		if e != nil {
			outErr = e
			return
		}
		defer zero(prk)
		out, outErr = hkdf.Expand(sha256.New, prk, labelChallenge, yubiChallengeLen)
	}); useErr != nil {
		return nil, fmt.Errorf("tumbler: derive challenge: %w", useErr)
	}
	if outErr != nil {
		return nil, fmt.Errorf("tumbler: derive challenge: %w", outErr)
	}
	return out, nil
}

// slotValid reports whether s is a valid YubiKey OTP slot (1 or 2).
func slotValid(s uint8) bool { return s == 1 || s == 2 }
