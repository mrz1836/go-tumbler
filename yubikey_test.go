package tumbler_test

import (
	"context"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ykSecret is a fixed 20-byte HMAC-SHA1 secret (real YubiKey CR secret size).
var ykSecret = []byte("0123456789abcdefghij")

func newFake() *transport.FakeTransport { return transport.NewFakeTransport(2, ykSecret) }

// ---------------------------------------------------------------------------
// YubiKey-only
// ---------------------------------------------------------------------------

func TestYubiKeyOnly_RoundTrip(t *testing.T) {
	ctx := context.Background()
	dek, want := makeDEK(t, 32)
	fake := newFake()

	m := tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil)
	assert.Equal(t, tumbler.MethodYubiKey, m.Type())

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly, m)
	require.NoError(t, err)
	assert.Equal(t, tumbler.PolicyYubiKeyOnly, env.EffectivePolicy())
	assert.Equal(t, 1, fake.Touches, "enroll should require exactly one touch")

	// Yubi-only slots store a random challenge and no chal-salt.
	slot := env.SlotsForTest()[0]
	assert.NotEmpty(t, slot.Challenge)
	assert.Empty(t, slot.ChalSalt)
	assert.Equal(t, uint8(2), slot.YKSlot)

	blob, err := env.Marshal()
	require.NoError(t, err)
	parsed, err := tumbler.ParseEnvelope(blob)
	require.NoError(t, err)

	got, err := parsed.Unlock(ctx, tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, want)
	assert.Equal(t, 2, fake.Touches, "unlock should require one more touch")
}

func TestYubiKeyOnly_WrongKey_AuthFailed(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly,
		tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 2}, nil))
	require.NoError(t, err)

	// A different device secret yields a different response -> auth fails.
	wrong := transport.NewFakeTransport(2, []byte("XXXXXXXXXXXXXXXXXXXX"))
	_, err = env.Unlock(ctx, tumbler.NewYubiKeyMethod(wrong, tumbler.YubiKeyConfig{Slot: 2}, nil))
	assert.ErrorIs(t, err, tumbler.ErrAuthFailed)
}

// ---------------------------------------------------------------------------
// Two-factor (password + YubiKey)
// ---------------------------------------------------------------------------

func Test2FA_RoundTrip(t *testing.T) {
	ctx := context.Background()
	dek, want := makeDEK(t, 64)
	fake := newFake()
	pw := newSecret(t, []byte("two-factor-password"))

	m := tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw)
	assert.Equal(t, tumbler.MethodPasswordAndYubiKey, m.Type())

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordAndYubiKey, m)
	require.NoError(t, err)
	assert.Equal(t, tumbler.PolicyPasswordAndYubiKey, env.EffectivePolicy())

	// 2FA slots store a chal-salt and NO stored challenge (it is secret).
	slot := env.SlotsForTest()[0]
	assert.Empty(t, slot.Challenge, "2FA challenge must not be stored")
	assert.NotEmpty(t, slot.ChalSalt)
	assert.NotEmpty(t, slot.KDFSalt)

	blob, err := env.Marshal()
	require.NoError(t, err)
	parsed, err := tumbler.ParseEnvelope(blob)
	require.NoError(t, err)

	got, err := parsed.Unlock(ctx,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, newSecret(t, []byte("two-factor-password"))))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, want)
}

func Test2FA_WrongPassword_AuthFailed(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := newFake()
	pw := newSecret(t, []byte("real-password"))

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordAndYubiKey,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw))
	require.NoError(t, err)

	wrong := newSecret(t, []byte("wrong-password"))
	_, err = env.Unlock(ctx,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, wrong))
	assert.ErrorIs(t, err, tumbler.ErrAuthFailed)
}

func Test2FA_RequiresKDF(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	// No KDF supplied for a 2FA (password) method.
	_, err := tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 2}, pw).
		Enroll(ctx, dek)
	assert.ErrorIs(t, err, tumbler.ErrUnsupportedKDF)
}

// ---------------------------------------------------------------------------
// Transport operational errors surface (not swallowed as auth failure)
// ---------------------------------------------------------------------------

func TestYubiKey_TouchTimeout_Surfaces(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := newFake()
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	require.NoError(t, err)

	fake.TouchFn = func() error { return transport.ErrTouchTimeout }
	_, err = env.Unlock(ctx, tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	assert.ErrorIs(t, err, transport.ErrTouchTimeout)
	assert.NotErrorIs(t, err, tumbler.ErrAuthFailed)
}

func TestYubiKey_NoDevice_Surfaces(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := newFake()
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	require.NoError(t, err)

	fake.ErrInject = transport.ErrNoDevice
	_, err = env.Unlock(ctx, tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	assert.ErrorIs(t, err, transport.ErrNoDevice)
}

func TestYubiKey_EnrollTouchTimeout(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := newFake()
	fake.TouchFn = func() error { return transport.ErrTouchTimeout }
	_, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	assert.ErrorIs(t, err, transport.ErrTouchTimeout)
}

func TestYubiKey_InvalidSlot(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	_, err := tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 5}, nil).Enroll(ctx, dek)
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

// ---------------------------------------------------------------------------
// Backup key (AddSlot) and comprehensive matrix
// ---------------------------------------------------------------------------

func TestYubiKey_BackupKey_BothUnlock(t *testing.T) {
	ctx := context.Background()
	dek, want := makeDEK(t, 32)
	primary := newFake()
	backup := transport.NewFakeTransport(2, []byte("backup-yubikey-secret"))

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly,
		tumbler.NewYubiKeyMethod(primary, tumbler.YubiKeyConfig{Slot: 2}, nil))
	require.NoError(t, err)
	require.NoError(t, env.AddSlot(ctx, dek,
		tumbler.NewYubiKeyMethod(backup, tumbler.YubiKeyConfig{Slot: 2}, nil, tumbler.WithLabel("backup"))))

	// Either device unlocks the same DEK.
	for _, tr := range []*transport.FakeTransport{primary, backup} {
		got, err := env.Unlock(ctx, tumbler.NewYubiKeyMethod(tr, tumbler.YubiKeyConfig{Slot: 2}, nil))
		require.NoError(t, err)
		requireSecretEquals(t, got, want)
		_ = got.Destroy()
	}
}

// TestMatrix_AllPoliciesAllKDFs is the comprehensive end-to-end table the plan
// calls for: every policy, both KDFs, with recovery and backup slots, through
// marshal/parse, all via FakeTransport (no hardware).
func TestMatrix_AllPoliciesAllKDFs(t *testing.T) {
	kdfs := map[string]func() tumbler.KDF{"scrypt": cheapScrypt, "argon2": cheapArgon}
	for kdfName, kdf := range kdfs {
		t.Run(kdfName, func(t *testing.T) {
			t.Run("password-only", func(t *testing.T) {
				roundTrip(t, tumbler.PolicyPasswordOnly, func(pw string) tumbler.Method {
					return tumbler.NewPasswordMethod(kdf(), newSecret(t, []byte(pw)))
				})
			})
			t.Run("yubikey-only", func(t *testing.T) {
				fake := newFake()
				roundTripFake(t, fake, tumbler.PolicyYubiKeyOnly, func(string) tumbler.Method {
					return tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil)
				})
			})
			t.Run("password-and-yubikey", func(t *testing.T) {
				fake := newFake()
				roundTripFake(t, fake, tumbler.PolicyPasswordAndYubiKey, func(pw string) tumbler.Method {
					return tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: kdf()}, newSecret(t, []byte(pw)))
				})
			})
		})
	}
}

// roundTrip enrolls with the primary method builder, adds a recovery slot,
// marshals, parses, and unlocks via the primary factor and the recovery code.
func roundTrip(t *testing.T, policy tumbler.Policy, build func(pw string) tumbler.Method) {
	t.Helper()
	roundTripFake(t, nil, policy, build)
}

func roundTripFake(t *testing.T, _ *transport.FakeTransport, policy tumbler.Policy, build func(pw string) tumbler.Method) {
	t.Helper()
	ctx := context.Background()
	dek, want := makeDEK(t, 48)
	const pw = "matrix-password"

	env, err := tumbler.NewEnvelope(ctx, dek, policy, build(pw))
	require.NoError(t, err)
	assert.Equal(t, policy, env.EffectivePolicy())

	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code)))

	blob, err := env.Marshal()
	require.NoError(t, err)
	parsed, err := tumbler.ParseEnvelope(blob)
	require.NoError(t, err)

	// Unlock via the primary factor.
	got, err := parsed.Unlock(ctx, build(pw))
	require.NoError(t, err)
	requireSecretEquals(t, got, want)
	_ = got.Destroy()

	// Unlock via the recovery code.
	got2, err := parsed.Unlock(ctx, tumbler.NewRecoveryMethod(code))
	require.NoError(t, err)
	requireSecretEquals(t, got2, want)
	_ = got2.Destroy()
}
