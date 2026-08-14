package tumbler_test

import (
	"context"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise the defensive error branches that only fire when a
// SecureBytes input has already been destroyed, plus a few crafted-slot edge
// cases — the paths normal round-trips cannot reach.

func TestSeal_DestroyedKEK(t *testing.T) {
	kek := newSecret(t, make32(0x01))
	require.NoError(t, kek.Destroy())
	dek := newSecret(t, []byte("payload"))
	_, err := tumbler.SealForTest(kek, dek, make([]byte, 12), nil)
	require.Error(t, err)
}

func TestSeal_DestroyedDEK(t *testing.T) {
	kek := newSecret(t, make32(0x01))
	dek := newSecret(t, []byte("payload"))
	require.NoError(t, dek.Destroy())
	_, err := tumbler.SealForTest(kek, dek, make([]byte, 12), nil)
	require.Error(t, err)
}

func TestOpen_DestroyedKEK(t *testing.T) {
	kek := newSecret(t, make32(0x02))
	dek := newSecret(t, []byte("payload"))
	ct, err := tumbler.SealForTest(kek, dek, make([]byte, 12), nil)
	require.NoError(t, err)
	require.NoError(t, kek.Destroy())
	_, err = tumbler.OpenForTest(kek, make([]byte, 12), ct, nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, tumbler.ErrAuthFailed) // a use error, not auth failure
}

func TestKDFDerive_DestroyedPassword(t *testing.T) {
	pw := newSecret(t, []byte("pw"))
	require.NoError(t, pw.Destroy())
	_, err := cheapScrypt().Derive(pw, make([]byte, 16))
	require.Error(t, err)
	_, err = cheapArgon().Derive(pw, make([]byte, 16))
	require.Error(t, err)
}

func TestBuildIKM_DestroyedRole(t *testing.T) {
	yr := newSecret(t, []byte("response"))
	require.NoError(t, yr.Destroy())
	_, err := tumbler.BuildIKMForTest(nil, yr, nil)
	require.Error(t, err)
}

func TestDeriveKEK_DestroyedPassword(t *testing.T) {
	pk := newSecret(t, make32(0x03))
	require.NoError(t, pk.Destroy())
	_, err := tumbler.DeriveKEKForTest(pk, nil, nil, make([]byte, 16), 1, tumbler.MethodPassword, [8]byte{})
	require.Error(t, err)
}

func TestPasswordEnroll_DestroyedPassword(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	require.NoError(t, pw.Destroy())
	_, err := tumbler.NewPasswordMethod(cheapScrypt(), pw).Enroll(context.Background(), dek)
	require.Error(t, err)
}

func TestPasswordUnlock_DestroyedPassword(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	dead := newSecret(t, []byte("pw"))
	require.NoError(t, dead.Destroy())
	_, err = env.Unlock(ctx, tumbler.NewPasswordMethod(cheapScrypt(), dead))
	require.Error(t, err)
}

func TestFormatRecoveryCode_Destroyed(t *testing.T) {
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	require.NoError(t, code.Destroy())
	_, err = tumbler.FormatRecoveryCode(code)
	require.Error(t, err)
}

func TestAddSlot_BadDEKSize(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	// AddSlot with an oversized DEK is rejected before enrollment.
	big := newSecret(t, make([]byte, 241))
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	err = env.AddSlot(ctx, big, tumbler.NewRecoveryMethod(code))
	assert.ErrorIs(t, err, tumbler.ErrDEKSize)
}

func TestEffectivePolicy_MixedPrimary_Invalid(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	// Craft a mismatched second primary slot directly (a password + a yubikey
	// primary in one envelope) -> EffectivePolicy is PolicyInvalid.
	slots := env.SlotsForTest()
	yk := slots[0]
	yk.Type = tumbler.MethodYubiKey
	yk.KDFID = tumbler.KDFNone
	yk.KDFParams = nil
	env.SetSlotsForTest([]tumbler.Slot{slots[0], yk})
	assert.Equal(t, tumbler.PolicyInvalid, env.EffectivePolicy())
}

func TestRecoveryUnlock_ContextCancelled(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code)))

	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = tumbler.NewRecoveryMethod(code).Unlock(cctx, env.SlotsForTest()[1])
	assert.ErrorIs(t, err, context.Canceled)
}

func TestPasswordUnlock_MissingKDFInSlot(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	slots := env.SlotsForTest()
	slots[0].KDFID = tumbler.KDFNone
	slots[0].KDFParams = nil
	env.SetSlotsForTest(slots)
	_, err = env.Unlock(ctx, tumbler.NewPasswordMethod(cheapScrypt(), pw))
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func Test2FAUnlock_MissingKDFInSlot(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := newFake()
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordAndYubiKey,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw))
	require.NoError(t, err)

	slots := env.SlotsForTest()
	slots[0].KDFID = tumbler.KDFNone
	slots[0].KDFParams = nil
	env.SetSlotsForTest(slots)
	_, err = env.Unlock(ctx, tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw))
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestYubiKeyUnlock_InvalidStoredSlot(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := newFake()
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	require.NoError(t, err)

	slots := env.SlotsForTest()
	slots[0].YKSlot = 5 // invalid OTP slot
	env.SetSlotsForTest(slots)
	_, err = env.Unlock(ctx, tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}
