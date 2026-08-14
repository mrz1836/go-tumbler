package tumbler_test

import (
	"context"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSafety_SingleSlotYubiKeyOnly_HardUnsafe(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := transport.NewFakeTransport(2, ykSecret)
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	require.NoError(t, err)

	// Without force: hard-unsafe.
	_, err = env.ValidateSafety(false)
	assert.ErrorIs(t, err, tumbler.ErrPolicyUnsafe)

	// With force: allowed, but warnings surface.
	rep, err := env.ValidateSafety(true)
	require.NoError(t, err)
	assert.NotEmpty(t, rep.Warnings)
	assert.Equal(t, 1, rep.UnlockSlots)
	assert.False(t, rep.HasRecovery)
}

func TestValidateSafety_PasswordOnly_WarnsNoBackupNoRecovery(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	rep, err := env.ValidateSafety(false)
	require.NoError(t, err)
	assert.Equal(t, 1, rep.UnlockSlots)
	assert.False(t, rep.HasRecovery)
	// Expect both the "single unlock method" and "no recovery" advisories.
	assert.GreaterOrEqual(t, len(rep.Warnings), 2)
}

func TestValidateSafety_TwoFactorWithRecovery_Clean(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := transport.NewFakeTransport(2, ykSecret)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordAndYubiKey,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw))
	require.NoError(t, err)

	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code)))

	rep, err := env.ValidateSafety(false)
	require.NoError(t, err)
	assert.Equal(t, 2, rep.UnlockSlots)
	assert.True(t, rep.HasRecovery)
	assert.Empty(t, rep.Warnings, "2FA + recovery should be clean")
}
