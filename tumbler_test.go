package tumbler_test

import (
	"errors"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateDEK_Valid(t *testing.T) {
	dek, err := tumbler.GenerateDEK(32)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dek.Destroy() })
	assert.Equal(t, 32, dek.Len())

	// Two DEKs must differ (overwhelmingly).
	a := copyOut(t, dek)
	dek2, err := tumbler.GenerateDEK(32)
	require.NoError(t, err)
	t.Cleanup(func() { _ = dek2.Destroy() })
	assert.NotEqual(t, a, copyOut(t, dek2))
}

func TestGenerateDEK_SizeBounds(t *testing.T) {
	_, err := tumbler.GenerateDEK(0)
	assert.ErrorIs(t, err, tumbler.ErrDEKSize)
	_, err = tumbler.GenerateDEK(-1)
	assert.ErrorIs(t, err, tumbler.ErrDEKSize)
	_, err = tumbler.GenerateDEK(241)
	assert.ErrorIs(t, err, tumbler.ErrDEKSize)
	// Boundaries.
	d1, err := tumbler.GenerateDEK(1)
	require.NoError(t, err)
	_ = d1.Destroy()
	d240, err := tumbler.GenerateDEK(240)
	require.NoError(t, err)
	_ = d240.Destroy()
}

func TestGenerateDEK_RandFailure(t *testing.T) {
	boom := errors.New("rng exhausted")
	restore := tumbler.SetRandRead(func([]byte) (int, error) { return 0, boom })
	defer restore()
	_, err := tumbler.GenerateDEK(32)
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

func TestMethodType_String(t *testing.T) {
	assert.Equal(t, "password", tumbler.MethodPassword.String())
	assert.Equal(t, "yubikey", tumbler.MethodYubiKey.String())
	assert.Equal(t, "password+yubikey", tumbler.MethodPasswordAndYubiKey.String())
	assert.Equal(t, "recovery", tumbler.MethodRecovery.String())
	assert.Contains(t, tumbler.MethodType(200).String(), "method(200)")
}

func TestPolicy_String(t *testing.T) {
	assert.Equal(t, "password-only", tumbler.PolicyPasswordOnly.String())
	assert.Equal(t, "password-and-yubikey", tumbler.PolicyPasswordAndYubiKey.String())
	assert.Equal(t, "yubikey-only", tumbler.PolicyYubiKeyOnly.String())
	assert.Equal(t, "invalid", tumbler.PolicyInvalid.String())
}
