package tumbler_test

import (
	"context"
	"errors"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/securebytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failRand is a RNG source that succeeds `ok` times, then errors.
func failRand(ok int) func([]byte) (int, error) {
	n := 0
	return func(b []byte) (int, error) {
		if n >= ok {
			return 0, errors.New("rng failure injected")
		}
		n++
		for i := range b {
			b[i] = 0x11
		}
		return len(b), nil
	}
}

func TestEnroll_RandFailure_SaltGeneration(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	restore := tumbler.SetRandRead(failRand(0)) // fail the very first read (salt)
	defer restore()

	_, err := tumbler.NewPasswordMethod(cheapScrypt(), pw).Enroll(context.Background(), dek)
	require.Error(t, err)
}

func TestWrapDEK_RandFailure_EachRandomField(t *testing.T) {
	// Recovery enroll goes straight to wrapDEK (no salt gen), which draws
	// randomness for slotID, then HKDF salt, then nonce. Failing after 0/1/2
	// successes covers each field's error branch.
	for _, ok := range []int{0, 1, 2} {
		dek, _ := makeDEK(t, 32)
		code, err := tumbler.GenerateRecoveryCode()
		require.NoError(t, err)
		restore := tumbler.SetRandRead(failRand(ok))
		_, err = tumbler.NewRecoveryMethod(code).Enroll(context.Background(), dek)
		restore()
		_ = code.Destroy()
		require.Errorf(t, err, "expected failure when rng fails after %d successes", ok)
	}
}

func TestGenerateRecoveryCode_RandFailure(t *testing.T) {
	restore := tumbler.SetRandRead(failRand(0))
	defer restore()
	_, err := tumbler.GenerateRecoveryCode()
	require.Error(t, err)
}

func TestDeriveKEK_MLockFailure_BuildIKM(t *testing.T) {
	pk := newSecret(t, make32(0x01))
	restore := tumbler.SetSBNewZero(func(int) (*securebytes.SecureBytes, error) {
		return nil, errors.New("mlock failure injected")
	})
	defer restore()
	_, err := tumbler.DeriveKEKForTest(pk, nil, nil, make([]byte, 16), 1, tumbler.MethodPassword, [8]byte{})
	require.Error(t, err)
}

func TestDeriveKEK_MLockFailure_KEKAllocation(t *testing.T) {
	pk := newSecret(t, make32(0x01))
	restore := tumbler.SetSBNew(func([]byte) (*securebytes.SecureBytes, error) {
		return nil, errors.New("mlock failure injected")
	})
	defer restore()
	_, err := tumbler.DeriveKEKForTest(pk, nil, nil, make([]byte, 16), 1, tumbler.MethodPassword, [8]byte{})
	require.Error(t, err)
}

func TestOpen_MLockFailure_IsNotAuthError(t *testing.T) {
	// A successful tag verification followed by an mlock failure on the DEK
	// allocation must surface as a system error, NOT ErrAuthFailed.
	kek := newSecret(t, make32(0x55))
	dek := newSecret(t, []byte("payload"))
	nonce := make([]byte, 12)
	aad := []byte("aad")
	ct, err := tumbler.SealForTest(kek, dek, nonce, aad)
	require.NoError(t, err)

	restore := tumbler.SetSBNew(func([]byte) (*securebytes.SecureBytes, error) {
		return nil, errors.New("mlock failure injected")
	})
	defer restore()
	_, err = tumbler.OpenForTest(kek, nonce, ct, aad)
	require.Error(t, err)
	assert.NotErrorIs(t, err, tumbler.ErrAuthFailed)
}

func TestGenerateDEK_MLockFailure(t *testing.T) {
	restore := tumbler.SetSBNewZero(func(int) (*securebytes.SecureBytes, error) {
		return nil, errors.New("mlock failure injected")
	})
	defer restore()
	_, err := tumbler.GenerateDEK(32)
	require.Error(t, err)
}

func TestKDFDerive_MLockFailure(t *testing.T) {
	pw := newSecret(t, []byte("pw"))
	restore := tumbler.SetSBNew(func([]byte) (*securebytes.SecureBytes, error) {
		return nil, errors.New("mlock failure injected")
	})
	defer restore()

	_, err := cheapArgon().Derive(pw, make([]byte, 16))
	require.Error(t, err)
	_, err = cheapScrypt().Derive(pw, make([]byte, 16))
	require.Error(t, err)
}

func TestVersion(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(context.Background(), dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	assert.Equal(t, tumbler.FormatVersion, env.Version())
}

func TestUnlock_NoMethods(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(context.Background(), dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	_, err = env.Unlock(context.Background())
	assert.ErrorIs(t, err, tumbler.ErrNoMethods)
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	_, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	assert.ErrorIs(t, err, context.Canceled)
}
