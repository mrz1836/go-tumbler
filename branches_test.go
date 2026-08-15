package tumbler_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/securebytes"
	"github.com/mrz1836/go-tumbler/transport"
)

// These tests fill the reachable error/guard branches that a normal round-trip
// never hits, using the existing test seams (SetRandRead / SetSBNew /
// SetSBNewZero / crafted in-memory slots / canceled ctx). The remaining ~2% of
// uncovered statements are genuinely-unreachable defensive branches — see
// coverage_notes_test.go for the enumerated list and why each cannot fire.

// ---------------------------------------------------------------------------
// method.go — wrapDEK / unwrapDEK
// ---------------------------------------------------------------------------

func TestWrapDEK_MarshalMetaError_OversizedLabel(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	long := strings.Repeat("x", 257) // > maxLabelLen -> marshalMeta rejects it
	_, err := tumbler.NewPasswordMethod(cheapScrypt(), pw, tumbler.WithLabel(long)).
		Enroll(context.Background(), dek)
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestWrapDEK_DeriveKEKError_MLock(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })

	// Recovery enroll goes straight to wrapDEK; failing the IKM allocation
	// (sbNewZero, the first such call) surfaces as a deriveKEK failure.
	restore := tumbler.SetSBNewZero(func(int) (*securebytes.SecureBytes, error) {
		return nil, errors.New("mlock failure injected")
	})
	defer restore()
	_, err = tumbler.NewRecoveryMethod(code).Enroll(context.Background(), dek)
	require.Error(t, err)
}

func TestUnwrapDEK_DeriveKEKError_MLock(t *testing.T) {
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

	// Recovery unlock goes straight to unwrapDEK -> deriveKEK -> buildIKM
	// (sbNewZero). Failing it surfaces as a system error, not ErrAuthFailed.
	restore := tumbler.SetSBNewZero(func(int) (*securebytes.SecureBytes, error) {
		return nil, errors.New("mlock failure injected")
	})
	defer restore()
	_, err = tumbler.NewRecoveryMethod(code).Unlock(ctx, env.SlotsForTest()[1])
	require.Error(t, err)
	assert.NotErrorIs(t, err, tumbler.ErrAuthFailed)
}

func TestUnwrapDEK_MetaNil_ResealReproducesAAD(t *testing.T) {
	ctx := context.Background()
	dek, want := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code)))

	// A slot with meta cleared forces unwrapDEK to re-marshal the AAD; because
	// every authenticated field is unchanged the reproduced AAD is identical
	// and the slot still opens.
	recSlot := env.SlotsForTest()[1].ClearMetaForTest()
	got, err := tumbler.NewRecoveryMethod(code).Unlock(ctx, recSlot)
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, want)
}

func TestUnwrapDEK_MetaNil_MarshalError(t *testing.T) {
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

	// meta cleared AND an oversized label -> the re-marshal in unwrapDEK fails.
	bad := env.SlotsForTest()[1].ClearMetaForTest()
	bad.Label = make([]byte, 257)
	_, err = tumbler.NewRecoveryMethod(code).Unlock(ctx, bad)
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

// ---------------------------------------------------------------------------
// kdf.go — scrypt stretch error
// ---------------------------------------------------------------------------

func TestScryptDerive_StretchError(t *testing.T) {
	pw := newSecret(t, []byte("pw"))
	// logN=0 -> N=1, which scrypt.Key rejects ("N must be > 1"); this is only
	// reachable by constructing the KDF directly (parseKDF's floor is logN>=1).
	_, err := tumbler.NewScryptKDF(0, 8, 1).Derive(pw, make([]byte, 16))
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// envelope.go — NewEnvelope / Unlock / AddSlot / Marshal / EffectivePolicy
// ---------------------------------------------------------------------------

func TestNewEnvelope_InvalidPolicy(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	_, err := tumbler.NewEnvelope(context.Background(), dek, tumbler.Policy(99),
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	assert.ErrorIs(t, err, tumbler.ErrPolicyMismatch)
}

func TestEnvelopeUnlock_ContextCancelledInLoop(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	// A canceled context is checked inside the slot/method loop once a
	// type-matching method is found.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = env.Unlock(cctx, tumbler.NewPasswordMethod(cheapScrypt(), pw))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestAddSlot_SlotCountAtMax(t *testing.T) {
	slots := make([]tumbler.Slot, 64) // maxSlotCount
	for i := range slots {
		slots[i] = craftPasswordSlot()
	}
	env := tumbler.NewEnvelopeRawForTest(tumbler.PolicyPasswordOnly, slots)

	dek, _ := makeDEK(t, 32)
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	err = env.AddSlot(context.Background(), dek, tumbler.NewRecoveryMethod(code))
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestAddSlot_PolicyMismatch(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	// A non-recovery method of a different policy is refused.
	err = env.AddSlot(ctx, dek, tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 2}, nil))
	assert.ErrorIs(t, err, tumbler.ErrPolicyMismatch)
}

func TestAddSlot_EnrollError(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	// A recovery method is always policy-permitted, but a canceled context
	// makes its Enroll fail; AddSlot surfaces that enroll error. (Also covers
	// RecoveryCodeMethod.Enroll's ctx.Err guard.)
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = env.AddSlot(cctx, dek, tumbler.NewRecoveryMethod(code))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestMarshal_Empty(t *testing.T) {
	env := tumbler.NewEnvelopeRawForTest(tumbler.PolicyPasswordOnly, nil)
	_, err := env.Marshal()
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestMarshal_SlotCountTooLarge(t *testing.T) {
	slots := make([]tumbler.Slot, 65) // > maxSlotCount
	for i := range slots {
		slots[i] = craftPasswordSlot()
	}
	env := tumbler.NewEnvelopeRawForTest(tumbler.PolicyPasswordOnly, slots)
	_, err := env.Marshal()
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestMarshal_WrappedLenGuard(t *testing.T) {
	s := craftPasswordSlot()
	s.Wrapped = nil // empty -> rejected before any metadata is written
	env := tumbler.NewEnvelopeRawForTest(tumbler.PolicyPasswordOnly, []tumbler.Slot{s})
	_, err := env.Marshal()
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestMarshal_MetaNilMarshalError(t *testing.T) {
	s := craftPasswordSlot() // meta==nil, Wrapped is a valid length
	s.Label = make([]byte, 257)
	env := tumbler.NewEnvelopeRawForTest(tumbler.PolicyPasswordOnly, []tumbler.Slot{s})
	_, err := env.Marshal()
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestMarshalMeta_UnsupportedAEAD(t *testing.T) {
	s := craftPasswordSlot()
	s.AEADID = tumbler.AEADID(99)
	_, err := tumbler.MarshalMetaForTest(&s)
	assert.ErrorIs(t, err, tumbler.ErrUnsupportedAEAD)
}

func TestEffectivePolicy_UnknownPrimaryType_Invalid(t *testing.T) {
	s := craftPasswordSlot()
	s.Type = tumbler.MethodType(99) // unknown, non-recovery -> policyForMethod default
	env := tumbler.NewEnvelopeRawForTest(tumbler.PolicyPasswordOnly, []tumbler.Slot{s})
	assert.Equal(t, tumbler.PolicyInvalid, env.EffectivePolicy())
}

// ---------------------------------------------------------------------------
// password.go — Enroll / Unlock guards
// ---------------------------------------------------------------------------

func TestPasswordEnroll_ContextCancelled(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tumbler.NewPasswordMethod(cheapScrypt(), pw).Enroll(cctx, dek)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestPasswordEnroll_NilKDF(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	_, err := tumbler.NewPasswordMethod(nil, pw).Enroll(context.Background(), dek)
	assert.ErrorIs(t, err, tumbler.ErrUnsupportedKDF)
}

func TestPasswordUnlock_ContextCancelled(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = tumbler.NewPasswordMethod(cheapScrypt(), pw).Unlock(cctx, env.SlotsForTest()[0])
	assert.ErrorIs(t, err, context.Canceled)
}

func TestPasswordUnlock_InvalidKDFParams(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	slots := env.SlotsForTest()
	slots[0].KDFParams = []byte{1, 2, 3} // wrong length -> parseKDF rejects it
	env.SetSlotsForTest(slots)
	_, err = env.Unlock(ctx, tumbler.NewPasswordMethod(cheapScrypt(), pw))
	assert.ErrorIs(t, err, tumbler.ErrKDFParams)
}

// ---------------------------------------------------------------------------
// recovery.go — Enroll / code generation / parsing / groupString
// ---------------------------------------------------------------------------

func TestRecoveryEnroll_ContextCancelled(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = tumbler.NewRecoveryMethod(code).Enroll(cctx, dek)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestGenerateRecoveryCode_MLockFailure(t *testing.T) {
	restore := tumbler.SetSBNew(func([]byte) (*securebytes.SecureBytes, error) {
		return nil, errors.New("mlock failure injected")
	})
	defer restore()
	_, err := tumbler.GenerateRecoveryCode()
	require.Error(t, err)
}

func TestParseRecoveryCode_MLockFailure(t *testing.T) {
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	printed, err := tumbler.FormatRecoveryCode(code)
	require.NoError(t, err)
	_ = code.Destroy()

	restore := tumbler.SetSBNew(func([]byte) (*securebytes.SecureBytes, error) {
		return nil, errors.New("mlock failure injected")
	})
	defer restore()
	_, err = tumbler.ParseRecoveryCode(printed)
	require.Error(t, err)
}

func TestGroupString_EarlyReturns(t *testing.T) {
	assert.Equal(t, "abc", tumbler.GroupStringForTest("abc", 0))    // n <= 0
	assert.Equal(t, "ab", tumbler.GroupStringForTest("ab", 4))      // len(s) <= n
	assert.Equal(t, "ab-cd", tumbler.GroupStringForTest("abcd", 2)) // normal grouping
}

// ---------------------------------------------------------------------------
// yubikey.go — Enroll / Unlock guards, enroll2FA rand/derive/transport errors
// ---------------------------------------------------------------------------

func TestYubiKeyEnroll_ContextCancelled(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 2}, nil).Enroll(cctx, dek)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestYubiKeyEnroll_RandFailure_Challenge(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	restore := tumbler.SetRandRead(failRand(0))
	defer restore()
	_, err := tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 2}, nil).
		Enroll(context.Background(), dek)
	require.Error(t, err)
}

func TestYubiKey2FAEnroll_RandFailure_KDFSalt(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	restore := tumbler.SetRandRead(failRand(0))
	defer restore()
	_, err := tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw).
		Enroll(context.Background(), dek)
	require.Error(t, err)
}

func TestYubiKey2FAEnroll_RandFailure_ChalSalt(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	// The KDF salt (read #0) succeeds; the chal-salt (read #1) fails. scrypt's
	// Derive draws no randomness, so read ordering is deterministic.
	restore := tumbler.SetRandRead(failRand(1))
	defer restore()
	_, err := tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw).
		Enroll(context.Background(), dek)
	require.Error(t, err)
}

func TestYubiKey2FAEnroll_DeriveError(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	require.NoError(t, pw.Destroy()) // a destroyed password fails Derive
	_, err := tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw).
		Enroll(context.Background(), dek)
	require.Error(t, err)
}

func TestYubiKey2FAEnroll_ChallengeResponseError(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	fake := newFake()
	fake.TouchFn = func() error { return transport.ErrTouchTimeout }
	_, err := tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw).
		Enroll(context.Background(), dek)
	assert.ErrorIs(t, err, transport.ErrTouchTimeout)
}

func TestYubiKeyUnlock_ContextCancelled(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := newFake()
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil))
	require.NoError(t, err)

	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2}, nil).
		Unlock(cctx, env.SlotsForTest()[0])
	assert.ErrorIs(t, err, context.Canceled)
}

func TestYubiKey2FAUnlock_ChallengeResponseError(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	fake := newFake()
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordAndYubiKey,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw))
	require.NoError(t, err)

	fake.TouchFn = func() error { return transport.ErrTouchTimeout }
	_, err = env.Unlock(ctx,
		tumbler.NewYubiKeyMethod(fake, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, newSecret(t, []byte("pw"))))
	assert.ErrorIs(t, err, transport.ErrTouchTimeout)
}

func TestDeriveChallenge_DestroyedPK(t *testing.T) {
	pk := newSecret(t, make32(0x01))
	require.NoError(t, pk.Destroy())
	_, err := tumbler.DeriveChallengeForTest(pk, make([]byte, 16))
	require.Error(t, err)
}

// badKDF is a KDF whose Derive returns an already-destroyed key, so the caller
// that then Uses it (deriveChallenge in enroll2FA) fails. It models a
// misbehaving third-party KDF plugin.
type badKDF struct{}

func (badKDF) ID() tumbler.KDFID { return tumbler.KDFScrypt }
func (badKDF) SaltLen() int      { return 16 }
func (badKDF) MarshalParams() []byte {
	return scryptParams(8, 8, 1)
}

func (badKDF) Derive(_ *securebytes.SecureBytes, _ []byte) (*securebytes.SecureBytes, error) {
	sb, err := securebytes.New(make([]byte, 32))
	if err != nil {
		return nil, err
	}
	_ = sb.Destroy()
	return sb, nil // live-looking but destroyed -> Use fails downstream
}

func TestYubiKey2FAEnroll_DeriveChallengeError(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	_, err := tumbler.NewYubiKeyMethod(newFake(), tumbler.YubiKeyConfig{Slot: 2, KDF: badKDF{}}, pw).
		Enroll(context.Background(), dek)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// combine.go — seal/open key-size guard; wrapDEK seal error
// ---------------------------------------------------------------------------

func TestSeal_WrongKeySize(t *testing.T) {
	kek := newSecret(t, make([]byte, 16)) // not 32 bytes -> chacha20poly1305.New errors
	dek := newSecret(t, []byte("payload"))
	_, err := tumbler.SealForTest(kek, dek, make([]byte, 12), nil)
	require.Error(t, err)
}

func TestOpen_WrongKeySize(t *testing.T) {
	kek := newSecret(t, make([]byte, 16))
	_, err := tumbler.OpenForTest(kek, make([]byte, 12), make([]byte, 32), nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, tumbler.ErrAuthFailed) // a construction error, not auth failure
}

func TestWrapDEK_SealError_DestroyedDEK(t *testing.T) {
	dek, _ := makeDEK(t, 32)
	require.NoError(t, dek.Destroy()) // recovery Enroll skips the DEK-length check
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	_, err = tumbler.NewRecoveryMethod(code).Enroll(context.Background(), dek)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// tumbler.go — GenerateDEK Use error
// ---------------------------------------------------------------------------

func TestGenerateDEK_UseError(t *testing.T) {
	// Hand GenerateDEK a live-looking but destroyed buffer so its Use fails.
	restore := tumbler.SetSBNewZero(func(n int) (*securebytes.SecureBytes, error) {
		sb, err := securebytes.NewZero(n)
		if err != nil {
			return nil, err
		}
		_ = sb.Destroy()
		return sb, nil
	})
	defer restore()
	_, err := tumbler.GenerateDEK(32)
	require.Error(t, err)
}
