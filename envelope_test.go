package tumbler_test

import (
	"context"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/securebytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeDEK returns a fixed, known data key for round-trip assertions.
func makeDEK(t *testing.T, n int) (*securebytes.SecureBytes, []byte) {
	t.Helper()
	want := make([]byte, n)
	for i := range want {
		want[i] = byte(i * 7)
	}
	return newSecret(t, want), want
}

// ---------------------------------------------------------------------------
// Password-only round trips
// ---------------------------------------------------------------------------

func TestEnvelope_PasswordOnly_RoundTrip(t *testing.T) {
	ctx := context.Background()
	dek, want := makeDEK(t, 32)
	pw := newSecret(t, []byte("correct horse battery staple"))

	m := tumbler.NewPasswordMethod(cheapScrypt(), pw)
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly, m)
	require.NoError(t, err)
	assert.Equal(t, tumbler.PolicyPasswordOnly, env.EffectivePolicy())
	assert.Equal(t, 1, env.SlotCount())

	// Serialize, parse, unlock.
	blob, err := env.Marshal()
	require.NoError(t, err)
	parsed, err := tumbler.ParseEnvelope(blob)
	require.NoError(t, err)

	got, err := parsed.Unlock(ctx, tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, want)
}

func TestEnvelope_WrongPassword_UniformAuthFailed(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("the-real-password"))

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	wrong := newSecret(t, []byte("not-the-password"))
	_, err = env.Unlock(ctx, tumbler.NewPasswordMethod(cheapScrypt(), wrong))
	require.Error(t, err)
	assert.ErrorIs(t, err, tumbler.ErrAuthFailed)
}

func TestEnvelope_AppSeedAsDEK_64Bytes(t *testing.T) {
	ctx := context.Background()
	dek, want := makeDEK(t, 64) // sigil/hush seed size
	pw := newSecret(t, []byte("wallet-guardian"))

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapArgon(), pw))
	require.NoError(t, err)

	blob, err := env.Marshal()
	require.NoError(t, err)
	parsed, err := tumbler.ParseEnvelope(blob)
	require.NoError(t, err)

	got, err := parsed.Unlock(ctx, tumbler.NewPasswordMethod(cheapArgon(), pw))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, want)
}

// ---------------------------------------------------------------------------
// Recovery code (additive slot)
// ---------------------------------------------------------------------------

func TestEnvelope_RecoveryCode_UnlocksAlongsidePassword(t *testing.T) {
	ctx := context.Background()
	dek, want := makeDEK(t, 32)
	pw := newSecret(t, []byte("primary-password"))

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })

	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code)))
	assert.Equal(t, 2, env.SlotCount())
	// Recovery slots do not change the derived policy.
	assert.Equal(t, tumbler.PolicyPasswordOnly, env.EffectivePolicy())

	// Round-trip and unlock via the recovery code alone.
	blob, err := env.Marshal()
	require.NoError(t, err)
	parsed, err := tumbler.ParseEnvelope(blob)
	require.NoError(t, err)

	got, err := parsed.Unlock(ctx, tumbler.NewRecoveryMethod(code))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, want)
}

func TestEnvelope_RecoveryCode_FormatParseRoundTrip(t *testing.T) {
	ctx := context.Background()
	dek, want := makeDEK(t, 32)
	pw := newSecret(t, []byte("primary-password"))

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code)))

	// Format for display, then parse the printed form back (simulating a user).
	printed, err := tumbler.FormatRecoveryCode(code)
	require.NoError(t, err)
	assert.Contains(t, printed, "-") // grouped for readability

	reparsed, err := tumbler.ParseRecoveryCode(printed)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reparsed.Destroy() })

	got, err := env.Unlock(ctx, tumbler.NewRecoveryMethod(reparsed))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, want)
}

func TestEnvelope_WrongRecoveryCode_AuthFailed(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("primary-password"))

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code)))

	other, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Destroy() })

	_, err = env.Unlock(ctx, tumbler.NewRecoveryMethod(other))
	assert.ErrorIs(t, err, tumbler.ErrAuthFailed)
}

// ---------------------------------------------------------------------------
// Policy semantics
// ---------------------------------------------------------------------------

func TestNewEnvelope_PolicyMismatch(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))

	// Password method but declaring YubiKey-only -> mismatch.
	_, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyYubiKeyOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	assert.ErrorIs(t, err, tumbler.ErrPolicyMismatch)
}

func TestNewEnvelope_NoMethods(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	_, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly)
	assert.ErrorIs(t, err, tumbler.ErrNoMethods)
}

func TestNewEnvelope_BadDEKSize(t *testing.T) {
	ctx := context.Background()
	pw := newSecret(t, []byte("pw"))
	empty, err := securebytes.NewZero(0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = empty.Destroy() })
	_, err = tumbler.NewEnvelope(ctx, empty, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	assert.ErrorIs(t, err, tumbler.ErrDEKSize)
}

func TestAddSlot_PolicyCoherence(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	// Adding a second password slot keeps policy coherent.
	pw2 := newSecret(t, []byte("pw2"))
	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewPasswordMethod(cheapScrypt(), pw2, tumbler.WithLabel("second"))))
	assert.Equal(t, tumbler.PolicyPasswordOnly, env.EffectivePolicy())

	infos := env.SlotInfos()
	require.Len(t, infos, 2)
	assert.Equal(t, "password", infos[0].Label)
	assert.Equal(t, "second", infos[1].Label)
}

// ---------------------------------------------------------------------------
// RemoveSlot
// ---------------------------------------------------------------------------

func TestRemoveSlot(t *testing.T) {
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
	require.Equal(t, 2, env.SlotCount())

	// Remove the recovery slot by ID.
	infos := env.SlotInfos()
	var recoveryID [8]byte
	for _, in := range infos {
		if in.Type == tumbler.MethodRecovery {
			recoveryID = in.ID
		}
	}
	require.NoError(t, env.RemoveSlot(recoveryID))
	assert.Equal(t, 1, env.SlotCount())

	// The password slot still opens.
	got, err := env.Unlock(ctx, tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, want)

	// Removing the last slot is refused.
	last := env.SlotInfos()[0].ID
	err = env.RemoveSlot(last)
	assert.ErrorIs(t, err, tumbler.ErrPolicyUnsafe)

	// Removing an unknown ID reports not-found.
	err = env.RemoveSlot([8]byte{0xDE, 0xAD})
	assert.ErrorIs(t, err, tumbler.ErrSlotNotFound)
}

// ---------------------------------------------------------------------------
// Marshal / Parse stability
// ---------------------------------------------------------------------------

func TestMarshalParse_ByteIdenticalRoundTrip(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 48)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewRecoveryMethod(code)))

	blob1, err := env.Marshal()
	require.NoError(t, err)
	parsed, err := tumbler.ParseEnvelope(blob1)
	require.NoError(t, err)
	blob2, err := parsed.Marshal()
	require.NoError(t, err)
	assert.Equal(t, blob1, blob2, "re-marshal must be byte-identical")
}

// ---------------------------------------------------------------------------
// Tamper: exhaustive single-byte-flip property
// ---------------------------------------------------------------------------

// TestTamper_EveryByteFlip proves that flipping ANY single byte of a valid
// serialized envelope can never cause it to unlock to a DIFFERENT data key.
// Each flip must either fail to parse, fail authentication (ErrAuthFailed),
// or — only for the advisory policy-hint byte — still yield the SAME key.
func TestTamper_EveryByteFlip(t *testing.T) {
	ctx := context.Background()
	dek, want := makeDEK(t, 32)
	pw := newSecret(t, []byte("tamper-test-pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	blob, err := env.Marshal()
	require.NoError(t, err)

	const policyHintOffset = 5 // magic(4) + version(1)

	for i := range blob {
		tampered := append([]byte(nil), blob...)
		tampered[i] ^= 0xFF

		parsed, perr := tumbler.ParseEnvelope(tampered)
		if perr != nil {
			continue // rejected at parse — safe
		}
		got, uerr := parsed.Unlock(ctx, tumbler.NewPasswordMethod(cheapScrypt(), pw))
		if uerr == nil {
			// The only byte whose flip may still unlock is the advisory
			// policy hint; it must yield the identical key and must not
			// alter the enforced (effective) policy source.
			require.Equalf(t, policyHintOffset, i, "unexpected successful unlock after flipping byte %d", i)
			requireSecretEquals(t, got, want)
			_ = got.Destroy()
			continue
		}
		require.ErrorIsf(t, uerr, tumbler.ErrAuthFailed, "byte %d: expected ErrAuthFailed", i)
	}
}

// TestTamper_TargetedFields flips specific authenticated metadata fields on
// disk and asserts each produces ErrAuthFailed (or a parse rejection),
// proving the downgrade-evident property field by field.
func TestTamper_TargetedFields(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("targeted-pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)

	// On-disk field flips: locate the slot body and flip representative
	// authenticated metadata bytes (the type byte and the kdfID byte). Any
	// edit must break the tag (ErrAuthFailed) or be rejected at parse.
	blob, err := env.Marshal()
	require.NoError(t, err)

	// Byte layout: header(8) | slotBodyLen(4) | [type(1) slotID(8) flags(1)
	// aead(1) kdfID(1) ...]. Flip the type byte and the kdfID byte.
	typeByteIx := 8 + 4
	kdfIDByteIx := 8 + 4 + 1 + 8 + 1 + 1 // after type,id,flags,aead

	for _, ix := range []int{typeByteIx, kdfIDByteIx} {
		tampered := append([]byte(nil), blob...)
		tampered[ix] ^= 0x01
		parsed, perr := tumbler.ParseEnvelope(tampered)
		if perr != nil {
			continue // structural rejection is acceptable
		}
		_, uerr := parsed.Unlock(ctx, tumbler.NewPasswordMethod(cheapScrypt(), pw))
		assert.ErrorIsf(t, uerr, tumbler.ErrAuthFailed, "flip at %d should auth-fail", ix)
	}
}

// TestTamper_PolicyHintIsAdvisory proves the header policy byte does not
// drive enforcement: flipping it leaves EffectivePolicy unchanged.
func TestTamper_PolicyHintIsAdvisory(t *testing.T) {
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("advisory-pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	blob, err := env.Marshal()
	require.NoError(t, err)

	blob[5] = byte(tumbler.PolicyYubiKeyOnly) // lie in the header
	parsed, err := tumbler.ParseEnvelope(blob)
	require.NoError(t, err)
	assert.Equal(t, tumbler.PolicyYubiKeyOnly, parsed.PolicyHint())
	// Enforcement source is unchanged:
	assert.Equal(t, tumbler.PolicyPasswordOnly, parsed.EffectivePolicy())
}
