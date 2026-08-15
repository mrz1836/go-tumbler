package tumbler_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/securebytes"
	"github.com/mrz1836/go-tumbler/transport"
)

// These tests pin the real findings from the adversarial audit so any
// regression (or the eventual v2 PIV fix) is caught by the suite.

// ---------------------------------------------------------------------------
// Finding #1 — the 2FA challenge (an offline password verifier) reaches the
// transport, where YkmanTransport places it in argv. This pins the v1 exposure;
// it will flip once the v2 PIV (no-argv-PIN) path lands.
// ---------------------------------------------------------------------------

// recordingTransport captures every challenge handed to the transport.
type recordingTransport struct {
	inner      *transport.FakeTransport
	challenges [][]byte
}

func (r *recordingTransport) ChallengeResponse(ctx context.Context, slot uint8, challenge []byte) (*securebytes.SecureBytes, error) {
	r.challenges = append(r.challenges, append([]byte(nil), challenge...))
	return r.inner.ChallengeResponse(ctx, slot, challenge)
}

func (r *recordingTransport) Serial(ctx context.Context) (string, error) { return r.inner.Serial(ctx) }

func (r *recordingTransport) Present(ctx context.Context) bool { return r.inner.Present(ctx) }

func TestFinding1_2FAChallengeReachesTransport(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	rec := &recordingTransport{inner: newFake()}
	pw := newSecret(t, []byte("two-factor-password"))

	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordAndYubiKey,
		tumbler.NewYubiKeyMethod(rec, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, pw))
	require.NoError(t, err)

	// The secret 2FA challenge is NOT stored on disk...
	slot := env.SlotsForTest()[0]
	assert.Empty(t, slot.Challenge, "2FA challenge must never be stored")

	// ...but it IS handed to the transport (which puts it in argv). The
	// enrollment challenge above was captured; capture the unlock one too.
	before := len(rec.challenges)
	got, err := env.Unlock(ctx,
		tumbler.NewYubiKeyMethod(rec, tumbler.YubiKeyConfig{Slot: 2, KDF: cheapScrypt()}, newSecret(t, []byte("two-factor-password"))))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })

	require.Greater(t, len(rec.challenges), before, "unlock must send a challenge to the transport")
	unlockChallenge := rec.challenges[len(rec.challenges)-1]
	assert.NotEmpty(t, unlockChallenge, "the derived secret challenge transits the transport boundary")
	assert.Len(t, unlockChallenge, 32, "challenge is the derived yubiChallengeLen secret")
}

// ---------------------------------------------------------------------------
// Finding #2 — over-ceiling KDF parameters in a crafted envelope are rejected
// at parse, before any expensive derivation is attempted.
// ---------------------------------------------------------------------------

func TestFinding2_OverCeilingKDFParams_RejectedAtParse(t *testing.T) {
	t.Parallel()
	t.Run("argon2 memory over ceiling", func(t *testing.T) {
		s := craftPasswordSlot()
		s.KDFParams = argonParams(1, 3*1024*1024, 1) // 3 GiB > 2 GiB ceiling
		_, err := tumbler.ParseEnvelope(craftBlob(t, s))
		assert.ErrorIs(t, err, tumbler.ErrKDFParams)
	})
	t.Run("argon2 max time+threads still bounded", func(t *testing.T) {
		s := craftPasswordSlot()
		s.KDFParams = argonParams(33, 256*1024, 17) // time & threads over ceilings
		_, err := tumbler.ParseEnvelope(craftBlob(t, s))
		assert.ErrorIs(t, err, tumbler.ErrKDFParams)
	})
}

// ---------------------------------------------------------------------------
// Finding #3 — a recovery-only envelope reports PolicyInvalid (recovery slots
// bear no policy) yet still unlocks by code. Documented escape-hatch semantics.
// ---------------------------------------------------------------------------

func TestFinding3_RecoveryOnlyEnvelope_PolicyInvalidButUnlockable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dek, want := makeDEK(t, 32)
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })

	// Build the recovery-only shape directly (NewEnvelope would reject the
	// policy; RemoveSlot now refuses to reduce a real envelope to this shape).
	slot, err := tumbler.NewRecoveryMethod(code).Enroll(ctx, dek)
	require.NoError(t, err)
	env := tumbler.NewEnvelopeRawForTest(tumbler.PolicyInvalid, []tumbler.Slot{slot})

	assert.Equal(t, tumbler.PolicyInvalid, env.EffectivePolicy(),
		"recovery slots do not participate in policy derivation")

	got, err := env.Unlock(ctx, tumbler.NewRecoveryMethod(code))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, want)
}

// ---------------------------------------------------------------------------
// Finding #4 — RemoveSlot must never leave an envelope with zero primary slots.
// ---------------------------------------------------------------------------

func TestFinding4_RemoveSlot_RefusesLastPrimary(t *testing.T) {
	t.Parallel()
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

	primaryID := slotIDByType(env, tumbler.MethodPassword)
	recoveryID := slotIDByType(env, tumbler.MethodRecovery)

	// Removing the only primary would leave a recovery-only, un-re-addable
	// envelope: refused, nothing changed.
	err = env.RemoveSlot(primaryID)
	assert.ErrorIs(t, err, tumbler.ErrPolicyUnsafe)
	assert.Equal(t, 2, env.SlotCount())

	// The recovery slot is still freely removable (it leaves the primary).
	require.NoError(t, env.RemoveSlot(recoveryID))
	assert.Equal(t, 1, env.SlotCount())
}

func TestFinding4_RemoveSlot_AddBeforeRemoveStaysLegal(t *testing.T) {
	t.Parallel()
	// The add-before-remove swap (hush's passphrase rewrap) is preserved: with
	// two primaries present, removing one leaves a valid single-primary envelope.
	ctx := context.Background()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(ctx, dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	firstID := env.SlotInfos()[0].ID

	pw2 := newSecret(t, []byte("pw2"))
	require.NoError(t, env.AddSlot(ctx, dek, tumbler.NewPasswordMethod(cheapScrypt(), pw2)))
	require.NoError(t, env.RemoveSlot(firstID)) // 2 primaries -> 1: allowed
	assert.Equal(t, 1, env.SlotCount())
	assert.Equal(t, tumbler.PolicyPasswordOnly, env.EffectivePolicy())
}

// slotIDByType returns the ID of the first slot of the given type.
func slotIDByType(env *tumbler.Envelope, mt tumbler.MethodType) [8]byte {
	for _, in := range env.SlotInfos() {
		if in.Type == mt {
			return in.ID
		}
	}
	return [8]byte{}
}
