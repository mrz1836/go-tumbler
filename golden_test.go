package tumbler_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenPassword is the fixed password baked into the v1 golden envelope.
const goldenPassword = "golden-v1-password-do-not-change"

// goldenPath is the committed frozen v1 envelope used as the back-compat guard.
var goldenPath = filepath.Join("testdata", "golden_v1.tmbl")

// buildGoldenEnvelope deterministically reconstructs the v1 golden envelope
// (a password + recovery two-slot envelope over a fixed data key) using a
// counting RNG so the bytes are reproducible. It returns the serialized bytes,
// the expected data key, and the recovery code that was enrolled.
func buildGoldenEnvelope(t *testing.T) (blob, wantDEK []byte, recovery string) {
	t.Helper()
	restore := tumbler.SetRandRead(countingRand())
	defer restore()

	dek, want := makeDEK(t, 32)
	pw := newSecret(t, []byte(goldenPassword))

	// Pin production-shaped scrypt params but at test-fast cost so the golden
	// is cheap to verify; the KDF id + params are what the format freezes.
	env, err := tumbler.NewEnvelope(context.Background(), dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(tumbler.NewScryptKDF(10, 8, 1), pw, tumbler.WithLabel("primary")))
	require.NoError(t, err)

	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	require.NoError(t, env.AddSlot(context.Background(), dek, tumbler.NewRecoveryMethod(code)))

	printed, err := tumbler.FormatRecoveryCode(code)
	require.NoError(t, err)

	b, err := env.Marshal()
	require.NoError(t, err)
	return b, want, printed
}

// TestGolden_V1_ByteStable asserts the deterministic v1 envelope is
// byte-identical to the committed fixture, catching any accidental
// wire-format drift. Regenerate the fixture deliberately (delete it and
// re-run) only when intentionally bumping the format.
func TestGolden_V1_ByteStable(t *testing.T) {
	blob, _, _ := buildGoldenEnvelope(t)

	committed, err := os.ReadFile(goldenPath)
	if os.IsNotExist(err) {
		require.NoError(t, os.MkdirAll(filepath.Dir(goldenPath), 0o755))
		require.NoError(t, os.WriteFile(goldenPath, blob, 0o644))
		t.Logf("wrote new golden fixture %s (%d bytes)", goldenPath, len(blob))
		return
	}
	require.NoError(t, err)
	assert.Equal(t, committed, blob, "v1 wire format drifted from committed golden")
}

// TestGolden_V1_ParsesAndUnlocks proves the committed v1 envelope still parses
// and unlocks via BOTH its password slot and its recovery slot — the true
// backward-compatibility guarantee.
func TestGolden_V1_ParsesAndUnlocks(t *testing.T) {
	_, wantDEK, recovery := buildGoldenEnvelope(t)

	committed, err := os.ReadFile(goldenPath)
	if os.IsNotExist(err) {
		t.Skip("golden fixture not yet generated; run TestGolden_V1_ByteStable first")
	}
	require.NoError(t, err)

	env, err := tumbler.ParseEnvelope(committed)
	require.NoError(t, err)
	assert.Equal(t, tumbler.PolicyPasswordOnly, env.EffectivePolicy())
	require.Equal(t, 2, env.SlotCount())

	// Unlock via password.
	pw := newSecret(t, []byte(goldenPassword))
	got, err := env.Unlock(context.Background(), tumbler.NewPasswordMethod(tumbler.NewScryptKDF(10, 8, 1), pw))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got.Destroy() })
	requireSecretEquals(t, got, wantDEK)

	// Unlock via recovery code.
	code, err := tumbler.ParseRecoveryCode(recovery)
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	got2, err := env.Unlock(context.Background(), tumbler.NewRecoveryMethod(code))
	require.NoError(t, err)
	t.Cleanup(func() { _ = got2.Destroy() })
	requireSecretEquals(t, got2, wantDEK)
}
