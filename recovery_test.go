package tumbler_test

import (
	"context"
	"strings"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/securebytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRecoveryCode_Length(t *testing.T) {
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })
	assert.Equal(t, tumbler.RecoveryCodeLen, code.Len())
}

func TestRecoveryCode_FormatParse_RoundTrip(t *testing.T) {
	code, err := tumbler.GenerateRecoveryCode()
	require.NoError(t, err)
	t.Cleanup(func() { _ = code.Destroy() })

	printed, err := tumbler.FormatRecoveryCode(code)
	require.NoError(t, err)

	// User re-entry tolerance: lowercase, spaces, and extra separators.
	messy := strings.ToLower(strings.ReplaceAll(printed, "-", " - ")) + "  "
	parsed, err := tumbler.ParseRecoveryCode(messy)
	require.NoError(t, err)
	t.Cleanup(func() { _ = parsed.Destroy() })

	require.NoError(t, code.Use(func(orig []byte) {
		require.NoError(t, parsed.Use(func(got []byte) {
			assert.Equal(t, orig, got)
		}))
	}))
}

func TestParseRecoveryCode_Invalid(t *testing.T) {
	// Too short (decodes to fewer than 32 bytes).
	_, err := tumbler.ParseRecoveryCode("ABCDEF")
	assert.ErrorIs(t, err, tumbler.ErrInvalidRecoveryCode)

	// Contains a non-base32 character that survives cleaning ('1' is not in
	// the RFC 4648 base32 alphabet).
	_, err = tumbler.ParseRecoveryCode("11111111")
	assert.ErrorIs(t, err, tumbler.ErrInvalidRecoveryCode)

	// Empty.
	_, err = tumbler.ParseRecoveryCode("")
	assert.ErrorIs(t, err, tumbler.ErrInvalidRecoveryCode)
}

func TestRecoveryMethod_WrongLengthCode_Rejected(t *testing.T) {
	// A code that is not exactly RecoveryCodeLen must be rejected at enroll.
	short, err := securebytes.New([]byte("too-short"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = short.Destroy() })

	dek, _ := makeDEK(t, 32)
	_, err = tumbler.NewRecoveryMethod(short).Enroll(context.Background(), dek)
	assert.ErrorIs(t, err, tumbler.ErrInvalidRecoveryCode)
}
