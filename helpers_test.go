package tumbler_test

import (
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/securebytes"
	"github.com/stretchr/testify/require"
)

// newSecret builds a SecureBytes from a COPY of b so the caller keeps b for
// later comparison (securebytes.New zeroes its input).
func newSecret(t *testing.T, b []byte) *securebytes.SecureBytes {
	t.Helper()
	cp := append([]byte(nil), b...)
	sb, err := securebytes.New(cp)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })
	return sb
}

// requireSecretEquals asserts the payload of sb equals want.
func requireSecretEquals(t *testing.T, sb *securebytes.SecureBytes, want []byte) {
	t.Helper()
	require.NotNil(t, sb)
	require.NoError(t, sb.Use(func(b []byte) {
		require.Equal(t, want, b)
	}))
}

// cheapScrypt returns a scrypt KDF with test-fast parameters (logN=8). It
// exercises the same code path as production without the multi-hundred-ms cost.
func cheapScrypt() tumbler.KDF { return tumbler.NewScryptKDF(8, 8, 1) }

// cheapArgon returns an Argon2id KDF with test-fast parameters.
func cheapArgon() tumbler.KDF { return tumbler.NewArgon2idKDF(1, 8, 1) }

// countingRand returns a deterministic byte source (0,1,2,... mod 256) for
// building stable golden envelopes. It NEVER errors.
func countingRand() func([]byte) (int, error) {
	var ctr byte
	return func(b []byte) (int, error) {
		for i := range b {
			b[i] = ctr
			ctr++
		}
		return len(b), nil
	}
}
