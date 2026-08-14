package tumbler_test

import (
	"encoding/binary"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArgon2id_DeterministicAndSized(t *testing.T) {
	k := tumbler.NewArgon2idKDF(1, 16, 1)
	pw := newSecret(t, []byte("passphrase-material"))
	salt := []byte("0123456789abcdef")

	a, err := k.Derive(pw, salt)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Destroy() })
	b, err := k.Derive(pw, salt)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Destroy() })

	assert.Equal(t, 32, a.Len())
	assert.Equal(t, copyOut(t, a), copyOut(t, b), "same pw+salt must derive same key")
	assert.Equal(t, tumbler.KDFArgon2id, k.ID())
	assert.Equal(t, 16, k.SaltLen())
}

func TestArgon2id_DifferentSaltDiffersKey(t *testing.T) {
	k := tumbler.NewArgon2idKDF(1, 16, 1)
	pw := newSecret(t, []byte("passphrase-material"))
	a, err := k.Derive(pw, []byte("salt-aaaaaaaaaaa"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Destroy() })
	b, err := k.Derive(pw, []byte("salt-bbbbbbbbbbb"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Destroy() })
	assert.NotEqual(t, copyOut(t, a), copyOut(t, b))
}

func TestScrypt_DeterministicAndSized(t *testing.T) {
	k := tumbler.NewScryptKDF(8, 8, 1)
	pw := newSecret(t, []byte("passphrase-material"))
	salt := []byte("0123456789abcdef")

	a, err := k.Derive(pw, salt)
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Destroy() })
	assert.Equal(t, 32, a.Len())
	assert.Equal(t, tumbler.KDFScrypt, k.ID())
}

func TestKDF_MarshalParams_RoundTripThroughParse(t *testing.T) {
	t.Run("argon2", func(t *testing.T) {
		k := tumbler.NewArgon2idKDF(4, 256*1024, 4) // hush production params
		got, err := tumbler.ParseKDFForTest(k.ID(), k.MarshalParams())
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, k.MarshalParams(), got.MarshalParams())
	})
	t.Run("scrypt", func(t *testing.T) {
		k := tumbler.NewScryptKDF(18, 8, 1) // sigil production params
		got, err := tumbler.ParseKDFForTest(k.ID(), k.MarshalParams())
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, k.MarshalParams(), got.MarshalParams())
	})
}

func TestParseKDF_None(t *testing.T) {
	k, err := tumbler.ParseKDFForTest(tumbler.KDFNone, nil)
	require.NoError(t, err)
	assert.Nil(t, k)

	_, err = tumbler.ParseKDFForTest(tumbler.KDFNone, []byte{1})
	assert.ErrorIs(t, err, tumbler.ErrKDFParams)
}

func TestParseKDF_UnknownID(t *testing.T) {
	_, err := tumbler.ParseKDFForTest(tumbler.KDFID(99), []byte{1, 2, 3})
	assert.ErrorIs(t, err, tumbler.ErrUnsupportedKDF)
}

// argonParams builds a 9-byte Argon2id parameter block.
func argonParams(time, mem uint32, threads uint8) []byte {
	b := make([]byte, 9)
	binary.BigEndian.PutUint32(b[0:4], time)
	binary.BigEndian.PutUint32(b[4:8], mem)
	b[8] = threads
	return b
}

// scryptParams builds a 9-byte scrypt parameter block.
func scryptParams(logN uint8, r, p uint32) []byte {
	b := make([]byte, 9)
	b[0] = logN
	binary.BigEndian.PutUint32(b[1:5], r)
	binary.BigEndian.PutUint32(b[5:9], p)
	return b
}

func TestParseKDF_Argon2Bounds(t *testing.T) {
	cases := map[string][]byte{
		"wrong length":    {1, 2, 3},
		"time zero":       argonParams(0, 1024, 1),
		"time too high":   argonParams(33, 1024, 1),
		"mem too small":   argonParams(1, 4, 1),
		"mem too large":   argonParams(1, 3*1024*1024, 1), // 3 GiB > 2 GiB ceiling
		"threads zero":    argonParams(1, 1024, 0),
		"threads too big": argonParams(1, 1024, 17),
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tumbler.ParseKDFForTest(tumbler.KDFArgon2id, params)
			assert.ErrorIs(t, err, tumbler.ErrKDFParams)
		})
	}
	// Valid production params pass.
	_, err := tumbler.ParseKDFForTest(tumbler.KDFArgon2id, argonParams(4, 256*1024, 4))
	assert.NoError(t, err)
}

func TestParseKDF_ScryptBounds(t *testing.T) {
	cases := map[string][]byte{
		"wrong length":   {1, 2, 3},
		"logN zero":      scryptParams(0, 8, 1),
		"logN too high":  scryptParams(23, 8, 1),
		"r zero":         scryptParams(14, 0, 1),
		"r too big":      scryptParams(14, 33, 1),
		"p zero":         scryptParams(14, 8, 0),
		"p too big":      scryptParams(14, 8, 17),
		"memory too big": scryptParams(22, 32, 1), // 128*2^22*32 = 16 GiB > ceiling
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tumbler.ParseKDFForTest(tumbler.KDFScrypt, params)
			assert.ErrorIs(t, err, tumbler.ErrKDFParams)
		})
	}
	// Valid production params pass.
	_, err := tumbler.ParseKDFForTest(tumbler.KDFScrypt, scryptParams(18, 8, 1))
	assert.NoError(t, err)
}
