package tumbler_test

import (
	"context"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validBlob returns a real, serialized password-only envelope.
func validBlob(t *testing.T) []byte {
	t.Helper()
	dek, _ := makeDEK(t, 32)
	pw := newSecret(t, []byte("pw"))
	env, err := tumbler.NewEnvelope(context.Background(), dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(cheapScrypt(), pw))
	require.NoError(t, err)
	blob, err := env.Marshal()
	require.NoError(t, err)
	return blob
}

func TestParse_ShortHeader(t *testing.T) {
	for n := range 8 {
		_, err := tumbler.ParseEnvelope(make([]byte, n))
		require.Error(t, err)
		assert.ErrorIsf(t, err, tumbler.ErrShortData, "len %d", n)
	}
}

func TestParse_BadMagic(t *testing.T) {
	blob := validBlob(t)
	blob[0] = 'X'
	_, err := tumbler.ParseEnvelope(blob)
	assert.ErrorIs(t, err, tumbler.ErrBadMagic)
}

func TestParse_BadVersion(t *testing.T) {
	blob := validBlob(t)
	blob[4] = 0xFE
	_, err := tumbler.ParseEnvelope(blob)
	assert.ErrorIs(t, err, tumbler.ErrBadVersion)
}

func TestParse_SlotCountZero(t *testing.T) {
	blob := validBlob(t)
	blob[6], blob[7] = 0, 0
	_, err := tumbler.ParseEnvelope(blob)
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestParse_SlotCountTooLarge(t *testing.T) {
	blob := validBlob(t)
	blob[6], blob[7] = 0xFF, 0xFF // 65535 > maxSlotCount
	_, err := tumbler.ParseEnvelope(blob)
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestParse_TrailingBytes(t *testing.T) {
	blob := validBlob(t)
	blob = append(blob, 0x00)
	_, err := tumbler.ParseEnvelope(blob)
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestParse_TruncatedSlotBody(t *testing.T) {
	blob := validBlob(t)
	// Drop the last byte so the declared slot body overruns the buffer.
	_, err := tumbler.ParseEnvelope(blob[:len(blob)-1])
	require.Error(t, err)
	assert.ErrorIs(t, err, tumbler.ErrShortData)
}

func TestParse_EnvelopeTooLarge(t *testing.T) {
	_, err := tumbler.ParseEnvelope(make([]byte, (1<<20)+1))
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

// ---------------------------------------------------------------------------
// Crafted slots: type <-> KDF constraints and AEAD
// ---------------------------------------------------------------------------

func craftPasswordSlot() tumbler.Slot {
	return tumbler.Slot{
		Type:      tumbler.MethodPassword,
		AEADID:    tumbler.AEADChaCha20Poly1305,
		KDFID:     tumbler.KDFArgon2id,
		KDFParams: argonParams(4, 256*1024, 4),
		KDFSalt:   make([]byte, 16),
		Wrapped:   make([]byte, 48),
	}
}

func craftBlob(t *testing.T, s tumbler.Slot) []byte {
	t.Helper()
	env := tumbler.NewEnvelopeRawForTest(tumbler.PolicyPasswordOnly, []tumbler.Slot{s})
	blob, err := env.Marshal()
	require.NoError(t, err)
	return blob
}

func TestParse_PasswordSlotWithoutKDF_Rejected(t *testing.T) {
	s := craftPasswordSlot()
	s.KDFID = tumbler.KDFNone
	s.KDFParams = nil
	_, err := tumbler.ParseEnvelope(craftBlob(t, s))
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestParse_YubiKeySlotWithKDF_Rejected(t *testing.T) {
	s := craftPasswordSlot()
	s.Type = tumbler.MethodYubiKey // yubi-only must not carry a KDF
	_, err := tumbler.ParseEnvelope(craftBlob(t, s))
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

func TestParse_UnknownAEAD_Rejected(t *testing.T) {
	blob := craftBlob(t, craftPasswordSlot())
	// header(8) + bodyLen(4) + type(1) + slotID(8) + flags(1) = 22 -> aead byte
	blob[22] = 0x7F
	_, err := tumbler.ParseEnvelope(blob)
	assert.ErrorIs(t, err, tumbler.ErrUnsupportedAEAD)
}

func TestParse_WrappedTooShort_Rejected(t *testing.T) {
	s := craftPasswordSlot()
	s.Wrapped = make([]byte, 8) // < AEAD overhead (16)
	_, err := tumbler.ParseEnvelope(craftBlob(t, s))
	assert.ErrorIs(t, err, tumbler.ErrMalformed)
}

// ---------------------------------------------------------------------------
// Marshal-side field bounds
// ---------------------------------------------------------------------------

func TestMarshalMeta_FieldBounds(t *testing.T) {
	base := craftPasswordSlot()

	t.Run("challenge too long", func(t *testing.T) {
		s := base
		s.Challenge = make([]byte, 65)
		_, err := tumbler.MarshalMetaForTest(&s)
		assert.ErrorIs(t, err, tumbler.ErrMalformed)
	})
	t.Run("label too long", func(t *testing.T) {
		s := base
		s.Label = make([]byte, 257)
		_, err := tumbler.MarshalMetaForTest(&s)
		assert.ErrorIs(t, err, tumbler.ErrMalformed)
	})
	t.Run("kdf params too long", func(t *testing.T) {
		s := base
		s.KDFParams = make([]byte, 65)
		_, err := tumbler.MarshalMetaForTest(&s)
		assert.ErrorIs(t, err, tumbler.ErrMalformed)
	})
	t.Run("salt too long", func(t *testing.T) {
		s := base
		s.KDFSalt = make([]byte, 65)
		_, err := tumbler.MarshalMetaForTest(&s)
		assert.ErrorIs(t, err, tumbler.ErrMalformed)
	})
	t.Run("invalid type", func(t *testing.T) {
		s := base
		s.Type = tumbler.MethodType(0)
		_, err := tumbler.MarshalMetaForTest(&s)
		assert.ErrorIs(t, err, tumbler.ErrMalformed)
	})
}
