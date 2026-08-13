package tumbler_test

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/securebytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// copyOut borrows a SecureBytes and returns a plain copy for comparison.
func copyOut(t *testing.T, sb *securebytes.SecureBytes) []byte {
	t.Helper()
	var out []byte
	require.NoError(t, sb.Use(func(b []byte) { out = append([]byte(nil), b...) }))
	return out
}

// ---------------------------------------------------------------------------
// IKM construction is unambiguous across roles
// ---------------------------------------------------------------------------

func TestBuildIKM_RolesAreUnambiguous(t *testing.T) {
	same := []byte("identical-secret-bytes-32-xxxxxx")

	pwOnly, err := tumbler.BuildIKMForTest(newSecret(t, same), nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pwOnly.Destroy() })

	ykOnly, err := tumbler.BuildIKMForTest(nil, newSecret(t, same), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ykOnly.Destroy() })

	rcOnly, err := tumbler.BuildIKMForTest(nil, nil, newSecret(t, same))
	require.NoError(t, err)
	t.Cleanup(func() { _ = rcOnly.Destroy() })

	twoFA, err := tumbler.BuildIKMForTest(newSecret(t, same), newSecret(t, same), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = twoFA.Destroy() })

	a, b, c, d := copyOut(t, pwOnly), copyOut(t, ykOnly), copyOut(t, rcOnly), copyOut(t, twoFA)
	// Despite identical secret bytes, every role combination yields a
	// structurally distinct IKM — no cross-role collision is possible.
	assert.NotEqual(t, a, b)
	assert.NotEqual(t, a, c)
	assert.NotEqual(t, b, c)
	assert.NotEqual(t, a, d)
	assert.NotEqual(t, b, d)
}

// ---------------------------------------------------------------------------
// deriveKEK matches the documented spec (independent HKDF cross-check)
// ---------------------------------------------------------------------------

func TestDeriveKEK_MatchesSpec(t *testing.T) {
	pkBytes := []byte("password-key-0123456789abcdef012")
	hkdfSalt := make([]byte, 16)
	for i := range hkdfSalt {
		hkdfSalt[i] = byte(0xA0 + i)
	}
	slotID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	kek, err := tumbler.DeriveKEKForTest(newSecret(t, pkBytes), nil, nil, hkdfSalt, tumbler.FormatVersion, tumbler.MethodPassword, slotID)
	require.NoError(t, err)
	t.Cleanup(func() { _ = kek.Destroy() })
	got := copyOut(t, kek)

	// Independent recomputation of the exact IKM layout + HKDF.
	ikm := []byte("tumbler/v1 ikm")
	ikm = append(ikm, 1) // password present
	ikm = binary.BigEndian.AppendUint16(ikm, uint16(len(pkBytes)))
	ikm = append(ikm, pkBytes...)
	ikm = append(ikm, 0, 0, 0) // yubiResp absent (present=0, len=0)
	ikm = append(ikm, 0, 0, 0) // recovery absent
	prk, err := hkdf.Extract(sha256.New, ikm, hkdfSalt)
	require.NoError(t, err)
	info := append([]byte("tumbler/v1 kek"), tumbler.FormatVersion, byte(tumbler.MethodPassword))
	info = append(info, slotID[:]...)
	want, err := hkdf.Expand(sha256.New, prk, string(info), 32)
	require.NoError(t, err)

	assert.Equal(t, want, got)
	assert.Len(t, got, 32)
}

// TestDeriveKEK_FrozenKAT pins the derivation so an accidental change to the
// IKM layout, labels, or HKDF wiring is caught immediately.
func TestDeriveKEK_FrozenKAT(t *testing.T) {
	pk := make([]byte, 32) // all-zero pk
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	slotID := [8]byte{} // all-zero slot id

	kek, err := tumbler.DeriveKEKForTest(newSecret(t, pk), nil, nil, salt, 1, tumbler.MethodPassword, slotID)
	require.NoError(t, err)
	t.Cleanup(func() { _ = kek.Destroy() })

	const want = "e0d4ce8d28fd5abcce621b3443620b35484bbfc3b1402af5d284f5ee02669eb4"
	// The KAT value is asserted below; if the construction is ever changed
	// intentionally, regenerate it deliberately (and bump FormatVersion).
	got := hex.EncodeToString(copyOut(t, kek))
	assert.Equal(t, want, got, "KEK derivation KAT changed — verify this was intentional")
}

// ---------------------------------------------------------------------------
// seal / open
// ---------------------------------------------------------------------------

func TestSealOpen_RoundTrip(t *testing.T) {
	kek := newSecret(t, make32(0x11))
	dekBytes := []byte("the-data-key-payload-0123456789!")
	dek := newSecret(t, dekBytes)
	nonce := make([]byte, 12)
	aad := []byte("slot-metadata-aad")

	ct, err := tumbler.SealForTest(kek, dek, nonce, aad)
	require.NoError(t, err)
	assert.Len(t, ct, len(dekBytes)+16)

	out, err := tumbler.OpenForTest(kek, nonce, ct, aad)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Destroy() })
	requireSecretEquals(t, out, dekBytes)
}

func TestSealOpen_TamperedAAD(t *testing.T) {
	kek := newSecret(t, make32(0x22))
	dek := newSecret(t, []byte("payload"))
	nonce := make([]byte, 12)

	ct, err := tumbler.SealForTest(kek, dek, nonce, []byte("aad-original"))
	require.NoError(t, err)

	_, err = tumbler.OpenForTest(kek, nonce, ct, []byte("aad-modified"))
	assert.ErrorIs(t, err, tumbler.ErrAuthFailed)
}

func TestSealOpen_TamperedCiphertext(t *testing.T) {
	kek := newSecret(t, make32(0x33))
	dek := newSecret(t, []byte("payload-xyz"))
	nonce := make([]byte, 12)
	aad := []byte("aad")

	ct, err := tumbler.SealForTest(kek, dek, nonce, aad)
	require.NoError(t, err)
	ct[0] ^= 0xFF

	_, err = tumbler.OpenForTest(kek, nonce, ct, aad)
	assert.ErrorIs(t, err, tumbler.ErrAuthFailed)
}

func TestSealOpen_WrongKEK(t *testing.T) {
	dek := newSecret(t, []byte("payload"))
	nonce := make([]byte, 12)
	aad := []byte("aad")

	ct, err := tumbler.SealForTest(newSecret(t, make32(0x44)), dek, nonce, aad)
	require.NoError(t, err)

	_, err = tumbler.OpenForTest(newSecret(t, make32(0x45)), nonce, ct, aad)
	assert.ErrorIs(t, err, tumbler.ErrAuthFailed)
}

// make32 returns a 32-byte slice filled with v.
func make32(v byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return b
}
