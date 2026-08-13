package tumbler

import "github.com/mrz1836/go-tumbler/securebytes"

// SetRandRead swaps the package RNG for deterministic tests. Returns a
// cleanup that restores crypto/rand.
func SetRandRead(f func([]byte) (int, error)) func() {
	orig := randRead
	randRead = f
	return func() { randRead = orig }
}

// SetSBNew swaps the securebytes.New bridge to cover mlock-failure paths.
func SetSBNew(f func([]byte) (*securebytes.SecureBytes, error)) func() {
	orig := sbNew
	sbNew = f
	return func() { sbNew = orig }
}

// SetSBNewZero swaps the securebytes.NewZero bridge to cover mlock-failure paths.
func SetSBNewZero(f func(int) (*securebytes.SecureBytes, error)) func() {
	orig := sbNewZero
	sbNewZero = f
	return func() { sbNewZero = orig }
}

// DeriveKEKForTest exposes deriveKEK for KATs and cross-checks.
func DeriveKEKForTest(pk, yr, rc *securebytes.SecureBytes, hkdfSalt []byte, version uint8, mt MethodType, slotID [8]byte) (*securebytes.SecureBytes, error) {
	return deriveKEK(ikmInputs{password: pk, yubiResp: yr, recovery: rc}, hkdfSalt, version, mt, slotID)
}

// BuildIKMForTest exposes buildIKM for unambiguity tests.
func BuildIKMForTest(pk, yr, rc *securebytes.SecureBytes) (*securebytes.SecureBytes, error) {
	return buildIKM(ikmInputs{password: pk, yubiResp: yr, recovery: rc})
}

// SealForTest / OpenForTest expose the AEAD layer.
func SealForTest(kek, dek *securebytes.SecureBytes, nonce, aad []byte) ([]byte, error) {
	return seal(kek, dek, nonce, aad)
}

func OpenForTest(kek *securebytes.SecureBytes, nonce, ciphertext, aad []byte) (*securebytes.SecureBytes, error) {
	return open(kek, nonce, ciphertext, aad)
}

// ParseKDFForTest exposes parseKDF for bounds tests.
func ParseKDFForTest(id KDFID, params []byte) (KDF, error) { return parseKDF(id, params) }

// MarshalMetaForTest exposes marshalMeta for AAD tests.
func MarshalMetaForTest(s *Slot) ([]byte, error) { return marshalMeta(s) }

// Meta returns the captured AAD bytes of a slot (nil until enrolled/parsed).
func (s *Slot) Meta() []byte { return s.meta }

// SlotsForTest returns a shallow copy of the envelope's slots for inspection.
func (e *Envelope) SlotsForTest() []Slot {
	out := make([]Slot, len(e.slots))
	copy(out, e.slots)
	return out
}

// SetSlotsForTest replaces the envelope's slots (for constructing malformed
// in-memory envelopes in tests).
func (e *Envelope) SetSlotsForTest(slots []Slot) { e.slots = slots }

// NewEnvelopeRawForTest builds an envelope directly from slots, bypassing
// enrollment and policy coherence — used to exercise Marshal/Parse edge cases.
func NewEnvelopeRawForTest(policyHint Policy, slots []Slot) *Envelope {
	return &Envelope{version: FormatVersion, policyHint: policyHint, slots: slots}
}
