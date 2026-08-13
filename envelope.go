package tumbler

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// magic is the 4-byte file signature: "TMBL".
//
//nolint:gochecknoglobals // file-format constant; immutable after init
var magic = [4]byte{'T', 'M', 'B', 'L'}

// Wire-format bounds. Every one is enforced on BOTH marshal and parse so a
// tampered or truncated file is rejected before any allocation or crypto.
const (
	maxEnvelopeLen  = 1 << 20 // 1 MiB — envelopes are tiny; this is generous.
	maxSlotCount    = 64
	headerLen       = 4 + 1 + 1 + 2 // magic + version + policyHint + slotCount
	slotFixedLen    = 1 + 8 + 1 + 1 + 1 + 1
	maxChallengeLen = 64  // HMAC-SHA1 challenge ceiling
	maxLabelLen     = 256 // human label
	maxSaltLen      = 64  // kdfSalt / chalSalt ceiling
	maxKDFParamsLen = 64
	maxWrappedLen   = maxDEKLen + wrappedOverhead // 256
	hkdfSaltLen     = 16
	nonceLen        = 12
	slotIDLen       = 8
)

// Slot is one wrapped copy of the data key, unlockable by exactly one method.
// Adding or removing a slot never touches the payload or any sibling slot.
//
// Every field except Wrapped is authenticated as AEAD associated data, so any
// edit to a slot's metadata (its type, KDF cost, stored challenge, salts,
// nonce) breaks that slot's tag and surfaces as a uniform ErrAuthFailed —
// downgrade-evident by construction.
type Slot struct {
	Type      MethodType
	ID        [8]byte
	Flags     uint8
	AEADID    AEADID
	KDFID     KDFID
	YKSlot    uint8
	KDFParams []byte
	KDFSalt   []byte
	ChalSalt  []byte
	HKDFSalt  [hkdfSaltLen]byte
	Challenge []byte
	Label     []byte
	Nonce     [nonceLen]byte
	Wrapped   []byte

	// meta holds the exact serialized metadata bytes used as the AEAD AAD.
	// On enroll it is produced by marshalMeta; on parse it is copied verbatim
	// from the input so unlock verifies against byte-identical AAD.
	meta []byte
}

// SlotInfo is the non-secret view of a slot for listing in CLIs.
type SlotInfo struct {
	ID    [8]byte
	Type  MethodType
	Label string
}

// Envelope is a set of independent keyslots wrapping one data key.
type Envelope struct {
	version    uint8
	policyHint Policy
	slots      []Slot
}

// Method wraps the data key into a Slot (Enroll) and recovers it from a Slot
// (Unlock). Implementations MUST hold every secret in securebytes and MUST
// collapse all unlock failures to ErrAuthFailed so nothing leaks about which
// check failed.
type Method interface {
	Type() MethodType
	Enroll(ctx context.Context, dek *securebytes.SecureBytes) (Slot, error)
	Unlock(ctx context.Context, slot Slot) (*securebytes.SecureBytes, error)
}

// NewEnvelope wraps dek once per method and returns the sealed envelope. The
// declared policy must match the policy implied by the enrolled primary slots
// (EffectivePolicy); a mismatch is rejected. dek is not consumed — the caller
// still owns and must Destroy it.
func NewEnvelope(ctx context.Context, dek *securebytes.SecureBytes, policy Policy, methods ...Method) (*Envelope, error) {
	if len(methods) == 0 {
		return nil, ErrNoMethods
	}
	if !policy.valid() {
		return nil, fmt.Errorf("%w: %d", ErrPolicyMismatch, policy)
	}
	if n := dek.Len(); n == 0 || n > maxDEKLen {
		return nil, fmt.Errorf("%w: %d", ErrDEKSize, n)
	}
	slots := make([]Slot, 0, len(methods))
	for _, m := range methods {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		slot, err := m.Enroll(ctx, dek)
		if err != nil {
			return nil, err
		}
		slots = append(slots, slot)
	}
	env := &Envelope{version: FormatVersion, policyHint: policy, slots: slots}
	if eff := env.EffectivePolicy(); eff != policy {
		return nil, fmt.Errorf("%w: declared %s, slots imply %s", ErrPolicyMismatch, policy, eff)
	}
	return env, nil
}

// Unlock tries each slot against every method whose Type matches the slot's,
// returning the data key from the first slot that opens. On total failure it
// returns the single uniform ErrAuthFailed. The returned key is owned by the
// caller and must be Destroyed.
func (e *Envelope) Unlock(ctx context.Context, methods ...Method) (*securebytes.SecureBytes, error) {
	if len(methods) == 0 {
		return nil, ErrNoMethods
	}
	for i := range e.slots {
		slot := e.slots[i]
		for _, m := range methods {
			if m.Type() != slot.Type {
				continue
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			dek, err := m.Unlock(ctx, slot)
			if err == nil {
				return dek, nil
			}
			// A wrong secret / tampered slot is uniform ErrAuthFailed — keep
			// trying other slots. An operational failure (no device, touch
			// timeout, mlock error) reveals nothing secret and must surface
			// immediately so the caller can act on it.
			if !errors.Is(err, ErrAuthFailed) {
				return nil, err
			}
		}
	}
	return nil, ErrAuthFailed
}

// AddSlot wraps dek under one more method and appends the slot — the O(1)
// path for enrolling a backup YubiKey or a printed recovery code. A
// non-recovery slot must match the envelope's current EffectivePolicy;
// recovery slots are always permitted.
func (e *Envelope) AddSlot(ctx context.Context, dek *securebytes.SecureBytes, m Method) error {
	if n := dek.Len(); n == 0 || n > maxDEKLen {
		return fmt.Errorf("%w: %d", ErrDEKSize, n)
	}
	if len(e.slots) >= maxSlotCount {
		return fmt.Errorf("%w: slot count at maximum %d", ErrMalformed, maxSlotCount)
	}
	if m.Type() != MethodRecovery {
		if eff := e.EffectivePolicy(); policyForMethod(m.Type()) != eff {
			return fmt.Errorf("%w: adding %s to a %s envelope", ErrPolicyMismatch, m.Type(), eff)
		}
	}
	slot, err := m.Enroll(ctx, dek)
	if err != nil {
		return err
	}
	e.slots = append(e.slots, slot)
	return nil
}

// RemoveSlot deletes the slot with the given ID. It refuses to remove the
// only remaining slot (which would render the envelope permanently
// unopenable). Removing a slot protects only THIS file; a possibly-compromised
// key is truly revoked only by rotating the data key — see SECURITY.md.
func (e *Envelope) RemoveSlot(id [8]byte) error {
	idx := -1
	for i := range e.slots {
		if e.slots[i].ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return ErrSlotNotFound
	}
	if len(e.slots) <= 1 {
		return fmt.Errorf("%w: cannot remove the only slot", ErrPolicyUnsafe)
	}
	e.slots = append(e.slots[:idx], e.slots[idx+1:]...)
	return nil
}

// EffectivePolicy derives the policy from the enrolled slots, ignoring
// recovery slots (an intentional escape hatch present under any policy). It
// returns the policy shared by all primary slots, or PolicyInvalid if there
// are no primary slots or they disagree (only reachable via tampering or
// misuse). Enforcement compares this against the caller's expected policy;
// never trust the advisory header byte.
func (e *Envelope) EffectivePolicy() Policy {
	derived := PolicyInvalid
	seen := false
	for i := range e.slots {
		if e.slots[i].Type == MethodRecovery {
			continue
		}
		p := policyForMethod(e.slots[i].Type)
		if !seen {
			derived, seen = p, true
			continue
		}
		if p != derived {
			return PolicyInvalid
		}
	}
	if !seen {
		return PolicyInvalid
	}
	return derived
}

// PolicyHint returns the advisory policy byte from the header. Prefer
// EffectivePolicy for any enforcement decision.
func (e *Envelope) PolicyHint() Policy { return e.policyHint }

// Version returns the envelope's format version.
func (e *Envelope) Version() uint8 { return e.version }

// SlotInfos returns the non-secret metadata of each slot, in file order.
func (e *Envelope) SlotInfos() []SlotInfo {
	out := make([]SlotInfo, len(e.slots))
	for i := range e.slots {
		out[i] = SlotInfo{ID: e.slots[i].ID, Type: e.slots[i].Type, Label: string(e.slots[i].Label)}
	}
	return out
}

// SlotCount returns the number of enrolled slots.
func (e *Envelope) SlotCount() int { return len(e.slots) }

// ---------------------------------------------------------------------------
// marshal
// ---------------------------------------------------------------------------

// marshalMeta serializes a slot's authenticated metadata (everything except
// Wrapped). The output is BOTH written to disk and used as the AEAD AAD, so
// the two can never disagree. It validates every field length against the
// wire bounds.
func marshalMeta(s *Slot) ([]byte, error) {
	if !s.Type.valid() {
		return nil, fmt.Errorf("%w: slot type %d", ErrMalformed, s.Type)
	}
	if s.AEADID != AEADChaCha20Poly1305 {
		return nil, fmt.Errorf("%w: aead %d", ErrUnsupportedAEAD, s.AEADID)
	}
	if len(s.KDFParams) > maxKDFParamsLen {
		return nil, fmt.Errorf("%w: kdfParams len %d", ErrMalformed, len(s.KDFParams))
	}
	if len(s.KDFSalt) > maxSaltLen || len(s.ChalSalt) > maxSaltLen {
		return nil, fmt.Errorf("%w: salt too long", ErrMalformed)
	}
	if len(s.Challenge) > maxChallengeLen {
		return nil, fmt.Errorf("%w: challenge len %d", ErrMalformed, len(s.Challenge))
	}
	if len(s.Label) > maxLabelLen {
		return nil, fmt.Errorf("%w: label len %d", ErrMalformed, len(s.Label))
	}

	var b []byte
	b = append(b, byte(s.Type))
	b = append(b, s.ID[:]...)
	b = append(b, s.Flags, byte(s.AEADID), byte(s.KDFID), s.YKSlot)
	b = appendU16Bytes(b, s.KDFParams)
	b = appendU16Bytes(b, s.KDFSalt)
	b = appendU16Bytes(b, s.ChalSalt)
	b = append(b, s.HKDFSalt[:]...)
	b = appendU16Bytes(b, s.Challenge)
	b = appendU16Bytes(b, s.Label)
	b = append(b, s.Nonce[:]...)
	return b, nil
}

// Marshal serializes the envelope to its versioned wire form.
func (e *Envelope) Marshal() ([]byte, error) {
	if len(e.slots) == 0 {
		return nil, fmt.Errorf("%w: empty envelope", ErrMalformed)
	}
	if len(e.slots) > maxSlotCount {
		return nil, fmt.Errorf("%w: slot count %d", ErrMalformed, len(e.slots))
	}

	out := make([]byte, 0, headerLen+len(e.slots)*128)
	out = append(out, magic[:]...)
	out = append(out, e.version, byte(e.policyHint))
	out = binary.BigEndian.AppendUint16(out, uint16(len(e.slots))) //nolint:gosec // G115: slot count is bounded by maxSlotCount (64)

	for i := range e.slots {
		s := &e.slots[i]
		if len(s.Wrapped) == 0 || len(s.Wrapped) > maxWrappedLen {
			return nil, fmt.Errorf("%w: wrapped len %d", ErrMalformed, len(s.Wrapped))
		}
		meta := s.meta
		if meta == nil {
			m, err := marshalMeta(s)
			if err != nil {
				return nil, err
			}
			meta = m
		}
		body := make([]byte, 0, len(meta)+len(s.Wrapped))
		body = append(body, meta...)
		body = append(body, s.Wrapped...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(body))) //nolint:gosec // G115: body length is bounded by maxEnvelopeLen
		out = append(out, body...)
		if len(out) > maxEnvelopeLen {
			return nil, fmt.Errorf("%w: envelope exceeds %d", ErrMalformed, maxEnvelopeLen)
		}
	}
	return out, nil
}

// appendU16Bytes appends a uint16 length prefix followed by b.
func appendU16Bytes(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(b))) //nolint:gosec // G115: field lengths are validated <= their max in marshalMeta
	return append(dst, b...)
}

// ---------------------------------------------------------------------------
// parse
// ---------------------------------------------------------------------------

// reader is a bounds-checked forward cursor over the envelope bytes. Every
// accessor returns ErrShortData on overrun; nothing ever indexes past the
// buffer.
type reader struct {
	b   []byte
	off int
}

func (r *reader) u8() (uint8, error) {
	if r.off+1 > len(r.b) {
		return 0, ErrShortData
	}
	v := r.b[r.off]
	r.off++
	return v, nil
}

func (r *reader) u16() (uint16, error) {
	if r.off+2 > len(r.b) {
		return 0, ErrShortData
	}
	v := binary.BigEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v, nil
}

func (r *reader) u32() (uint32, error) {
	if r.off+4 > len(r.b) {
		return 0, ErrShortData
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, nil
}

// take returns a COPY of the next n bytes (never an alias of the input).
func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.off+n > len(r.b) {
		return nil, ErrShortData
	}
	out := make([]byte, n)
	copy(out, r.b[r.off:r.off+n])
	r.off += n
	return out, nil
}

// takeU16 reads a uint16 length then that many bytes (copied), bounded by max.
func (r *reader) takeU16(maxLen int) ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	if int(n) > maxLen {
		return nil, fmt.Errorf("%w: field len %d exceeds %d", ErrMalformed, n, maxLen)
	}
	return r.take(int(n))
}

// ParseEnvelope validates and decodes an envelope. It performs only
// structural and bounds checks — no cryptography — and rejects anything
// malformed with ErrBadMagic / ErrBadVersion / ErrShortData / ErrMalformed.
func ParseEnvelope(b []byte) (*Envelope, error) {
	if len(b) > maxEnvelopeLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrMalformed, len(b))
	}
	if len(b) < headerLen {
		return nil, fmt.Errorf("%w: header", ErrShortData)
	}
	if b[0] != magic[0] || b[1] != magic[1] || b[2] != magic[2] || b[3] != magic[3] {
		return nil, ErrBadMagic
	}
	if b[4] != FormatVersion {
		return nil, fmt.Errorf("%w: %d", ErrBadVersion, b[4])
	}
	policy := Policy(b[5])
	slotCount := binary.BigEndian.Uint16(b[6:8])
	if slotCount == 0 || int(slotCount) > maxSlotCount {
		return nil, fmt.Errorf("%w: slot count %d", ErrMalformed, slotCount)
	}

	r := &reader{b: b, off: headerLen}
	slots := make([]Slot, 0, slotCount)
	for i := range int(slotCount) {
		slot, err := parseSlot(r)
		if err != nil {
			return nil, fmt.Errorf("slot %d: %w", i, err)
		}
		slots = append(slots, slot)
	}
	if r.off != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(b)-r.off)
	}
	return &Envelope{version: b[4], policyHint: policy, slots: slots}, nil
}

// parseSlot decodes one length-prefixed slot and validates its internal
// structure (type↔KDF constraints, AEAD, KDF-parameter bounds).
//
//nolint:gocyclo,gocognit // one linear field-by-field decode; complexity is structural.
func parseSlot(r *reader) (Slot, error) {
	bodyLen, err := r.u32()
	if err != nil {
		return Slot{}, err
	}
	if int(bodyLen) < slotFixedLen || int(bodyLen) > maxEnvelopeLen {
		return Slot{}, fmt.Errorf("%w: slot body len %d", ErrMalformed, bodyLen)
	}
	if r.off+int(bodyLen) > len(r.b) {
		return Slot{}, ErrShortData
	}
	metaStart := r.off
	body := &reader{b: r.b[:r.off+int(bodyLen)], off: r.off}

	var s Slot
	t, err := body.u8()
	if err != nil {
		return Slot{}, err
	}
	s.Type = MethodType(t)
	if !s.Type.valid() {
		return Slot{}, fmt.Errorf("%w: slot type %d", ErrMalformed, t)
	}
	id, err := body.take(slotIDLen)
	if err != nil {
		return Slot{}, err
	}
	copy(s.ID[:], id)
	if s.Flags, err = body.u8(); err != nil {
		return Slot{}, err
	}
	aeadID, err := body.u8()
	if err != nil {
		return Slot{}, err
	}
	s.AEADID = AEADID(aeadID)
	if s.AEADID != AEADChaCha20Poly1305 {
		return Slot{}, fmt.Errorf("%w: %d", ErrUnsupportedAEAD, aeadID)
	}
	kdfID, err := body.u8()
	if err != nil {
		return Slot{}, err
	}
	s.KDFID = KDFID(kdfID)
	if s.YKSlot, err = body.u8(); err != nil {
		return Slot{}, err
	}
	if s.KDFParams, err = body.takeU16(maxKDFParamsLen); err != nil {
		return Slot{}, err
	}
	if s.KDFSalt, err = body.takeU16(maxSaltLen); err != nil {
		return Slot{}, err
	}
	if s.ChalSalt, err = body.takeU16(maxSaltLen); err != nil {
		return Slot{}, err
	}
	hs, err := body.take(hkdfSaltLen)
	if err != nil {
		return Slot{}, err
	}
	copy(s.HKDFSalt[:], hs)
	if s.Challenge, err = body.takeU16(maxChallengeLen); err != nil {
		return Slot{}, err
	}
	if s.Label, err = body.takeU16(maxLabelLen); err != nil {
		return Slot{}, err
	}
	nn, err := body.take(nonceLen)
	if err != nil {
		return Slot{}, err
	}
	copy(s.Nonce[:], nn)

	// The metadata is everything consumed so far; capture it verbatim as AAD.
	metaEnd := body.off
	s.meta = make([]byte, metaEnd-metaStart)
	copy(s.meta, r.b[metaStart:metaEnd])

	// The remainder of the body is the wrapped data key.
	wrapped := body.b[body.off:]
	if len(wrapped) < wrappedOverhead || len(wrapped) > maxWrappedLen {
		return Slot{}, fmt.Errorf("%w: wrapped len %d", ErrMalformed, len(wrapped))
	}
	s.Wrapped = make([]byte, len(wrapped))
	copy(s.Wrapped, wrapped)

	if err = validateSlotShape(&s); err != nil {
		return Slot{}, err
	}

	r.off += int(bodyLen)
	return s, nil
}

// validateSlotShape enforces the type↔KDF invariants and pre-validates KDF
// parameters (bounds) so a tampered file is rejected at parse, before any
// expensive derivation is attempted at unlock.
func validateSlotShape(s *Slot) error {
	switch s.Type {
	case MethodPassword, MethodPasswordAndYubiKey:
		if s.KDFID == KDFNone {
			return fmt.Errorf("%w: %s slot requires a KDF", ErrMalformed, s.Type)
		}
	case MethodYubiKey, MethodRecovery:
		if s.KDFID != KDFNone {
			return fmt.Errorf("%w: %s slot must not carry a KDF", ErrMalformed, s.Type)
		}
	}
	// Validate KDF id + parameter bounds now (cheap; rejects DoS params early).
	if _, err := parseKDF(s.KDFID, s.KDFParams); err != nil {
		return err
	}
	return nil
}
