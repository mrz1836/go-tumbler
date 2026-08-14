package tumbler

import (
	"crypto/rand"
	"fmt"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// Option configures an unlock method at construction time.
type Option func(*methodOptions)

// methodOptions holds the resolved optional settings shared by all methods.
type methodOptions struct {
	label         []byte
	touchAnnounce func()
}

// WithLabel attaches a short, non-secret human label to a slot (e.g.
// "backup-key", "recovery-code"). Labels are stored in — and authenticated
// by — the slot and surface via Envelope.SlotInfos.
func WithLabel(label string) Option {
	return func(o *methodOptions) { o.label = []byte(label) }
}

// WithTouchAnnounce registers a callback invoked immediately before the
// YubiKey is asked for a response — i.e. at the exact moment the key begins
// blinking for a touch. Apps use it to print a "touch your key now" prompt at
// the right moment (after any password prompt and key derivation), rather than
// too early. It is a no-op for non-YubiKey methods.
func WithTouchAnnounce(fn func()) Option {
	return func(o *methodOptions) { o.touchAnnounce = fn }
}

// applyOptions resolves opts, falling back to the supplied default label.
func applyOptions(defaultLabel string, opts []Option) methodOptions {
	o := methodOptions{label: []byte(defaultLabel)}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// randRead is the active randomness source; crypto/rand.Read in production,
// replaced in tests to produce deterministic golden envelopes and to cover
// rand-failure paths.
var randRead = rand.Read //nolint:gochecknoglobals // RNG bridge; test-hookable

// sbNew / sbNewZero are securebytes constructor bridges, replaceable in tests
// to cover the (rare) mlock-failure paths that would otherwise be
// unreachable. Same pattern as hush's sbNewFromUnmarshal bridge.
var (
	sbNew     = securebytes.New     //nolint:gochecknoglobals // securebytes bridge; test-hookable
	sbNewZero = securebytes.NewZero //nolint:gochecknoglobals // securebytes bridge; test-hookable
)

// randFill fills b with cryptographically secure random bytes.
func randFill(b []byte) error {
	if _, err := randRead(b); err != nil {
		return fmt.Errorf("tumbler: rand: %w", err)
	}
	return nil
}

// randBytes returns n fresh random bytes.
func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if err := randFill(b); err != nil {
		return nil, err
	}
	return b, nil
}

// slotShape carries the non-random, method-specific fields needed to build a
// slot. The random fields (slot ID, HKDF salt, nonce) are generated inside
// wrapDEK so every enroll and rewrap is single-use by construction.
type slotShape struct {
	mt        MethodType
	kdfID     KDFID
	kdfParams []byte
	kdfSalt   []byte
	chalSalt  []byte
	challenge []byte
	ykSlot    uint8
	label     []byte
}

// wrapDEK builds a fresh sealed slot: it generates a random slot ID, a
// single-use HKDF-Extract salt, and a fresh nonce; derives the KEK from the
// supplied IKM inputs; and seals dek with the slot metadata as AAD. The KEK
// is zeroed before return. The caller retains ownership of both dek and the
// secrets inside `in`.
func wrapDEK(dek *securebytes.SecureBytes, in ikmInputs, sh slotShape) (Slot, error) {
	s := Slot{
		Type:      sh.mt,
		AEADID:    AEADChaCha20Poly1305,
		KDFID:     sh.kdfID,
		YKSlot:    sh.ykSlot,
		KDFParams: sh.kdfParams,
		KDFSalt:   sh.kdfSalt,
		ChalSalt:  sh.chalSalt,
		Challenge: sh.challenge,
		Label:     sh.label,
	}
	if err := randFill(s.ID[:]); err != nil {
		return Slot{}, err
	}
	if err := randFill(s.HKDFSalt[:]); err != nil {
		return Slot{}, err
	}
	if err := randFill(s.Nonce[:]); err != nil {
		return Slot{}, err
	}

	meta, err := marshalMeta(&s)
	if err != nil {
		return Slot{}, err
	}

	kek, err := deriveKEK(in, s.HKDFSalt[:], FormatVersion, s.Type, s.ID)
	if err != nil {
		return Slot{}, err
	}
	defer func() { _ = kek.Destroy() }()

	wrapped, err := seal(kek, dek, s.Nonce[:], meta)
	if err != nil {
		return Slot{}, err
	}
	s.Wrapped = wrapped
	s.meta = meta
	return s, nil
}

// unwrapDEK reconstructs the slot's KEK from the supplied IKM inputs and opens
// the wrapped data key. A wrong secret or tampered slot surfaces as
// ErrAuthFailed (from open); system failures (allocation, KDF) surface as
// themselves. The returned key is owned by the caller.
func unwrapDEK(slot Slot, in ikmInputs) (*securebytes.SecureBytes, error) {
	kek, err := deriveKEK(in, slot.HKDFSalt[:], FormatVersion, slot.Type, slot.ID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = kek.Destroy() }()

	meta := slot.meta
	if meta == nil {
		if meta, err = marshalMeta(&slot); err != nil {
			return nil, err
		}
	}
	return open(kek, slot.Nonce[:], slot.Wrapped, meta)
}
