package transport

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 CR is a MAC/PRF use; collision resistance is not relied upon.
	"sync"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// FakeTransport is an in-process Transport backed by an in-memory HMAC-SHA1
// secret. It is deterministic (same secret+challenge -> same response) so the
// full enroll/unlock path can be tested without hardware. Test-only —
// production code MUST NOT instantiate it.
type FakeTransport struct {
	mu      sync.Mutex
	secrets map[uint8][]byte

	// TouchFn, if set, is invoked before each response to simulate the touch
	// gate. Return a non-nil error (e.g. ErrTouchTimeout) to simulate the user
	// not touching the key.
	TouchFn func() error

	// PresentFlag is what Present reports.
	PresentFlag bool

	// SerialValue is what Serial returns.
	SerialValue string

	// ErrInject, if set, is returned by ChallengeResponse before any work.
	ErrInject error

	// Touches counts successful challenge-response calls (touch prompts).
	Touches int
}

// NewFakeTransport builds a FakeTransport with a single configured slot.
func NewFakeTransport(slot uint8, secret []byte) *FakeTransport {
	f := &FakeTransport{
		secrets:     make(map[uint8][]byte),
		PresentFlag: true,
		SerialValue: "00000000",
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	f.secrets[slot] = cp
	return f
}

// SetSlot configures (or replaces) the secret for a slot.
func (f *FakeTransport) SetSlot(slot uint8, secret []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(secret))
	copy(cp, secret)
	f.secrets[slot] = cp
}

// ChallengeResponse implements Transport with deterministic HMAC-SHA1.
func (f *FakeTransport) ChallengeResponse(ctx context.Context, slot uint8, challenge []byte) (*securebytes.SecureBytes, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.ErrInject != nil {
		return nil, f.ErrInject
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !otpSlotValid(slot) {
		return nil, ErrSlotNotConfigured
	}
	secret, ok := f.secrets[slot]
	if !ok {
		return nil, ErrSlotNotConfigured
	}
	if f.TouchFn != nil {
		if err := f.TouchFn(); err != nil {
			return nil, err
		}
	}
	mac := hmac.New(sha1.New, secret)
	mac.Write(challenge)
	sum := mac.Sum(nil) // 20 bytes
	f.Touches++
	return securebytes.New(sum)
}

// Serial implements Transport.
func (f *FakeTransport) Serial(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.SerialValue, nil
}

// Present implements Transport.
func (f *FakeTransport) Present(context.Context) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.PresentFlag
}
