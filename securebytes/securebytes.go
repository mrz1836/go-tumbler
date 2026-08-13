package securebytes

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
)

// SecureBytes wraps a binary payload under three simultaneous
// protections: memory pinning (mlock), type-driven render
// redaction, and zero-on-destroy. The zero value is NOT a valid
// container — instances must be constructed via New, NewZero, or
// Clone and used through the returned pointer.
type SecureBytes struct {
	mu        sync.Mutex
	buf       []byte
	destroyed bool
}

// ErrDestroyed is returned by Use (and Clone) when invoked on a
// container whose payload has already been zeroed (whether by
// explicit Destroy or by the runtime finalizer).
//
// Callers compare via errors.Is(err, securebytes.ErrDestroyed).
var ErrDestroyed = errors.New("tumbler/securebytes: destroyed")

const redactedLiteral = "[redacted]"

var redactedJSON = []byte(`"[redacted]"`) //nolint:gochecknoglobals // pre-encoded render literal; immutable after init

// mlockFn is the active OS mlock bridge; set once at startup, replaced in tests.
var mlockFn = mlock //nolint:gochecknoglobals // OS bridge; test-hookable for mlock error-path coverage

// munlockFn is the active OS munlock bridge; set once at startup, replaced in tests.
var munlockFn = munlock //nolint:gochecknoglobals // OS bridge; test-hookable for munlock error-path coverage

// raiseOnce guards the one-time process memlock-limit raise performed
// before the first mlock in New / NewZero.
var raiseOnce sync.Once //nolint:gochecknoglobals // guards a one-time process-wide rlimit raise

// New constructs a SecureBytes wrapping a copy of b.
//
// The constructor allocates a fresh buffer, copies b into it, pins the new
// buffer in non-swappable memory (mlock), then zeroes b. After New returns, b
// contains only zero bytes and the only live copy of the original payload is
// held inside the returned container.
//
// Any length is permitted, including 0.
//
// If the host operating system refuses the swap-protection request, New
// returns nil and a wrapped errno error. When New returns an error, b is
// left untouched (still holding the caller's payload) so the caller can
// decide how to dispose of it.
//
// New also registers a runtime finalizer that calls Destroy if the returned
// reference becomes unreachable without an explicit Destroy.
func New(b []byte) (*SecureBytes, error) {
	raiseOnce.Do(raiseMemlockLimit)
	buf := make([]byte, len(b))
	copy(buf, b)
	if err := mlockFn(buf); err != nil {
		// Wipe the unlocked copy we just made; leave the caller's b intact.
		for i := range buf {
			buf[i] = 0
		}
		return nil, fmt.Errorf("tumbler/securebytes: mlock: %w", err)
	}
	for i := range b {
		b[i] = 0
	}
	sb := &SecureBytes{buf: buf}
	runtime.SetFinalizer(sb, (*SecureBytes).finalize)
	return sb, nil
}

// NewZero constructs a SecureBytes of the given size whose payload is all
// zero bytes, pinned in non-swappable memory. It is the canonical way to
// allocate a destination buffer (e.g. a fresh data key or a KEK scratch
// area) that will be filled in place via Use.
//
// size must be >= 0; a negative size returns ErrNegativeSize.
func NewZero(size int) (*SecureBytes, error) {
	if size < 0 {
		return nil, ErrNegativeSize
	}
	raiseOnce.Do(raiseMemlockLimit)
	buf := make([]byte, size)
	if err := mlockFn(buf); err != nil {
		return nil, fmt.Errorf("tumbler/securebytes: mlock: %w", err)
	}
	sb := &SecureBytes{buf: buf}
	runtime.SetFinalizer(sb, (*SecureBytes).finalize)
	return sb, nil
}

// ErrNegativeSize is returned by NewZero when asked for a negative length.
var ErrNegativeSize = errors.New("tumbler/securebytes: negative size")

// Clone returns a new, independently-owned SecureBytes holding a copy of
// this container's payload. The returned container has its own mlocked
// storage and finalizer; destroying either one does not affect the other.
//
// Returns ErrDestroyed if the source has already been destroyed.
func (sb *SecureBytes) Clone() (*SecureBytes, error) {
	var (
		out    *SecureBytes
		newErr error
	)
	if useErr := sb.Use(func(b []byte) {
		buf := make([]byte, len(b))
		copy(buf, b)
		out, newErr = New(buf) // New zeroes buf after copying into its own storage.
	}); useErr != nil {
		return nil, useErr
	}
	if newErr != nil {
		return nil, newErr
	}
	return out, nil
}

// Use invokes fn with the container's payload buffer.
//
// The buffer is the container's own mlocked storage, NOT a copy. The callback
// MUST NOT retain the slice past the call.
//
// Use returns ErrDestroyed if the container has already been destroyed. In
// that case fn is NOT invoked. A panic from fn releases the mutex and leaves
// the container live.
func (sb *SecureBytes) Use(fn func(b []byte)) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.destroyed {
		return ErrDestroyed
	}
	fn(sb.buf)
	return nil
}

// Len reports the byte length of the payload. Returns 0 after Destroy.
func (sb *SecureBytes) Len() int {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.destroyed {
		return 0
	}
	return len(sb.buf)
}

// Destroy zeroes the payload buffer and releases the swap-protection.
//
// Destroy is idempotent — calling it on an already-destroyed container is a
// no-op and returns nil.
func (sb *SecureBytes) Destroy() error {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.destroyed {
		return nil
	}
	for i := range sb.buf {
		sb.buf[i] = 0
	}
	if err := munlockFn(sb.buf); err != nil {
		sb.destroyed = true
		sb.buf = nil
		return fmt.Errorf("tumbler/securebytes: munlock: %w", err)
	}
	sb.destroyed = true
	sb.buf = nil
	runtime.KeepAlive(sb)
	return nil
}

// LogValue implements slog.LogValuer. Always returns slog.StringValue("[redacted]").
func (sb *SecureBytes) LogValue() slog.Value {
	return slog.StringValue(redactedLiteral)
}

// String implements fmt.Stringer. Always returns "[redacted]".
func (sb *SecureBytes) String() string {
	return redactedLiteral
}

// MarshalJSON implements json.Marshaler. Always returns []byte(`"[redacted]"`).
func (sb *SecureBytes) MarshalJSON() ([]byte, error) {
	return redactedJSON, nil
}

// finalize is called by the runtime finalizer set in New / NewZero.
func (sb *SecureBytes) finalize() {
	_ = sb.Destroy()
}
