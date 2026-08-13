package securebytes_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"testing"

	"github.com/mrz1836/go-tumbler/securebytes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// New
// ---------------------------------------------------------------------------

func TestNew_CopiesAndZeroesSource(t *testing.T) {
	src := []byte("super-secret-material")
	want := append([]byte(nil), src...)

	sb, err := securebytes.New(src)
	require.NoError(t, err)
	require.NotNil(t, sb)
	t.Cleanup(func() { _ = sb.Destroy() })

	// Source must be zeroed after New returns.
	for i, b := range src {
		assert.Equalf(t, byte(0), b, "src[%d] not zeroed", i)
	}

	// Payload must equal the original bytes and be independent of src.
	require.NoError(t, sb.Use(func(b []byte) {
		assert.Equal(t, want, b)
	}))
	assert.Equal(t, len(want), sb.Len())
}

func TestNew_EmptyPayload(t *testing.T) {
	sb, err := securebytes.New([]byte{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })
	assert.Equal(t, 0, sb.Len())
	require.NoError(t, sb.Use(func(b []byte) {
		assert.Empty(t, b)
	}))
}

func TestNew_NilPayload(t *testing.T) {
	sb, err := securebytes.New(nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })
	assert.Equal(t, 0, sb.Len())
}

func TestNew_PayloadIsIndependentCopy(t *testing.T) {
	src := []byte{1, 2, 3, 4}
	sb, err := securebytes.New(src)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })

	// Mutating the payload inside Use must not touch any external slice.
	require.NoError(t, sb.Use(func(b []byte) { b[0] = 0xFF }))
	require.NoError(t, sb.Use(func(b []byte) { assert.Equal(t, byte(0xFF), b[0]) }))
	// src is already zeroed; prove it stayed zeroed.
	assert.Equal(t, []byte{0, 0, 0, 0}, src)
}

func TestNew_MLockFailure_LeavesSourceIntact(t *testing.T) {
	sentinel := errors.New("mlock boom")
	restore := securebytes.SetMLock(func([]byte) error { return sentinel })
	defer restore()

	src := []byte("keep-me-on-failure")
	snapshot := append([]byte(nil), src...)

	sb, err := securebytes.New(src)
	require.Error(t, err)
	assert.Nil(t, sb)
	assert.ErrorIs(t, err, sentinel)
	// On failure the caller's buffer must be left untouched so the caller
	// can decide how to dispose of it.
	assert.Equal(t, snapshot, src)
}

// ---------------------------------------------------------------------------
// NewZero
// ---------------------------------------------------------------------------

func TestNewZero_AllZero(t *testing.T) {
	sb, err := securebytes.NewZero(32)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })
	assert.Equal(t, 32, sb.Len())
	require.NoError(t, sb.Use(func(b []byte) {
		assert.Equal(t, make([]byte, 32), b)
	}))
}

func TestNewZero_Zero(t *testing.T) {
	sb, err := securebytes.NewZero(0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })
	assert.Equal(t, 0, sb.Len())
}

func TestNewZero_Negative(t *testing.T) {
	sb, err := securebytes.NewZero(-1)
	require.Error(t, err)
	assert.Nil(t, sb)
	assert.ErrorIs(t, err, securebytes.ErrNegativeSize)
}

func TestNewZero_MLockFailure(t *testing.T) {
	sentinel := errors.New("mlock boom")
	restore := securebytes.SetMLock(func([]byte) error { return sentinel })
	defer restore()

	sb, err := securebytes.NewZero(16)
	require.Error(t, err)
	assert.Nil(t, sb)
	assert.ErrorIs(t, err, sentinel)
}

func TestNewZero_FillInPlace(t *testing.T) {
	sb, err := securebytes.NewZero(4)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })
	require.NoError(t, sb.Use(func(b []byte) {
		copy(b, []byte{9, 8, 7, 6})
	}))
	require.NoError(t, sb.Use(func(b []byte) {
		assert.Equal(t, []byte{9, 8, 7, 6}, b)
	}))
}

// ---------------------------------------------------------------------------
// Clone
// ---------------------------------------------------------------------------

func TestClone_IndependentCopy(t *testing.T) {
	sb, err := securebytes.New([]byte("clone-me"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })

	clone, err := sb.Clone()
	require.NoError(t, err)
	t.Cleanup(func() { _ = clone.Destroy() })

	require.NoError(t, clone.Use(func(b []byte) {
		assert.Equal(t, []byte("clone-me"), b)
	}))

	// Destroying the clone must not touch the source.
	require.NoError(t, clone.Destroy())
	require.NoError(t, sb.Use(func(b []byte) {
		assert.Equal(t, []byte("clone-me"), b)
	}))
}

func TestClone_SourceUnaffectedByCloneMutation(t *testing.T) {
	sb, err := securebytes.New([]byte{1, 1, 1, 1})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })

	clone, err := sb.Clone()
	require.NoError(t, err)
	t.Cleanup(func() { _ = clone.Destroy() })

	require.NoError(t, clone.Use(func(b []byte) { b[0] = 0xEE }))
	require.NoError(t, sb.Use(func(b []byte) { assert.Equal(t, byte(1), b[0]) }))
}

func TestClone_OfDestroyed(t *testing.T) {
	sb, err := securebytes.New([]byte("x"))
	require.NoError(t, err)
	require.NoError(t, sb.Destroy())

	clone, err := sb.Clone()
	require.Error(t, err)
	assert.Nil(t, clone)
	assert.ErrorIs(t, err, securebytes.ErrDestroyed)
}

func TestClone_MLockFailure(t *testing.T) {
	sb, err := securebytes.New([]byte("y"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })

	sentinel := errors.New("mlock boom")
	restore := securebytes.SetMLock(func([]byte) error { return sentinel })
	defer restore()

	clone, err := sb.Clone()
	require.Error(t, err)
	assert.Nil(t, clone)
	assert.ErrorIs(t, err, sentinel)
	// Source must still be usable after a failed clone.
	require.NoError(t, sb.Use(func(b []byte) { assert.Equal(t, []byte("y"), b) }))
}

// ---------------------------------------------------------------------------
// Use
// ---------------------------------------------------------------------------

func TestUse_AfterDestroy(t *testing.T) {
	sb, err := securebytes.New([]byte("gone"))
	require.NoError(t, err)
	require.NoError(t, sb.Destroy())

	called := false
	err = sb.Use(func([]byte) { called = true })
	assert.ErrorIs(t, err, securebytes.ErrDestroyed)
	assert.False(t, called, "fn must not be invoked after Destroy")
}

func TestUse_PanicLeavesContainerLive(t *testing.T) {
	sb, err := securebytes.New([]byte("live"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })

	require.Panics(t, func() {
		_ = sb.Use(func([]byte) { panic("boom") })
	})

	// After the panic the mutex must be released and the container usable.
	require.NoError(t, sb.Use(func(b []byte) {
		assert.Equal(t, []byte("live"), b)
	}))
}

// ---------------------------------------------------------------------------
// Len / Destroy
// ---------------------------------------------------------------------------

func TestLen_AfterDestroy(t *testing.T) {
	sb, err := securebytes.New([]byte("12345"))
	require.NoError(t, err)
	assert.Equal(t, 5, sb.Len())
	require.NoError(t, sb.Destroy())
	assert.Equal(t, 0, sb.Len())
}

func TestDestroy_Idempotent(t *testing.T) {
	sb, err := securebytes.New([]byte("z"))
	require.NoError(t, err)
	require.NoError(t, sb.Destroy())
	require.NoError(t, sb.Destroy())
	require.NoError(t, sb.Destroy())
	assert.True(t, sb.Destroyed())
}

func TestDestroy_ZeroesPayload(t *testing.T) {
	sb, err := securebytes.New([]byte{0xAA, 0xBB, 0xCC})
	require.NoError(t, err)

	// Capture the backing slice pointer via Use to prove it's wiped.
	var captured []byte
	require.NoError(t, sb.Use(func(b []byte) {
		captured = b // NOTE: retained only for white-box wipe assertion in-test.
	}))
	require.NoError(t, sb.Destroy())
	for i, b := range captured {
		assert.Equalf(t, byte(0), b, "byte %d not zeroed after Destroy", i)
	}
}

func TestDestroy_MUnlockFailure(t *testing.T) {
	sb, err := securebytes.New([]byte("munlock-fail"))
	require.NoError(t, err)

	sentinel := errors.New("munlock boom")
	restore := securebytes.SetMUnlock(func([]byte) error { return sentinel })
	defer restore()

	err = sb.Destroy()
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
	// Even on munlock failure the container is marked destroyed and Len is 0.
	assert.True(t, sb.Destroyed())
	assert.Equal(t, 0, sb.Len())

	// A subsequent Destroy is a no-op and returns nil (idempotent).
	restore()
	assert.NoError(t, sb.Destroy())
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

func TestRedaction_String(t *testing.T) {
	sb, err := securebytes.New([]byte("do-not-print"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })

	assert.Equal(t, "[redacted]", sb.String())
	assert.Equal(t, "[redacted]", fmt.Sprintf("%s", sb))
	assert.Equal(t, "[redacted]", fmt.Sprintf("%v", sb))
	assert.NotContains(t, fmt.Sprintf("%v", sb), "do-not-print")
}

func TestRedaction_JSON(t *testing.T) {
	sb, err := securebytes.New([]byte("json-secret"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })

	out, err := json.Marshal(sb)
	require.NoError(t, err)
	assert.JSONEq(t, `"[redacted]"`, string(out))

	// Even nested inside a struct.
	wrapper := struct {
		Secret *securebytes.SecureBytes `json:"secret"`
	}{Secret: sb}
	out, err = json.Marshal(wrapper)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "json-secret")
	assert.Contains(t, string(out), "[redacted]")
}

func TestRedaction_Slog(t *testing.T) {
	sb, err := securebytes.New([]byte("slog-secret"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	logger.Info("logging a secret", "value", sb)

	assert.Contains(t, buf.String(), "[redacted]")
	assert.NotContains(t, buf.String(), "slog-secret")
}

func TestRedaction_AfterDestroy(t *testing.T) {
	sb, err := securebytes.New([]byte("secret"))
	require.NoError(t, err)
	require.NoError(t, sb.Destroy())
	// Rendering paths must remain safe (never panic) post-destroy.
	assert.Equal(t, "[redacted]", sb.String())
	out, err := sb.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, `"[redacted]"`, string(out))
}

// ---------------------------------------------------------------------------
// Finalizer
// ---------------------------------------------------------------------------

func TestFinalizer_ZeroesOnGC(t *testing.T) {
	// Prove the finalizer path does not panic and that a dropped reference
	// is eventually collected. We cannot easily assert the wipe from the
	// outside (the only slice reference is inside the container), so this
	// exercises the finalizer registration + GC without leaking.
	func() {
		sb, err := securebytes.New([]byte("finalize-me"))
		require.NoError(t, err)
		_ = sb.Len()
		// drop sb
	}()
	for range 3 {
		runtime.GC()
	}
	// If the finalizer double-freed or panicked, the test binary would crash.
}

// ---------------------------------------------------------------------------
// Concurrency (run with -race)
// ---------------------------------------------------------------------------

func TestConcurrent_UseAndDestroy(t *testing.T) {
	sb, err := securebytes.New(bytes.Repeat([]byte{0x5A}, 64))
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				_ = sb.Use(func(b []byte) {
					_ = len(b)
				})
				_ = sb.Len()
			}
		}()
	}
	// Concurrent destroyer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = sb.Destroy()
	}()
	wg.Wait()
	assert.True(t, sb.Destroyed())
}

func TestConcurrent_MultipleDestroy(t *testing.T) {
	sb, err := securebytes.New([]byte("race-destroy"))
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, sb.Destroy())
		}()
	}
	wg.Wait()
	assert.True(t, sb.Destroyed())
}

// ---------------------------------------------------------------------------
// rlimit raise (unix real, non-unix no-op) — must never panic
// ---------------------------------------------------------------------------

func TestRaiseMemlockLimit_NeverPanics(t *testing.T) {
	assert.NotPanics(t, securebytes.RaiseMemlockLimit)
}
