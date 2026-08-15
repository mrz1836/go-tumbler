//go:build unix

package securebytes_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/mrz1836/go-tumbler/securebytes"
)

func TestRaiseMemlockLimit_GetrlimitError(t *testing.T) {
	restore := securebytes.SetRlimitHooks(
		func(int, *unix.Rlimit) error { return errors.New("getrlimit failed") },
		func(int, *unix.Rlimit) error {
			t.Fatal("setrlimit must not be called when getrlimit fails")
			return nil
		},
	)
	defer restore()
	assert.NotPanics(t, securebytes.RaiseMemlockLimit)
}

func TestRaiseMemlockLimit_AlreadyAtMax(t *testing.T) {
	restore := securebytes.SetRlimitHooks(
		func(_ int, l *unix.Rlimit) error { l.Cur = 1024; l.Max = 1024; return nil },
		func(int, *unix.Rlimit) error {
			t.Fatal("setrlimit must not be called when Cur >= Max")
			return nil
		},
	)
	defer restore()
	assert.NotPanics(t, securebytes.RaiseMemlockLimit)
}

func TestRaiseMemlockLimit_RaisesToMax(t *testing.T) {
	var setCur uint64
	setCalled := false
	restore := securebytes.SetRlimitHooks(
		func(_ int, l *unix.Rlimit) error { l.Cur = 8; l.Max = 4096; return nil },
		func(_ int, l *unix.Rlimit) error { setCalled = true; setCur = l.Cur; return nil },
	)
	defer restore()

	securebytes.RaiseMemlockLimit()
	assert.True(t, setCalled, "setrlimit should be called when Cur < Max")
	assert.Equal(t, uint64(4096), setCur, "soft limit should be raised to the hard limit")
}

func TestRaiseMemlockLimit_SetrlimitErrorIgnored(t *testing.T) {
	restore := securebytes.SetRlimitHooks(
		func(_ int, l *unix.Rlimit) error { l.Cur = 8; l.Max = 4096; return nil },
		func(int, *unix.Rlimit) error { return errors.New("setrlimit failed") },
	)
	defer restore()
	// Best-effort: a setrlimit failure must be swallowed silently.
	assert.NotPanics(t, securebytes.RaiseMemlockLimit)
}
