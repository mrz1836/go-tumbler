//go:build !unix

package securebytes

// This file provides no-op memory-pinning bridges for platforms without a
// POSIX mlock (notably Windows). It exists so the module cross-compiles
// under CGO_ENABLED=0 to every GOOS/GOARCH target without pulling in any
// cgo dependency.
//
// On these platforms SecureBytes still delivers zero-on-destroy, redacted
// rendering, and the borrow-only Use API; it simply cannot pin pages
// against swap. That degraded posture is documented in doc.go and is the
// same trade-off the parent projects already accept for non-unix builds.

func mlock(_ []byte) error { return nil }

func munlock(_ []byte) error { return nil }

// raiseMemlockLimit is a no-op on platforms without RLIMIT_MEMLOCK.
func raiseMemlockLimit() {}
