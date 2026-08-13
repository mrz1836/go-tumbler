// Package securebytes provides the SecureBytes container — an opaque,
// pointer-only secret holder that pins its payload in non-swappable
// memory (where the OS supports it), zeroes the payload on explicit
// Destroy AND on garbage collection (via a runtime finalizer), and
// renders as the literal string "[redacted]" through every standard
// log/format/JSON path.
//
// SecureBytes is the in-memory secret-handling foundation shared by the
// go-tumbler envelope, its methods, and its transports. Every data key,
// key-encryption key, derived password key, YubiKey response, and
// recovery code lives inside a SecureBytes for its whole lifetime and is
// Destroy-ed as soon as it is no longer needed.
//
// # Borrow-only access
//
// There is deliberately no Bytes() accessor. Callers obtain the payload
// only through Use(func(b []byte)), for the duration of the callback, and
// MUST NOT retain the slice past the call. This keeps the plaintext window
// bounded and auditable.
//
// # Platform support
//
// On unix targets the payload is pinned with mlock and the process
// RLIMIT_MEMLOCK soft ceiling is raised once (best-effort) to the hard
// limit. On non-unix targets (notably Windows) the mlock bridge is a
// documented no-op so the module still cross-compiles under
// CGO_ENABLED=0; the other protections (zero-on-destroy, redaction,
// borrow-only access) remain fully in force.
//
// # Residual risk
//
// mlock pins the current backing region against swap and against
// relocation of the pinned region, but the Go runtime may transiently
// copy heap objects during GC in pathological cases; that transient copy
// may land in unlocked memory. This is outside the package's threat model
// (commodity malware enumerating files, NOT root-level memory forensics)
// and no bandaid mitigation is added beyond the pinned-region design.
package securebytes
