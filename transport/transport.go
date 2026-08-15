// Package transport abstracts the raw YubiKey I/O behind a small interface so
// the tumbler envelope logic never shells out or touches USB/CCID directly.
//
// The production backend (NewYkmanTransport) delegates to Yubico's official
// ykman CLI over a fixed-argv exec — no third-party Go crypto/hardware
// dependency, and the CGO_ENABLED=0 static-binary posture is preserved.
// FakeTransport provides a deterministic in-memory HMAC-SHA1 for
// hardware-free tests. PIVDecipher is the (stubbed) v2 seam for a strong
// PIN+touch passwordless mode.
package transport

import (
	"context"
	"errors"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// Transport is the minimal YubiKey capability tumbler needs: HMAC-SHA1
// challenge-response on a configured OTP slot. Implementations must never log
// the challenge or the response, and must return the response inside a
// SecureBytes the caller owns and destroys.
type Transport interface {
	// ChallengeResponse computes HMAC-SHA1(device_secret, challenge) on the
	// given OTP slot (1 or 2). It is touch-gated: it may block until the user
	// touches the key, and returns ErrTouchTimeout if they do not in time.
	// The 20-byte response is returned in a fresh SecureBytes.
	ChallengeResponse(ctx context.Context, slot uint8, challenge []byte) (*securebytes.SecureBytes, error)

	// Serial returns the connected device's serial number (non-secret), for
	// identification and diagnostics. Empty string if unavailable.
	Serial(ctx context.Context) (string, error)

	// Present reports whether a YubiKey is currently connected and responsive.
	Present(ctx context.Context) bool
}

// PIVDecipher is the (future, unimplemented) v2 upgrade seam: a PIN+touch,
// non-extractable-key RSA-OAEP decrypt on PIV slot 9d for a genuinely strong
// passwordless mode. It is declared here so callers can compile against the
// planned seam; the full build is NOT a no-format-break drop-in — it adds a new
// AAD-bound KEM-ciphertext slot field and a MethodPIV (see transport/piv.go).
type PIVDecipher interface {
	// Decipher performs a PIN- and touch-gated private-key operation in the
	// secure element, returning the recovered key material in a SecureBytes.
	Decipher(ctx context.Context, pin, ciphertext []byte) (*securebytes.SecureBytes, error)
}

// Sentinel errors. Compare with errors.Is. None of these reveal secret
// material; they describe operational conditions the caller should surface.
var (
	// ErrToolNotFound means the ykman executable could not be located.
	ErrToolNotFound = errors.New("tumbler/transport: ykman not found")

	// ErrToolVersion means the located ykman is older than the pinned minimum.
	ErrToolVersion = errors.New("tumbler/transport: ykman version too old")

	// ErrNoDevice means no YubiKey is connected / responsive.
	ErrNoDevice = errors.New("tumbler/transport: no yubikey present")

	// ErrTouchTimeout means the required touch was not provided in time.
	ErrTouchTimeout = errors.New("tumbler/transport: touch timeout")

	// ErrSlotNotConfigured means the OTP slot is not programmed for HMAC-SHA1
	// challenge-response.
	ErrSlotNotConfigured = errors.New("tumbler/transport: slot not configured for challenge-response")

	// ErrBadResponse means the tool returned output that was not exactly a
	// 40-character lowercase-hex (20-byte) HMAC-SHA1 response.
	ErrBadResponse = errors.New("tumbler/transport: malformed challenge-response output")

	// ErrToolFailure is a generic wrapper for an unclassified tool failure.
	ErrToolFailure = errors.New("tumbler/transport: tool invocation failed")

	// ErrNotImplemented is returned by the PIV v2 stub.
	ErrNotImplemented = errors.New("tumbler/transport: not implemented")
)

// responseHexLen is the expected length of a hex-encoded HMAC-SHA1 response.
const responseHexLen = 40

// otpSlotValid reports whether slot is a valid YubiKey OTP slot (1 or 2).
func otpSlotValid(slot uint8) bool { return slot == 1 || slot == 2 }
