package transport

import (
	"context"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// PIVTransport is the (future, unimplemented) v2 upgrade seam for a genuinely
// strong passwordless mode: a PIN- and touch-gated RSA-2048 OAEP decrypt against
// a non-extractable key in the YubiKey secure element (PIV slot 9d). Unlike the
// challenge-response path — where a touch proves presence, not identity — PIV
// adds a PIN, proving identity.
//
// Mechanism (grounded in what the CLIs can actually do):
//   - Unlock (decrypt) runs through `openssl pkeyutl -decrypt` + `pkcs11-provider`,
//     or `pkcs11-tool` (OpenSC/ykcs11), with the PIN passed OFF argv AND OFF env
//     via `pin-source=file:/dev/fd/N` over an anonymous pipe.
//   - `yubico-piv-tool` CANNOT perform the unlock — its `test-decipher` is a
//     self-test that generates its own data and prints only a pass/fail line, so
//     it cannot decrypt caller ciphertext. It remains the right tool for the
//     enroll side (key generation, attestation, public-key export; PIN over its
//     hidden `--stdin-input`), where the OAEP encrypt is pure-Go crypto/rsa.
//
// This is NOT a drop-in behind the v1 wire format: a 256-byte OAEP ciphertext
// exceeds maxChallengeLen (64), so the real build needs a new AAD-bound
// KEM-ciphertext slot field + algorithm id, a new MethodPIV, and an append-only,
// version-gated 4th IKM role (so existing golden envelopes keep verifying).
//
// It is intentionally a stub in v1: Decipher returns ErrNotImplemented. The type
// exists so callers can compile against the seam and the design is recorded
// in-tree.
type PIVTransport struct {
	// ToolPath is the absolute path to the PKCS#11-capable tool (pkcs11-tool or
	// openssl+pkcs11-provider) resolved by the v2 implementation, mirroring
	// YkmanTransport. (yubico-piv-tool is used only on the enroll side.)
	ToolPath string
	// Slot is the PIV slot (0x9d, key management / decipher).
	Slot byte
}

// Decipher implements PIVDecipher. Stub: not implemented in v1.
func (p *PIVTransport) Decipher(_ context.Context, _, _ []byte) (*securebytes.SecureBytes, error) {
	return nil, ErrNotImplemented
}

// compile-time assertion that the stub satisfies the seam interface.
var _ PIVDecipher = (*PIVTransport)(nil)
