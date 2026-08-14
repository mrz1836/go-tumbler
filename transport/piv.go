package transport

import (
	"context"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// PIVTransport is the v2 upgrade seam for a genuinely strong passwordless
// mode: a PIN- and touch-gated operation against a non-extractable key in the
// YubiKey secure element (PIV slot 9d, via Yubico's yubico-piv-tool). It drops
// in behind the same Method/Transport/wire-format machinery with no format
// break — the CR path's honest limit is that touch proves presence, not
// identity, whereas PIV adds a PIN.
//
// It is intentionally a stub in v1: Decipher returns ErrNotImplemented. The
// type exists so callers can compile against the seam and so the design is
// documented in-tree.
type PIVTransport struct {
	// ToolPath is the absolute path to yubico-piv-tool (resolved by the v2
	// implementation, mirroring YkmanTransport).
	ToolPath string
	// Slot is the PIV slot (0x9d for key management / decipher).
	Slot byte
}

// Decipher implements PIVDecipher. Stub: not implemented in v1.
func (p *PIVTransport) Decipher(_ context.Context, _, _ []byte) (*securebytes.SecureBytes, error) {
	return nil, ErrNotImplemented
}

// compile-time assertion that the stub satisfies the seam interface.
var _ PIVDecipher = (*PIVTransport)(nil)
