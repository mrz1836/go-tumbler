package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// minYkmanVersion is the pinned floor. Yubico ships ykman on a ~2–4 month
// cadence; 5.9.x is current at design time. A located ykman older than this
// is rejected (ErrToolVersion).
var minYkmanVersion = [3]int{5, 0, 0} //nolint:gochecknoglobals // pinned floor; immutable

// runResult is the structured outcome of one command invocation, so error
// classification is deterministic and unit-testable without hardware.
type runResult struct {
	stdout []byte
	stderr []byte
	err    error
}

// commandRunner executes name with args and returns the structured result.
// Replaceable in tests to feed canned tool output through the exact
// classification/validation logic used in production.
type commandRunner func(ctx context.Context, name string, args []string) runResult

// YkmanTransport is the production Transport delegating to Yubico's ykman CLI.
//
// Security posture:
//   - the ykman path is resolved to an ABSOLUTE path once at construction, so
//     a later $PATH change cannot redirect the invocation;
//   - every call uses a fixed argv via exec.CommandContext — never a shell;
//   - the response is validated to be exactly 40 lowercase hex chars, wrapped
//     in a SecureBytes, and the stdout buffer is zeroed; nothing is logged.
type YkmanTransport struct {
	path string
	run  commandRunner
}

// YkmanOption configures a YkmanTransport.
type YkmanOption func(*YkmanTransport)

// withRunner overrides the command runner (tests only; unexported).
func withRunner(r commandRunner) YkmanOption {
	return func(t *YkmanTransport) { t.run = r }
}

// NewYkmanTransport resolves ykman to an absolute path, verifies it meets the
// pinned minimum version, and returns a ready transport. path may be a bare
// name ("ykman") to search $PATH once, or an absolute path to pin exactly.
func NewYkmanTransport(path string, opts ...YkmanOption) (*YkmanTransport, error) {
	t := &YkmanTransport{run: defaultRunner}
	for _, o := range opts {
		o(t)
	}

	abs, err := resolveToolPath(path)
	if err != nil {
		return nil, err
	}
	t.path = abs

	if err = t.checkVersion(context.Background()); err != nil {
		return nil, err
	}
	return t, nil
}

// resolveToolPath resolves a bare name via $PATH (once) or validates an
// absolute path. Returns ErrToolNotFound if it cannot be found.
func resolveToolPath(path string) (string, error) {
	if path == "" {
		path = "ykman"
	}
	abs, err := exec.LookPath(path)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %v", ErrToolNotFound, path, err)
	}
	return abs, nil
}

// checkVersion runs `ykman --version` and enforces the pinned floor.
func (t *YkmanTransport) checkVersion(ctx context.Context) error {
	res := t.run(ctx, t.path, []string{"--version"})
	if res.err != nil {
		return fmt.Errorf("%w: version probe: %v", ErrToolFailure, res.err)
	}
	v, err := parseYkmanVersion(string(res.stdout))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrToolVersion, err)
	}
	if versionLess(v, minYkmanVersion) {
		return fmt.Errorf("%w: found %d.%d.%d, need >= %d.%d.%d",
			ErrToolVersion, v[0], v[1], v[2], minYkmanVersion[0], minYkmanVersion[1], minYkmanVersion[2])
	}
	return nil
}

// ChallengeResponse implements Transport via `ykman otp calculate`.
//
// NOTE: the exact `otp calculate` argv and output shape MUST be verified
// against the pinned ykman version on real hardware and captured in a KAT;
// this is the documented hardware-verification step. The surrounding path
// resolution, version pinning, output validation, SecureBytes wrapping, and
// buffer zeroing are exercised by unit tests with an injected runner.
func (t *YkmanTransport) ChallengeResponse(ctx context.Context, slot uint8, challenge []byte) (*securebytes.SecureBytes, error) {
	if !otpSlotValid(slot) {
		return nil, ErrSlotNotConfigured
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	hexChal := hex.EncodeToString(challenge)
	// Fixed argv — never a shell. The challenge is non-secret for yubi-only
	// mode; for 2FA it is defense-in-depth-degraded but safe (the password
	// key is also mixed directly into the KEK). See SECURITY.md.
	args := []string{"otp", "calculate", strconv.Itoa(int(slot)), hexChal}
	res := t.run(ctx, t.path, args)
	if res.err != nil {
		return nil, classifyToolError(ctx, res)
	}

	out := bytes.TrimSpace(res.stdout)
	defer zeroBytes(res.stdout)
	resp, err := decodeResponse(out)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(resp)
	return securebytes.New(resp)
}

// Serial implements Transport via `ykman list --serials`.
func (t *YkmanTransport) Serial(ctx context.Context) (string, error) {
	res := t.run(ctx, t.path, []string{"list", "--serials"})
	if res.err != nil {
		return "", classifyToolError(ctx, res)
	}
	s := strings.TrimSpace(string(res.stdout))
	if s == "" {
		return "", ErrNoDevice
	}
	// First line if multiple keys are attached.
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s), nil
}

// Present implements Transport: a device is present if Serial succeeds.
func (t *YkmanTransport) Present(ctx context.Context) bool {
	s, err := t.Serial(ctx)
	return err == nil && s != ""
}

// decodeResponse validates that out is exactly 40 lowercase hex chars and
// decodes it to the 20-byte HMAC-SHA1 response.
func decodeResponse(out []byte) ([]byte, error) {
	if len(out) != responseHexLen {
		return nil, fmt.Errorf("%w: length %d", ErrBadResponse, len(out))
	}
	for _, c := range out {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, fmt.Errorf("%w: non-lowercase-hex byte", ErrBadResponse)
		}
	}
	resp := make([]byte, hex.DecodedLen(len(out)))
	if _, err := hex.Decode(resp, out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadResponse, err)
	}
	return resp, nil
}

// classifyToolError maps a failed invocation to a sentinel, using ctx state
// and stderr heuristics. The heuristics are best-effort and documented as
// requiring hardware verification against the pinned ykman version.
func classifyToolError(ctx context.Context, res runResult) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %v", ErrTouchTimeout, ctx.Err())
	}
	var execErr *exec.Error
	if errors.As(res.err, &execErr) {
		return fmt.Errorf("%w: %v", ErrToolNotFound, res.err)
	}
	stderr := strings.ToLower(string(res.stderr))
	switch {
	case strings.Contains(stderr, "touch") && strings.Contains(stderr, "timeout"):
		return fmt.Errorf("%w: %s", ErrTouchTimeout, strings.TrimSpace(string(res.stderr)))
	case strings.Contains(stderr, "no yubikey") || strings.Contains(stderr, "failed connecting") || strings.Contains(stderr, "failed to connect"):
		return fmt.Errorf("%w: %s", ErrNoDevice, strings.TrimSpace(string(res.stderr)))
	case strings.Contains(stderr, "not configured") || strings.Contains(stderr, "not programmed") || strings.Contains(stderr, "no valid"):
		return fmt.Errorf("%w: %s", ErrSlotNotConfigured, strings.TrimSpace(string(res.stderr)))
	default:
		return fmt.Errorf("%w: %s", ErrToolFailure, strings.TrimSpace(string(res.stderr)))
	}
}

// parseYkmanVersion extracts the first x.y.z it finds in the --version output.
func parseYkmanVersion(s string) ([3]int, error) {
	var v [3]int
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= '0' && r <= '9') && r != '.'
	})
	for _, f := range fields {
		parts := strings.Split(f, ".")
		if len(parts) < 3 {
			continue
		}
		a, e1 := strconv.Atoi(parts[0])
		b, e2 := strconv.Atoi(parts[1])
		c, e3 := strconv.Atoi(parts[2])
		if e1 == nil && e2 == nil && e3 == nil {
			v[0], v[1], v[2] = a, b, c
			return v, nil
		}
	}
	return v, fmt.Errorf("no x.y.z version in %q", strings.TrimSpace(s))
}

// versionLess reports whether a < b.
func versionLess(a, b [3]int) bool {
	for i := range 3 {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// defaultRunner is the production commandRunner using exec.CommandContext.
func defaultRunner(ctx context.Context, name string, args []string) runResult {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return runResult{stdout: out.Bytes(), stderr: errBuf.Bytes(), err: err}
}

// zeroBytes overwrites b with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
