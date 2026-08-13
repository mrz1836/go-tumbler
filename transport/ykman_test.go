package transport

import (
	"context"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedRunner returns a commandRunner that always yields res.
func fixedRunner(res runResult) commandRunner {
	return func(context.Context, string, []string) runResult { return res }
}

// respHex is a valid 40-char lowercase-hex HMAC-SHA1 response.
func respHex() []byte {
	return []byte(hex.EncodeToString([]byte("0123456789abcdefghij"))) // 20 bytes -> 40 hex
}

// ---------------------------------------------------------------------------
// parseYkmanVersion / versionLess
// ---------------------------------------------------------------------------

func TestParseYkmanVersion(t *testing.T) {
	cases := map[string][3]int{
		"5.9.2":                                  {5, 9, 2},
		"YubiKey Manager (ykman) version: 5.9.2": {5, 9, 2},
		"ykman 5.10.0 built with love":           {5, 10, 0},
		"12.0.3\n":                               {12, 0, 3},
	}
	for in, want := range cases {
		got, err := parseYkmanVersion(in)
		require.NoErrorf(t, err, "input %q", in)
		assert.Equalf(t, want, got, "input %q", in)
	}
	_, err := parseYkmanVersion("no version here")
	assert.Error(t, err)
	_, err = parseYkmanVersion("5.9")
	assert.Error(t, err)
}

func TestVersionLess(t *testing.T) {
	assert.True(t, versionLess([3]int{4, 9, 9}, [3]int{5, 0, 0}))
	assert.True(t, versionLess([3]int{5, 0, 0}, [3]int{5, 0, 1}))
	assert.False(t, versionLess([3]int{5, 0, 0}, [3]int{5, 0, 0}))
	assert.False(t, versionLess([3]int{6, 0, 0}, [3]int{5, 9, 9}))
}

// ---------------------------------------------------------------------------
// decodeResponse
// ---------------------------------------------------------------------------

func TestDecodeResponse(t *testing.T) {
	resp, err := decodeResponse(respHex())
	require.NoError(t, err)
	assert.Len(t, resp, 20)

	_, err = decodeResponse([]byte("tooshort"))
	assert.ErrorIs(t, err, ErrBadResponse)

	// Correct length but uppercase (rejected — we require lowercase).
	up := []byte("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
	require.Len(t, up, responseHexLen)
	_, err = decodeResponse(up)
	assert.ErrorIs(t, err, ErrBadResponse)

	// Correct length, contains a non-hex char.
	bad := []byte("zz23456789abcdef0123456789abcdef01234567")
	require.Len(t, bad, responseHexLen)
	_, err = decodeResponse(bad)
	assert.ErrorIs(t, err, ErrBadResponse)
}

// ---------------------------------------------------------------------------
// classifyToolError
// ---------------------------------------------------------------------------

func TestClassifyToolError(t *testing.T) {
	t.Run("context canceled -> touch timeout", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := classifyToolError(ctx, runResult{err: exec.ErrNotFound})
		assert.ErrorIs(t, err, ErrTouchTimeout)
	})
	t.Run("exec error -> tool not found", func(t *testing.T) {
		err := classifyToolError(context.Background(), runResult{err: &exec.Error{Name: "ykman", Err: exec.ErrNotFound}})
		assert.ErrorIs(t, err, ErrToolNotFound)
	})
	t.Run("no device", func(t *testing.T) {
		err := classifyToolError(context.Background(), runResult{err: errBoom(), stderr: []byte("Failed connecting to the YubiKey")})
		assert.ErrorIs(t, err, ErrNoDevice)
	})
	t.Run("slot not configured", func(t *testing.T) {
		err := classifyToolError(context.Background(), runResult{err: errBoom(), stderr: []byte("Slot 2 is not configured")})
		assert.ErrorIs(t, err, ErrSlotNotConfigured)
	})
	t.Run("touch timeout stderr", func(t *testing.T) {
		err := classifyToolError(context.Background(), runResult{err: errBoom(), stderr: []byte("Touch timeout occurred")})
		assert.ErrorIs(t, err, ErrTouchTimeout)
	})
	t.Run("default -> tool failure", func(t *testing.T) {
		err := classifyToolError(context.Background(), runResult{err: errBoom(), stderr: []byte("something odd")})
		assert.ErrorIs(t, err, ErrToolFailure)
	})
}

// ---------------------------------------------------------------------------
// ChallengeResponse / Serial / Present via injected runner
// ---------------------------------------------------------------------------

func TestChallengeResponse_Success(t *testing.T) {
	tr := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: respHex()})}
	sb, err := tr.ChallengeResponse(context.Background(), 2, []byte("challenge"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sb.Destroy() })
	assert.Equal(t, 20, sb.Len())
}

func TestChallengeResponse_InvalidSlot(t *testing.T) {
	tr := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: respHex()})}
	_, err := tr.ChallengeResponse(context.Background(), 3, []byte("challenge"))
	assert.ErrorIs(t, err, ErrSlotNotConfigured)
}

func TestChallengeResponse_BadOutput(t *testing.T) {
	tr := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: []byte("nope")})}
	_, err := tr.ChallengeResponse(context.Background(), 2, []byte("challenge"))
	assert.ErrorIs(t, err, ErrBadResponse)
}

func TestChallengeResponse_TolerantOutput(t *testing.T) {
	lower := string(respHex())
	upper := strings.ToUpper(lower)

	cases := map[string]string{
		"plain lowercase":    lower,
		"uppercase":          upper,
		"trailing newline":   lower + "\n",
		"surrounded by text": "Touch your YubiKey...\n" + upper + "\nDone.\n",
	}
	for name, stdout := range cases {
		t.Run(name, func(t *testing.T) {
			tr := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: []byte(stdout)})}
			sb, err := tr.ChallengeResponse(context.Background(), 2, []byte("challenge"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = sb.Destroy() })
			assert.Equal(t, 20, sb.Len())
		})
	}
}

func TestChallengeResponse_AmbiguousOutputRejected(t *testing.T) {
	two := string(respHex()) + " " + string(respHex())
	tr := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: []byte(two)})}
	_, err := tr.ChallengeResponse(context.Background(), 2, []byte("challenge"))
	assert.ErrorIs(t, err, ErrBadResponse)
}

func TestChallengeResponse_ToolError(t *testing.T) {
	tr := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{err: errBoom(), stderr: []byte("No YubiKey detected")})}
	_, err := tr.ChallengeResponse(context.Background(), 2, []byte("challenge"))
	assert.ErrorIs(t, err, ErrNoDevice)
}

func TestChallengeResponse_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: respHex()})}
	_, err := tr.ChallengeResponse(ctx, 2, []byte("challenge"))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestSerialAndPresent(t *testing.T) {
	tr := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: []byte("12345678\n87654321\n")})}
	s, err := tr.Serial(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "12345678", s)
	assert.True(t, tr.Present(context.Background()))

	empty := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: []byte("  ")})}
	_, err = empty.Serial(context.Background())
	assert.ErrorIs(t, err, ErrNoDevice)
	assert.False(t, empty.Present(context.Background()))
}

// ---------------------------------------------------------------------------
// checkVersion / NewYkmanTransport / resolveToolPath
// ---------------------------------------------------------------------------

func TestCheckVersion(t *testing.T) {
	ok := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: []byte("5.9.2")})}
	assert.NoError(t, ok.checkVersion(context.Background()))

	old := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: []byte("4.0.0")})}
	assert.ErrorIs(t, old.checkVersion(context.Background()), ErrToolVersion)

	junk := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{stdout: []byte("banana")})}
	assert.ErrorIs(t, junk.checkVersion(context.Background()), ErrToolVersion)

	failed := &YkmanTransport{path: "/x/ykman", run: fixedRunner(runResult{err: errBoom()})}
	assert.ErrorIs(t, failed.checkVersion(context.Background()), ErrToolFailure)
}

func TestResolveToolPath(t *testing.T) {
	// A real, resolvable binary present on both darwin and linux.
	abs, err := resolveToolPath("/bin/sh")
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh", abs)

	_, err = resolveToolPath("definitely-not-a-real-tool-xyzzy")
	assert.ErrorIs(t, err, ErrToolNotFound)
}

func TestNewYkmanTransport_FullFlow(t *testing.T) {
	// Use /bin/sh as a stand-in resolvable binary; the injected runner
	// supplies a satisfactory version so construction succeeds.
	tr, err := NewYkmanTransport("/bin/sh", withRunner(fixedRunner(runResult{stdout: []byte("5.9.2")})))
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh", tr.path)

	_, err = NewYkmanTransport("definitely-not-real-xyzzy", withRunner(fixedRunner(runResult{stdout: []byte("5.9.2")})))
	assert.ErrorIs(t, err, ErrToolNotFound)

	_, err = NewYkmanTransport("/bin/sh", withRunner(fixedRunner(runResult{stdout: []byte("1.0.0")})))
	assert.ErrorIs(t, err, ErrToolVersion)
}

func errBoom() error { return &exec.ExitError{} }

// TestDefaultRunner exercises the real exec-backed runner against portable
// binaries so the production command path is covered without ykman.
func TestDefaultRunner(t *testing.T) {
	// Success path: /bin/echo prints its argument to stdout.
	res := defaultRunner(context.Background(), "/bin/echo", []string{"hello"})
	require.NoError(t, res.err)
	assert.Contains(t, string(res.stdout), "hello")

	// Failure path: a nonexistent binary yields an *exec.Error.
	res = defaultRunner(context.Background(), "/definitely/not/here/xyzzy", []string{"x"})
	require.Error(t, res.err)
}
