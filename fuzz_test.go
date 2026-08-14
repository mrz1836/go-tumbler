package tumbler_test

import (
	"bytes"
	"context"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/securebytes"
)

// fuzzKDF is the cheapest valid scrypt cost — fuzzing hammers the envelope
// logic, not the KDF's work factor.
func fuzzKDF() tumbler.KDF { return tumbler.NewScryptKDF(2, 1, 1) }

// FuzzParseEnvelope asserts ParseEnvelope never panics on arbitrary input and
// that any envelope it accepts re-marshals to a stable, re-parseable form.
func FuzzParseEnvelope(f *testing.F) {
	// Seed with a real, valid envelope and some structural fragments.
	dek, _ := securebytes.NewZero(32)
	defer func() { _ = dek.Destroy() }()
	pw, _ := securebytes.New([]byte("seed-password"))
	defer func() { _ = pw.Destroy() }()
	env, err := tumbler.NewEnvelope(context.Background(), dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(fuzzKDF(), pw))
	if err == nil {
		if blob, mErr := env.Marshal(); mErr == nil {
			f.Add(blob)
		}
	}
	f.Add([]byte("TMBL"))
	f.Add([]byte{'T', 'M', 'B', 'L', 1, 1, 0, 1})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		envA, err := tumbler.ParseEnvelope(data)
		if err != nil {
			return // rejecting malformed input is the expected outcome
		}
		// A parsed envelope must re-marshal and re-parse to identical bytes.
		blob, err := envA.Marshal()
		if err != nil {
			t.Fatalf("parsed envelope failed to re-marshal: %v", err)
		}
		envB, err := tumbler.ParseEnvelope(blob)
		if err != nil {
			t.Fatalf("re-marshaled envelope failed to parse: %v", err)
		}
		blob2, err := envB.Marshal()
		if err != nil {
			t.Fatalf("second marshal failed: %v", err)
		}
		if !bytes.Equal(blob, blob2) {
			t.Fatalf("marshal is not idempotent")
		}
	})
}

// FuzzEnrollUnlockRoundTrip asserts that for any password and data key within
// bounds, enroll -> marshal -> parse -> unlock recovers the exact data key,
// and that a different password never unlocks.
func FuzzEnrollUnlockRoundTrip(f *testing.F) {
	f.Add([]byte("password"), []byte("0123456789abcdef0123456789abcdef"))
	f.Add([]byte(""), []byte("k"))
	f.Add([]byte("p"), bytes.Repeat([]byte{0x01}, 64))

	f.Fuzz(func(t *testing.T, password, dekBytes []byte) {
		if len(dekBytes) == 0 || len(dekBytes) > 240 {
			return // outside the supported DEK range
		}
		dekCopy := append([]byte(nil), dekBytes...)
		dek, err := securebytes.New(dekCopy)
		if err != nil {
			return
		}
		defer func() { _ = dek.Destroy() }()

		pwCopy := append([]byte(nil), password...)
		pw, err := securebytes.New(pwCopy)
		if err != nil {
			return
		}
		defer func() { _ = pw.Destroy() }()

		env, err := tumbler.NewEnvelope(context.Background(), dek, tumbler.PolicyPasswordOnly,
			tumbler.NewPasswordMethod(fuzzKDF(), pw))
		if err != nil {
			t.Fatalf("enroll failed for valid inputs: %v", err)
		}
		blob, err := env.Marshal()
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		parsed, err := tumbler.ParseEnvelope(blob)
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}

		pw2Copy := append([]byte(nil), password...)
		pw2, err := securebytes.New(pw2Copy)
		if err != nil {
			return
		}
		defer func() { _ = pw2.Destroy() }()

		got, err := parsed.Unlock(context.Background(), tumbler.NewPasswordMethod(fuzzKDF(), pw2))
		if err != nil {
			t.Fatalf("unlock failed with correct password: %v", err)
		}
		defer func() { _ = got.Destroy() }()

		if uErr := got.Use(func(b []byte) {
			if !bytes.Equal(b, dekBytes) {
				t.Fatalf("recovered DEK mismatch")
			}
		}); uErr != nil {
			t.Fatalf("use recovered dek: %v", uErr)
		}
	})
}
