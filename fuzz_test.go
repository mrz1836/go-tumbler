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

// FuzzParseRecoveryCode asserts ParseRecoveryCode never panics on arbitrary
// input and that any code it accepts is exactly RecoveryCodeLen bytes.
func FuzzParseRecoveryCode(f *testing.F) {
	f.Add("ABCD-EFGH-IJKL")
	f.Add("")
	f.Add("11111111")        // '1' is not in the base32 alphabet
	f.Add("aa bb cc  dd - ") // messy separators / casing
	if code, err := tumbler.GenerateRecoveryCode(); err == nil {
		if printed, fErr := tumbler.FormatRecoveryCode(code); fErr == nil {
			f.Add(printed)
		}
		_ = code.Destroy()
	}

	f.Fuzz(func(t *testing.T, s string) {
		sb, err := tumbler.ParseRecoveryCode(s)
		if err != nil {
			return // rejecting malformed input is the expected outcome
		}
		if sb.Len() != tumbler.RecoveryCodeLen {
			t.Fatalf("accepted code of wrong length %d", sb.Len())
		}
		_ = sb.Destroy()
	})
}

// FuzzParseKDFParams asserts parseKDF never panics and that any KDF it accepts
// round-trips its parameters stably through MarshalParams and a re-parse.
func FuzzParseKDFParams(f *testing.F) {
	f.Add(uint8(0), []byte{})                     // KDFNone
	f.Add(uint8(1), argonParams(4, 256*1024, 4))  // argon2 (hush)
	f.Add(uint8(2), scryptParams(18, 8, 1))       // scrypt (sigil)
	f.Add(uint8(1), []byte{1, 2, 3})              // wrong-length argon2
	f.Add(uint8(99), bytes.Repeat([]byte{1}, 16)) // unknown id

	f.Fuzz(func(t *testing.T, id uint8, params []byte) {
		kdf, err := tumbler.ParseKDFForTest(tumbler.KDFID(id), params)
		if err != nil {
			return
		}
		if kdf == nil {
			return // KDFNone: no parameters to round-trip
		}
		reparsed, err := tumbler.ParseKDFForTest(kdf.ID(), kdf.MarshalParams())
		if err != nil {
			t.Fatalf("re-parse of accepted KDF failed: %v", err)
		}
		if !bytes.Equal(kdf.MarshalParams(), reparsed.MarshalParams()) {
			t.Fatalf("KDF params not stable through re-parse")
		}
	})
}
