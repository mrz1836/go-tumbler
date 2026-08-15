package tumbler_test

import (
	"context"
	"testing"

	tumbler "github.com/mrz1836/go-tumbler"
	"github.com/mrz1836/go-tumbler/securebytes"
)

// Benchmarks for the hot paths (consumed by CI's fortress-benchmarks). The KDF
// benchmarks use each app's production cost (hush Argon2id, sigil scrypt); the
// rest are microsecond-scale envelope/crypto primitives.

// mustSecretB builds a SecureBytes from a copy of data for a benchmark.
func mustSecretB(b *testing.B, data []byte) *securebytes.SecureBytes {
	b.Helper()
	sb, err := securebytes.New(append([]byte(nil), data...))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = sb.Destroy() })
	return sb
}

func BenchmarkArgon2idDerive(b *testing.B) {
	k := tumbler.NewArgon2idKDF(4, 256*1024, 4) // hush production cost
	pw := mustSecretB(b, []byte("benchmark-password"))
	salt := make([]byte, 16)
	for b.Loop() {
		out, err := k.Derive(pw, salt)
		if err != nil {
			b.Fatal(err)
		}
		_ = out.Destroy()
	}
}

func BenchmarkScryptDerive(b *testing.B) {
	k := tumbler.NewScryptKDF(18, 8, 1) // sigil production cost
	pw := mustSecretB(b, []byte("benchmark-password"))
	salt := make([]byte, 16)
	for b.Loop() {
		out, err := k.Derive(pw, salt)
		if err != nil {
			b.Fatal(err)
		}
		_ = out.Destroy()
	}
}

func BenchmarkSeal(b *testing.B) {
	kek := mustSecretB(b, make([]byte, 32))
	dek := mustSecretB(b, make([]byte, 64))
	nonce := make([]byte, 12)
	aad := make([]byte, 84)
	for b.Loop() {
		if _, err := tumbler.SealForTest(kek, dek, nonce, aad); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	kek := mustSecretB(b, make([]byte, 32))
	dek := mustSecretB(b, make([]byte, 64))
	nonce := make([]byte, 12)
	aad := make([]byte, 84)
	ct, err := tumbler.SealForTest(kek, dek, nonce, aad)
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		out, oErr := tumbler.OpenForTest(kek, nonce, ct, aad)
		if oErr != nil {
			b.Fatal(oErr)
		}
		_ = out.Destroy()
	}
}

func BenchmarkDeriveKEK(b *testing.B) {
	pk := mustSecretB(b, make([]byte, 32))
	salt := make([]byte, 16)
	var id [8]byte
	for b.Loop() {
		kek, err := tumbler.DeriveKEKForTest(pk, nil, nil, salt, tumbler.FormatVersion, tumbler.MethodPassword, id)
		if err != nil {
			b.Fatal(err)
		}
		_ = kek.Destroy()
	}
}

func BenchmarkBuildIKM(b *testing.B) {
	pk := mustSecretB(b, make([]byte, 32))
	yr := mustSecretB(b, make([]byte, 20))
	for b.Loop() {
		ikm, err := tumbler.BuildIKMForTest(pk, yr, nil)
		if err != nil {
			b.Fatal(err)
		}
		_ = ikm.Destroy()
	}
}

// benchEnvelope builds a small, cheap-to-derive envelope and its serialized
// form for the parse/marshal benchmarks.
func benchEnvelope(b *testing.B) (*tumbler.Envelope, []byte) {
	b.Helper()
	dek := mustSecretB(b, make([]byte, 64))
	pw := mustSecretB(b, []byte("bench-pw"))
	env, err := tumbler.NewEnvelope(context.Background(), dek, tumbler.PolicyPasswordOnly,
		tumbler.NewPasswordMethod(tumbler.NewScryptKDF(8, 8, 1), pw))
	if err != nil {
		b.Fatal(err)
	}
	blob, err := env.Marshal()
	if err != nil {
		b.Fatal(err)
	}
	return env, blob
}

func BenchmarkParseEnvelope(b *testing.B) {
	_, blob := benchEnvelope(b)
	for b.Loop() {
		if _, err := tumbler.ParseEnvelope(blob); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshal(b *testing.B) {
	env, _ := benchEnvelope(b)
	for b.Loop() {
		if _, err := env.Marshal(); err != nil {
			b.Fatal(err)
		}
	}
}
