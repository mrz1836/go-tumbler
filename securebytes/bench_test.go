package securebytes_test

import (
	"testing"

	"github.com/mrz1836/go-tumbler/securebytes"
)

// Benchmarks for the SecureBytes lifecycle (consumed by CI's
// fortress-benchmarks). Each op allocates an mlocked buffer, so these measure
// the real per-secret overhead callers pay.

func BenchmarkNew(b *testing.B) {
	for b.Loop() {
		sb, err := securebytes.New(make([]byte, 64))
		if err != nil {
			b.Fatal(err)
		}
		_ = sb.Destroy()
	}
}

func BenchmarkClone(b *testing.B) {
	src, err := securebytes.New(make([]byte, 64))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = src.Destroy() })
	for b.Loop() {
		cp, cErr := src.Clone()
		if cErr != nil {
			b.Fatal(cErr)
		}
		_ = cp.Destroy()
	}
}

func BenchmarkUse(b *testing.B) {
	sb, err := securebytes.New(make([]byte, 64))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = sb.Destroy() })
	for b.Loop() {
		if uErr := sb.Use(func(_ []byte) {}); uErr != nil {
			b.Fatal(uErr)
		}
	}
}

func BenchmarkDestroy(b *testing.B) {
	for b.Loop() {
		b.StopTimer()
		sb, err := securebytes.New(make([]byte, 64))
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if dErr := sb.Destroy(); dErr != nil {
			b.Fatal(dErr)
		}
	}
}
