package transport_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mrz1836/go-tumbler/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFake_Deterministic(t *testing.T) {
	f := transport.NewFakeTransport(2, []byte("secret"))
	a, err := f.ChallengeResponse(context.Background(), 2, []byte("chal"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Destroy() })
	b, err := f.ChallengeResponse(context.Background(), 2, []byte("chal"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Destroy() })

	var av, bv []byte
	require.NoError(t, a.Use(func(x []byte) { av = append([]byte(nil), x...) }))
	require.NoError(t, b.Use(func(x []byte) { bv = append([]byte(nil), x...) }))
	assert.Equal(t, av, bv)
	assert.Len(t, av, 20) // HMAC-SHA1
	assert.Equal(t, 2, f.Touches)
}

func TestFake_TouchFnError(t *testing.T) {
	f := transport.NewFakeTransport(2, []byte("secret"))
	f.TouchFn = func() error { return transport.ErrTouchTimeout }
	_, err := f.ChallengeResponse(context.Background(), 2, []byte("chal"))
	assert.ErrorIs(t, err, transport.ErrTouchTimeout)
}

func TestFake_ErrInject(t *testing.T) {
	f := transport.NewFakeTransport(2, []byte("secret"))
	sentinel := errors.New("injected")
	f.ErrInject = sentinel
	_, err := f.ChallengeResponse(context.Background(), 2, []byte("chal"))
	assert.ErrorIs(t, err, sentinel)
}

func TestFake_UnconfiguredSlot(t *testing.T) {
	f := transport.NewFakeTransport(2, []byte("secret"))
	_, err := f.ChallengeResponse(context.Background(), 1, []byte("chal"))
	assert.ErrorIs(t, err, transport.ErrSlotNotConfigured)
	_, err = f.ChallengeResponse(context.Background(), 3, []byte("chal"))
	assert.ErrorIs(t, err, transport.ErrSlotNotConfigured)
}

func TestFake_ContextCancelled(t *testing.T) {
	f := transport.NewFakeTransport(2, []byte("secret"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.ChallengeResponse(ctx, 2, []byte("chal"))
	assert.ErrorIs(t, err, context.Canceled)
}

func TestFake_SetSlotSerialPresent(t *testing.T) {
	f := transport.NewFakeTransport(2, []byte("secret"))
	f.SetSlot(1, []byte("other"))
	_, err := f.ChallengeResponse(context.Background(), 1, []byte("chal"))
	assert.NoError(t, err)

	f.SerialValue = "ABC123"
	s, err := f.Serial(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ABC123", s)

	assert.True(t, f.Present(context.Background()))
	f.PresentFlag = false
	assert.False(t, f.Present(context.Background()))
}

func TestPIVStub(t *testing.T) {
	p := &transport.PIVTransport{Slot: 0x9d}
	_, err := p.Decipher(context.Background(), []byte("1234"), []byte("ct"))
	assert.ErrorIs(t, err, transport.ErrNotImplemented)
}
