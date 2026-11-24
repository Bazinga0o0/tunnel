package edgeudp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllocateRandom(t *testing.T) {
	p := NewPool(10000, 10002)
	got := map[int]struct{}{}
	for i := 0; i < 3; i++ {
		port, err := p.Allocate(0)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, port, 10000)
		assert.LessOrEqual(t, port, 10002)
		got[port] = struct{}{}
	}
	assert.Len(t, got, 3, "each allocation returns a distinct port")
}

func TestAllocatePreferred(t *testing.T) {
	p := NewPool(10000, 10010)
	port, err := p.Allocate(10005)
	require.NoError(t, err)
	assert.Equal(t, 10005, port)

	// The same preferred port can't be allocated twice in a row.
	_, err = p.Allocate(10005)
	assert.ErrorIs(t, err, ErrPortUnavailable)
}

func TestAllocateOutOfRange(t *testing.T) {
	p := NewPool(10000, 10010)
	_, err := p.Allocate(9999)
	assert.ErrorIs(t, err, ErrPortOutOfRange)
	_, err = p.Allocate(10011)
	assert.ErrorIs(t, err, ErrPortOutOfRange)
}

func TestAllocateExhaustion(t *testing.T) {
	p := NewPool(10000, 10001)
	_, err := p.Allocate(0)
	require.NoError(t, err)
	_, err = p.Allocate(0)
	require.NoError(t, err)
	_, err = p.Allocate(0)
	assert.ErrorIs(t, err, ErrPoolExhausted)
}

func TestReleaseReturnsPortToPool(t *testing.T) {
	p := NewPool(10000, 10000)
	port, err := p.Allocate(0)
	require.NoError(t, err)
	require.Equal(t, 10000, port)

	_, err = p.Allocate(0)
	assert.ErrorIs(t, err, ErrPoolExhausted)

	p.Release(10000)
	port2, err := p.Allocate(0)
	require.NoError(t, err)
	assert.Equal(t, 10000, port2)
}

func TestReleaseIgnoresOutOfRange(t *testing.T) {
	p := NewPool(10000, 10000)
	// Should not panic.
	p.Release(9999)
	p.Release(65000)
}

func TestNewPoolPanicsOnInvalidRange(t *testing.T) {
	assert.Panics(t, func() { NewPool(0, 10) })
	assert.Panics(t, func() { NewPool(10, 1) })
	assert.Panics(t, func() { NewPool(10, 70000) })
}
