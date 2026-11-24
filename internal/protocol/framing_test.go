package protocol

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFrameRoundtrip(t *testing.T) {
	payload := []byte(`{"type":"hello"}`)
	var buf bytes.Buffer
	require.NoError(t, WriteFrame(&buf, payload))

	got, err := ReadFrame(&buf, 1<<20)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestFrameRejectsOversize(t *testing.T) {
	payload := make([]byte, 100)
	var buf bytes.Buffer
	require.NoError(t, WriteFrame(&buf, payload))

	_, err := ReadFrame(&buf, 50)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "frame too large")
}

func TestFrameEmpty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, WriteFrame(&buf, nil))

	got, err := ReadFrame(&buf, 1<<20)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestDatagramRoundtripSizes(t *testing.T) {
	cases := []int{0, 1, 1500, MaxDatagramSize}
	for _, n := range cases {
		t.Run(fmt.Sprintf("size=%d", n), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xAB}, n)
			var buf bytes.Buffer
			require.NoError(t, WriteDatagram(&buf, payload))

			got, err := ReadDatagram(&buf, nil)
			require.NoError(t, err)
			if n == 0 {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, payload, got)
			}
		})
	}
}

func TestDatagramRejectsOversizeOnWrite(t *testing.T) {
	payload := make([]byte, MaxDatagramSize+1)
	var buf bytes.Buffer
	err := WriteDatagram(&buf, payload)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDatagramTooLarge)
	assert.Zero(t, buf.Len(), "no bytes written when size check fails")
}

func TestDatagramScratchBufferReused(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 1500)
	var buf bytes.Buffer
	require.NoError(t, WriteDatagram(&buf, payload))

	scratch := make([]byte, 4096)
	got, err := ReadDatagram(&buf, scratch)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
	assert.Same(t, &scratch[0], &got[0])
}

func TestDatagramScratchTooSmallAllocates(t *testing.T) {
	payload := bytes.Repeat([]byte{0x99}, 2000)
	var buf bytes.Buffer
	require.NoError(t, WriteDatagram(&buf, payload))

	scratch := make([]byte, 100)
	got, err := ReadDatagram(&buf, scratch)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestDatagramReadShortLength(t *testing.T) {
	_, err := ReadDatagram(bytes.NewReader([]byte{0x05}), nil)
	require.Error(t, err)
}

func TestDatagramReadShortPayload(t *testing.T) {
	raw := []byte{0x00, 0x0A, 0x01, 0x02, 0x03}
	_, err := ReadDatagram(bytes.NewReader(raw), nil)
	require.Error(t, err)
}
