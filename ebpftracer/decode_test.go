package ebpftracer

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sizes of the C structs (ebpf/*.c)
func TestEventSizes(t *testing.T) {
	assert.Equal(t, 12, procEventSize)     // struct proc_event
	assert.Equal(t, 110, tcpEventSize)     // struct tcp_event is 112 incl. tail padding, 110 are decoded
	assert.Equal(t, 32, fileEventSize)     // struct file_event
	assert.Equal(t, 48, l7EventHeaderSize) // struct l7_event fields preceding the payload
	assert.Equal(t, 1080, l7EventSize)     // + payload[1024] + timestamp
}

func TestDecodeMatchesBinaryRead(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 1000; i++ {
		b := make([]byte, l7EventSize+8)
		rnd.Read(b)

		var p procEvent
		require.NoError(t, binary.Read(bytes.NewReader(b), binary.LittleEndian, &p))
		pd, err := decodeProcEvent(b)
		require.NoError(t, err)
		assert.Equal(t, p, pd)

		var tc tcpEvent
		require.NoError(t, binary.Read(bytes.NewReader(b), binary.LittleEndian, &tc))
		td, err := decodeTCPEvent(b)
		require.NoError(t, err)
		assert.Equal(t, tc, td)

		var f fileEvent
		require.NoError(t, binary.Read(bytes.NewReader(b), binary.LittleEndian, &f))
		fd, err := decodeFileEvent(b)
		require.NoError(t, err)
		assert.Equal(t, f, fd)

		// the timestamp follows the payload, so binary.Read can only verify the header
		var l l7Event
		require.NoError(t, binary.Read(bytes.NewReader(b), binary.LittleEndian, &l))
		ld, payload, err := decodeL7Event(b)
		require.NoError(t, err)
		l.Timestamp = binary.LittleEndian.Uint64(b[48+MaxPayloadSize:])
		assert.Equal(t, l, ld)
		assert.Equal(t, b[48:48+MaxPayloadSize], payload)
	}
}

func TestDecodeShortInput(t *testing.T) {
	b := make([]byte, 5)
	_, err := decodeProcEvent(b)
	assert.Error(t, err)
	_, err = decodeTCPEvent(b)
	assert.Error(t, err)
	_, err = decodeFileEvent(b)
	assert.Error(t, err)
	_, _, err = decodeL7Event(b)
	assert.Error(t, err)
}
