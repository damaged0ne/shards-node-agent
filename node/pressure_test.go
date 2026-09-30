package node

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNode_pressure(t *testing.T) {
	cpu, err := pressure("fixtures/proc", "cpu")
	require.NoError(t, err)
	assert.Equal(t, map[string]float64{"some": 123.456789, "full": 0}, cpu)

	mem, err := pressure("fixtures/proc", "memory")
	require.NoError(t, err)
	assert.Equal(t, map[string]float64{"some": 2.5, "full": 1.5}, mem)

	io, err := pressure("fixtures/proc", "io")
	require.NoError(t, err)
	assert.Equal(t, map[string]float64{"some": 0.987654}, io)

	_, err = pressure("fixtures/nonexistent", "cpu")
	assert.True(t, err != nil)
}
