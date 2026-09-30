package promagent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostNetnsDialerSameNamespace(t *testing.T) {
	// no custom dialer is needed when the agent runs in the target namespace
	dial, err := HostNetnsDialer("/proc/self/ns/net")
	require.NoError(t, err)
	assert.Nil(t, dial)

	_, err = HostNetnsDialer("/nonexistent")
	assert.Error(t, err)
}
