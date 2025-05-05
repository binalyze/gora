package gora_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/binalyze/gora"
)

func TestWorkingSetHandler(t *testing.T) {
	wsh, err := gora.NewWorkingSetHandler(uint32(os.Getpid()))
	require.NoError(t, err)

	err = wsh.EmptyWorkingSet()
	require.NoError(t, err)

	err = wsh.Close()
	require.NoError(t, err)
}
