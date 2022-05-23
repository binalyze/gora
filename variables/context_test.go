package variables_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/stretchr/testify/require"

	. "github.com/binalyze/gora/variables"
)

func TestScanContextImpl(t *testing.T) {
	var sctx ScanContextImpl

	testScanContextImplDefaults(t, &sctx)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sctx.SetContext(ctx)
	require.Same(t, ctx, sctx.Context())

	sctx.SetFilePath("abc")
	require.Equal(t, "abc", sctx.FilePath())

	sctx.SetPid(1)
	require.Equal(t, int(1), sctx.Pid())

	finfo, err := os.Stat(os.Args[0])
	require.NoError(t, err)
	sctx.SetFileInfo(finfo)
	require.Same(t, finfo, sctx.FileInfo())

	proc := &process.Process{}
	sctx.SetProcessInfo(proc)
	require.Same(t, proc, sctx.ProcessInfo())

	errTest := errors.New("test error")
	sctx.SetHandleValueError(func(_ VariableDefiner, _ VariableType, e error) error {
		require.NotNil(t, e)
		return errTest
	})

	require.Same(t, errTest, sctx.HandleValueError(nil, 0, errors.New("value error")))

	sctx.Reset()
	testScanContextImplDefaults(t, &sctx)
}

func testScanContextImplDefaults(t *testing.T, sctx *ScanContextImpl) {
	t.Helper()
	require.Same(t, context.Background(), sctx.Context())
	require.Error(t, sctx.HandleValueError(nil, VarFilePath, errors.New("test error")))

	require.Nil(t, sctx.FileInfo())
	require.Empty(t, sctx.FilePath())
	require.Zero(t, sctx.Pid())
	require.Nil(t, sctx.ProcessInfo())
}
