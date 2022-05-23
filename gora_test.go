package gora_test

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/binalyze/gora"
)

func TestCompileString(t *testing.T) {
	comp := gora.NewCompiled()
	err := comp.CompileString(gora.ScanFile, `rule x{`, "")
	require.Error(t, err)
	require.Nil(t, comp.Rules())

	comp = gora.NewCompiled()
	err = comp.CompileString(gora.ScanFile, rulestrFs, "")
	require.NoError(t, err)
	require.NotNil(t, comp.Rules())
}

func TestCompileFile(t *testing.T) {
	tempDir := t.TempDir()

	comp := gora.NewCompiled()
	path := genFile(t, tempDir, `rule x{`)
	err := comp.CompileFiles(gora.ScanFile, true, path)
	require.Error(t, err)
	require.Nil(t, comp.Rules())

	comp = gora.NewCompiled()
	path = genFile(t, tempDir, rulestrFs)
	err = comp.CompileFiles(gora.ScanFile, true, path)
	require.NoError(t, err)
	require.NotNil(t, comp.Rules())
}

const rulestrFs = `
	rule test_fs
{
    strings:
        $my_text_string = "test"
    condition:
        $my_text_string
}
`

var atomicFileCounter int64

func genFile(t *testing.T, dir, rulestr string) string {
	t.Helper()
	p := filepath.Join(dir, strconv.FormatInt(atomic.AddInt64(&atomicFileCounter, 1), 10))
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o777)
	require.NoError(t, err)

	_, err = io.WriteString(f, rulestr)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return p
}
