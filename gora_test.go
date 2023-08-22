package gora_test

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/binalyze/gora"
	"github.com/binalyze/gora/variables"
)

func TestCompileString(t *testing.T) {
	comp := gora.NewCompiled()
	err := comp.CompileString(`rule x{`, "")
	require.Error(t, err)
	require.Nil(t, comp.Rules())

	comp = gora.NewCompiled()
	err = comp.CompileString(rulestrFs, "")
	require.NoError(t, err)
	require.NotNil(t, comp.Rules())
}

func TestCompileFile(t *testing.T) {
	tempDir := t.TempDir()

	comp := gora.NewCompiled()
	path := genFile(t, tempDir, `rule x{`)
	err := comp.CompileFiles(true, path)
	require.Error(t, err)
	require.Nil(t, comp.Rules())

	comp = gora.NewCompiled()
	path = genFile(t, tempDir, rulestrFs)
	err = comp.CompileFiles(true, path)
	require.NoError(t, err)
	require.NotNil(t, comp.Rules())
}

func TestBuildRuleWithAllVars(t *testing.T) {
	tempDir := t.TempDir()

	const ee = " == "

	vars := variables.List()
	var sb strings.Builder

	for i, v := range vars {
		sb.WriteString(v.String())

		switch m := v.Meta(); {
		case m&variables.MetaBool != 0:
		case m&variables.MetaFloat != 0, m&variables.MetaInt != 0:
			sb.WriteString(ee)
			sb.WriteString("0")
		case m&variables.MetaString != 0:
			sb.WriteString(ee)
			sb.WriteString("\"\"")
		}

		if i < len(vars)-1 {
			sb.WriteString(" and ")
		}
	}

	rs := fmt.Sprintf(ruleAllVarsTmpl, sb.String())

	comp := gora.NewCompiled()
	path := genFile(t, tempDir, rs)
	err := comp.CompileFiles(true, path)
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

const ruleAllVarsTmpl = `
rule all_vars
{
    condition:
        %s
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
