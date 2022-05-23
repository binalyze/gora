package variables_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/binalyze/gora/variables"
)

func TestParseVariablesFromReader(t *testing.T) {
	p := new(variables.Parser)
	err := p.ParseFromReader(strings.NewReader(exampleRule))
	// spew.Dump(p.Variables())
	require.NoError(t, err)
	vars := p.Variables()
	require.Equal(t, 2, len(vars))
	require.Equal(t, vars[0], variables.VarFilePath)
	require.Equal(t, vars[1], variables.VarOs)
}

func TestParseVariablesFromFile(t *testing.T) {
	tdir := t.TempDir()
	f, err := os.Create(filepath.Join(tdir, "rule.yar"))
	require.NoError(t, err)
	defer f.Close()
	_, err = f.WriteString(exampleRule)
	require.NoError(t, err)

	p := new(variables.Parser)
	err = p.ParseFromFile(f.Name())
	// spew.Dump(p.Variables())
	require.NoError(t, err)
	vars := p.Variables()
	require.Equal(t, 2, len(vars))
	require.Equal(t, vars[0], variables.VarFilePath)
	require.Equal(t, vars[1], variables.VarOs)
}

func TestParseIncludesImportsVariables(t *testing.T) {
	p := new(variables.Parser)
	err := p.ParseFromReader(strings.NewReader(`
	include "path1"
	import "module1"
	include "path2"
	import "module2"
	private rule test {
		condition:
			file_path matches /.*/
	}
	`))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"path1", "path2"}, p.Includes())
	require.ElementsMatch(t, []string{"module1", "module2"}, p.Imports())

	vars := p.Variables()
	require.Equal(t, 1, len(vars))
	require.Equal(t, vars[0], variables.VarFilePath)
}

const exampleRule = `
private rule HexExample {
	strings:
		// A few hex definitions demonstrating
		$hex_string1 = { 0123456789ABCDEF }
		$hex_string2 = { 0123456789abcdef }
		$hex_string3 = { 01 23 45 67 89 ab cd ef }
	
	condition:
		// Match any file containing 
		$hex_string1 or $hex_string2 or $hex_string3 and file_path=="" and file_path=="" and os=="linux"
}
`
