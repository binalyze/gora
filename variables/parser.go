package variables

import (
	"io"
	"os"

	"github.com/VirusTotal/gyp/ast"
	"github.com/VirusTotal/gyp/parser"
)

const depthLimit = 1024

// Parser reprents a parser which parses the given yara rule(s) to identify all external variables, includes and imports
// used in the rule(s).
type Parser struct {
	vars     []VariableType
	includes []string
	imports  []string
	varmap   map[string]struct{}
}

// ParseFromFile parses the given file which must be a valid yara rule file to identify external variables, includes and
// imports.
// Note that, subsequent calls do not reset underlying list of variables, includes and imports identified. Use this
// behaviour to parse multiple inputs to aggregate.
func (p *Parser) ParseFromFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	return p.ParseFromReader(f)
}

// ParseFromReader parses the given io.Reader which must provide a valid yara rule to identify external variables,
// includes and imports.
// Note that, subsequent calls do not reset underlying list of variables, includes and imports identified. Use this
// behaviour to parse multiple inputs to aggregate.
func (p *Parser) ParseFromReader(rd io.Reader) error {
	ast, err := parser.Parse(rd)
	if err != nil {
		return err
	}
	p.includes = append(p.includes, ast.Includes...)
	p.imports = append(p.imports, ast.Imports...)
	p.includes = dedupStringSlice(p.includes)
	p.imports = dedupStringSlice(p.imports)
	p.visit(ast.Rules)
	return nil
}

// Variables returns the list of variables parsed.
func (p *Parser) Variables() []VariableType {
	return p.vars
}

// Includes returns the list of included paths parsed.
func (p *Parser) Includes() []string {
	return p.includes
}

// Imports returns the list of imported modules parsed.
func (p *Parser) Imports() []string {
	return p.imports
}

func (p *Parser) visit(rules []*ast.Rule) {
	if len(rules) == 0 {
		return
	}
	if p.varmap == nil {
		p.varmap = make(map[string]struct{}, len(varNames))
	}
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		p.visitNode(rule.Condition, 1)
	}
}

func (p *Parser) visitNode(node ast.Node, depth int) {
	if node == nil || depth > depthLimit {
		return
	}

	ident, ok := node.(*ast.Identifier)
	if ok && ident != nil && ident.Identifier != "" {
		if v := p.findType(ident.Identifier); v > 0 {
			p.vars = append(p.vars, v)
		}
	}
	// fmt.Println("node", spew.Sdump(node))
	for _, n := range node.Children() {
		p.visitNode(n, depth+1)
	}
}

func (p *Parser) findType(ident string) VariableType {
	if _, ok := p.varmap[ident]; ok {
		return 0
	}
	return p.findTypeSlow(ident)
}

func (p *Parser) findTypeSlow(ident string) VariableType {
	for i, name := range varNames {
		if name == ident {
			p.varmap[name] = struct{}{}
			return VariableType(i)
		}
	}
	return 0
}

func dedupStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	switch len(s) {
	case 0:
		return []string{}
	case 1:
		return []string{s[0]}
	}
	result := []string{}
	seen := make(map[string]struct{})
	for _, val := range s {
		if _, ok := seen[val]; !ok {
			result = append(result, val)
			seen[val] = struct{}{}
		}
	}
	return result
}
