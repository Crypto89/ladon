package parser

import (
	"fmt"
	"io"
	"strings"

	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
)

var aclLexer = lexer.Must(lexer.Regexp(
	`(?m)` +
		`(\s+)` +
		`|(^[#;].*$)` +
		`|(?P<Ident>[a-zA-Z][a-zA-Z0-9_-]*)` +
		`|(?P<Object>@[\S]+)` +
		`|(?P<Address>[\d]+\.[\d]+\.[\d]+\.[\d]+(?:\/[\d]{1,2})?)` +
		`|(?P<Date>\d{8})` +
		`|(?P<Port>(?:(?:[a-zA-Z]+|[\d]{1,5})(?:-[a-zA-Z0-9]*)?|-(?:[a-zA-Z0-9]+)))`,
))

type Ports struct {
	Entries []string `{ @(Object|Port|Ident) }`
}

type Hosts struct {
	Entries []string `{ @(Object|Address) }`
}

type Reference struct {
	Object string `( @Ident | @Object | @Address )`
	Port   string `{ "port" ( @Port | @Object | @"any" ) }`
}

func (r *Reference) String() string {
	port := "any"
	if r.Port != "" {
		port = r.Port
	}
	return fmt.Sprintf("%s/%s", r.Object, port)
}

// Rule is a rule
type Rule struct {
	Policy      string     `@("allow" | "deny")`
	Protocol    string     `@Ident`
	Types       string     `@{"any"}`
	Source      *Reference `"src" @@`
	Destination *Reference `"dst" @@`
	Log         bool       `{ @"log" }`
	Mirror      bool       `{ @"mirror" }`
	Expire      int        `{ "expire" @Date }`
	Stateful    bool       `{ @"stateful" }`
}

func (r *Rule) String() string {
	return fmt.Sprintf("policy=%s, proto=%s, type=%s, source=%s, dst=%s, log=%t", r.Policy, r.Protocol, r.Types, r.Source.String(), r.Destination.String(), r.Log)
}

// RuleSet is a set of rules
type RuleSet struct {
	Rule []*Rule `{ @@ }`
}

func (rs *RuleSet) String() string {
	var result []string
	for _, r := range rs.Rule {
		result = append(result, r.String())
	}
	return strings.Join(result, "\n")
}

// ParseRuleSet parses a policy file
func ParseRuleSet(r io.Reader) (*RuleSet, error) {
	parser, err := participle.Build(&RuleSet{}, aclLexer)
	if err != nil {
		return nil, err
	}

	result := &RuleSet{}
	if err := parser.Parse(r, result); err != nil {
		return nil, err
	}

	return result, nil
}

// ParseHosts parses an host object
func ParseHosts(r io.Reader) (*Hosts, error) {
	parser, err := participle.Build(&Hosts{}, aclLexer)
	if err != nil {
		return nil, err
	}

	result := &Hosts{}
	if err := parser.Parse(r, result); err != nil {
		return nil, err
	}

	return result, nil
}

// ParsePorts parses an port object
func ParsePorts(r io.Reader) (*Ports, error) {
	parser, err := participle.Build(&Ports{}, aclLexer)
	if err != nil {
		return nil, err
	}

	result := &Ports{}
	if err := parser.Parse(r, result); err != nil {
		return nil, err
	}

	return result, nil
}
