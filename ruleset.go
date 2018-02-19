package main

import (
	"fmt"
	"os"

	"github.com/Crypto89/ladon/parser"
	log "github.com/sirupsen/logrus"
)

func loadRuleSet(name string) *parser.RuleSet {
	f, err := os.Open(fmt.Sprintf("%s/%s", ruleDir, name))
	if err != nil {
		log.Fatalf("ruleset: Failed to read file %s/%s", ruleDir, name)
	}

	set, err := parser.ParseRuleSet(f)
	if err != nil {
		panic(err)
	}

	return set
}
